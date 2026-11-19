require 'flipper'
require 'flipper/adapters/operation_logger'

# Regression coverage for the "kill switch" question asked before a platform
# launch: once an emergency disable lands in storage, how long until a request
# observes the closed state?
#
# The Memoizer middleware wraps a request in `flipper.memoize = true` and flips
# it back to false in an `ensure`, which clears the per-request snapshot. So the
# boundary at which a fresh read happens is the request boundary itself:
#
#   * a request already in flight keeps the gate snapshot it first read, no
#     matter how many times (or under which gate scope) it re-checks;
#   * the next request starts with an empty cache and reads storage again, so
#     it is the first point that can see the emergency disable.
#
# These examples drive that boundary directly through the DSL instead of going
# through Rack, and use an OperationLogger-wrapped Memory adapter so the
# enabled/disabled decision is asserted together with the exact number of
# storage reads that produced it.
RSpec.describe 'Flipper request-level memoization (kill switch visibility)' do
  let(:memory) { Flipper::Adapters::Memory.new }

  # Countable in-memory store: every gate read the memoizer cannot satisfy from
  # its per-request cache is counted here.
  let(:store) { Flipper::Adapters::OperationLogger.new(memory) }
  let(:flipper) { Flipper.new(store) }

  # A second handle onto the same underlying storage, with memoization turned
  # off. Stands in for the emergency console / another process that flips the
  # kill switch out of band while a request is in flight. Its writes bypass the
  # OperationLogger, so read counts below only reflect request reads.
  let(:admin) { Flipper.new(memory, memoize: false) }

  let(:actor) { Flipper::Actor.new('User;1') }

  # Mirrors Flipper::Middleware::Memoizer#memoized_call: enable the per-request
  # cache for the duration of the block, then reset it (which clears the cache)
  # even if the block raises.
  def request
    flipper.memoize = true
    begin
      yield
    ensure
      flipper.memoize = false
    end
  end

  describe 'multiple reads inside one request' do
    before do
      flipper.enable(:search)
      store.reset
    end

    it 'reads storage once regardless of how many times the flag is checked' do
      decisions = request do
        [
          flipper[:search].enabled?,
          flipper[:search].enabled?,
          flipper[:search].enabled?,
        ]
      end

      expect(decisions).to eq([true, true, true])
      expect(store.count(:get)).to be(1)
    end

    it 'shares one snapshot across global and actor-scoped checks of the same feature' do
      decisions = request do
        [
          flipper[:search].enabled?,                         # boolean gate scope
          flipper.enabled?(:search, actor),                  # actor gate scope
          flipper.enabled?(:search, Flipper::Actor.new('User;2')),
        ]
      end

      # All scopes evaluate against the same gate snapshot, so they share a
      # single storage read and agree on the boolean decision.
      expect(decisions).to eq([true, true, true])
      expect(store.count(:get)).to be(1)
    end
  end

  describe 'an emergency disable while a request is in flight' do
    before do
      flipper.enable(:search)
      store.reset
    end

    it 'keeps the stale snapshot for the old request and re-reads for the next one' do
      # Old request: takes a snapshot, then stays open across the kill switch.
      stale_decisions = nil
      request do
        stale_decisions = [
          flipper[:search].enabled?,
          flipper.enabled?(:search, actor),
        ]
        expect(store.count(:get)).to be(1)

        # Kill switch lands in storage while this request is still running.
        admin.disable(:search)

        # Re-checking inside the same request does not touch storage again.
        stale_decisions << flipper[:search].enabled?
        expect(store.count(:get)).to be(1)
      end

      # The in-flight request never saw the disable: it held its snapshot.
      expect(stale_decisions).to eq([true, true, true])
      expect(store.count(:get)).to be(1)

      # The very next request starts with a cleared cache, reads storage once,
      # and is the first point that observes the closed state.
      fresh_decisions = request do
        [
          flipper[:search].enabled?,
          flipper.enabled?(:search, actor),
          flipper[:search].enabled?,
        ]
      end

      expect(fresh_decisions).to eq([false, false, false])
      expect(store.count(:get)).to be(2)
    end

    it 'resets the snapshot even when a request raises, so the next request re-reads' do
      expect do
        request do
          flipper[:search].enabled?
          raise 'boom'
        end
      end.to raise_error('boom')

      expect(flipper.memoizing?).to be(false)
      expect(flipper.adapter.cache).to be_empty

      admin.disable(:search)

      fresh = request { flipper[:search].enabled? }
      expect(fresh).to be(false)
    end
  end

  describe 'requests operating over different scopes' do
    before do
      flipper.enable(:checkout)
      store.reset
    end

    it 'reads once per distinct feature within a request, then memoizes each' do
      decisions = request do
        [
          flipper[:search].enabled?,     # different feature, separate read
          flipper[:checkout].enabled?,
          flipper[:search].enabled?,     # served from the per-request cache
          flipper[:checkout].enabled?,
        ]
      end

      expect(decisions).to eq([false, true, false, true])
      expect(store.count(:get)).to be(2)
    end

    it 'gives every new request its own read budget, independent of prior requests' do
      first = request { [flipper[:checkout].enabled?, flipper[:checkout].enabled?] }
      expect(first).to eq([true, true])
      expect(store.count(:get)).to be(1)

      # Same feature, brand new request: cache was cleared, so storage is read
      # again rather than inheriting the previous request's snapshot.
      second = request { [flipper[:checkout].enabled?, flipper[:checkout].enabled?] }
      expect(second).to eq([true, true])
      expect(store.count(:get)).to be(2)
    end

    it 'keeps an actor-scoped check on the stale snapshot until the next request' do
      flipper[:search].enable_actor(actor)

      current = request do
        before = flipper.enabled?(:search, actor)
        admin.disable(:search) # emergency boolean kill, out of band
        after = flipper.enabled?(:search, actor)
        [before, after]
      end

      # Both actor-scoped checks use the one snapshot read at the start of the
      # request, so the in-flight request stays open even after the kill.
      expect(current).to eq([true, true])
      expect(store.count(:get)).to be(1)

      # The next request re-reads storage and the actor-scoped check is closed.
      upcoming = request { flipper.enabled?(:search, actor) }
      expect(upcoming).to be(false)
      expect(store.count(:get)).to be(2)
    end
  end
end
