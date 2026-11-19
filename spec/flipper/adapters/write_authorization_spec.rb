require "flipper/adapters/write_authorization"
require "flipper/instrumenters/memory"
require "flipper/spec/shared_adapter_specs"

RSpec.describe Flipper::Adapters::WriteAuthorization do
  let(:memory) { Flipper::Adapters::Memory.new }
  let(:instrumenter) { Flipper::Instrumenters::Memory.new }

  let(:policy) do
    described_class::Policy.new(
      on_call: {
        "checkout" => %i[add disable clear],
        "search" => %i[add disable],
      },
      security: :all,
    )
  end

  subject { described_class.new(memory, policy: policy, instrumenter: instrumenter) }

  let(:flipper) { Flipper.new(subject) }
  let(:checkout) { flipper[:checkout] }
  let(:search) { flipper[:search] }

  def as(principal)
    described_class.with_principal(principal) { yield }
  end

  def denial_events
    instrumenter.events_by_name(described_class::DenialInstrumentationName)
  end

  def memory_values(feature)
    Flipper::GateValues.new(memory.get(feature))
  end

  before do
    described_class.principal = nil
  end

  after do
    described_class.principal = nil
  end

  context "with a principal allowed every action" do
    subject do
      described_class.new(
        Flipper::Adapters::Memory.new,
        policy: { system: :all },
        principal: :system,
      )
    end

    it_should_behave_like "a flipper adapter"
    it_should_behave_like "an adapter that stores its sync version"
  end

  it "has a symbol name" do
    expect(subject.name).to be_instance_of(Symbol)
  end

  it "is not read only, since some writes are allowed" do
    expect(subject.read_only?).to be(false)
  end

  describe "read pass-through" do
    before do
      as(:security) { checkout.enable_actor(Flipper::Actor.new("user;9")) }
    end

    it "reads without a principal" do
      expect(checkout.enabled?(Flipper::Actor.new("user;9"))).to be(true)
      expect(checkout.state).to be(:conditional)
      expect(subject.get(checkout)).to eq(memory.get(checkout))
      expect(subject.features).to eq(memory.features)
      expect(subject.get_all).to eq(memory.get_all)
    end

    it "does not instrument reads" do
      expect { checkout.enabled?(Flipper::Actor.new("user;9")) }
        .not_to change { instrumenter.events.size }
    end
  end

  describe "two on-call identities" do
    it "lets on_call disable a targeted actor, leaving storage as written" do
      as(:security) { checkout.enable_actor(Flipper::Actor.new("user;1")) }

      as(:on_call) do
        expect(checkout.disable_actor(Flipper::Actor.new("user;1"))).to be(true)
      end

      expect(memory_values(checkout).actors).to eq(Set.new)
      expect(checkout.enabled?(Flipper::Actor.new("user;1"))).to be(false)
      expect(denial_events).to be_empty
    end

    it "lets on_call clear a dangerous feature, matching stored gate values" do
      as(:security) do
        checkout.enable_actor(Flipper::Actor.new("user;1"))
        checkout.enable_group(:admins)
        checkout.enable_percentage_of_actors(25)
      end

      as(:on_call) { expect(checkout.clear).to be(true) }

      expect(memory_values(checkout)).to eq(Flipper::GateValues.new(subject.default_config))
      expect(checkout.state).to be(:off)
      expect(checkout.gate_values.actors).to eq(Set.new)
      expect(checkout.gate_values.groups).to eq(Set.new)
      expect(denial_events).to be_empty
    end

    it "rejects an on_call expansion and records the denial without touching storage" do
      as(:security) { checkout.disable_actor(Flipper::Actor.new("user;1")) }
      before_values = memory.get(checkout)

      expect do
        as(:on_call) { checkout.enable }
      end.to raise_error(described_class::NotAuthorized, /:on_call is not authorized to enable feature "checkout"/)

      expect(memory.get(checkout)).to eq(before_values)
      expect(checkout.state).to be(:off)
      expect(denial_events.size).to eq(1)

      event = denial_events.first
      expect(event.payload).to include(
        adapter_name: :write_authorization,
        principal: :on_call,
        operation: :enable,
        feature_name: :checkout,
        gate_name: :boolean,
        thing_value: true,
        reason: :policy_denied,
      )
      expect(event.payload[:exception_object]).to be_a(described_class::NotAuthorized)
    end

    it "lets security expand the rollout, and reads reflect it" do
      as(:on_call) { checkout.disable_actor(Flipper::Actor.new("user;1")) }

      as(:security) do
        checkout.enable_actor(Flipper::Actor.new("user;1"))
        checkout.enable_actor(Flipper::Actor.new("user;2"))
      end

      expect(memory_values(checkout).actors).to eq(Set["user;1", "user;2"])
      expect(checkout.enabled?(Flipper::Actor.new("user;2"))).to be(true)
      expect(denial_events).to be_empty
    end

    it "limits on_call to the allowed features" do
      as(:on_call) do
        expect { search.enable }.to raise_error(described_class::NotAuthorized)
      end

      expect(denial_events.size).to eq(1)
      expect(denial_events.first.payload[:feature_name]).to eq(:search)
    end
  end

  describe "gate state agrees with allowed operations" do
    it "reports authorized? consistently with what writes do" do
      as(:on_call) do
        expect(subject.authorized?(:disable, checkout)).to be(true)
        expect(subject.authorized?(:clear, checkout)).to be(true)
        expect(subject.authorized?(:enable, checkout)).to be(false)
        expect(subject.authorized?(:disable, :search)).to be(true)
        expect(subject.authorized?(:enable, :search)).to be(false)
        expect(subject.allowed_actions(checkout)).to eq([:add, :clear, :disable])
      end

      as(:security) do
        expect(subject.authorized?(:enable, checkout)).to be(true)
        expect(subject.authorized?(:disable, search)).to be(true)
      end
    end

    it "shows on_call a feature state that only reflects writes they could make" do
      as(:security) { checkout.enable_actor(Flipper::Actor.new("user;1")) }
      as(:on_call) { checkout.disable }

      expect(checkout.state).to be(:off)
      expect(subject.authorized?(:enable, checkout)).to be(false)
    end
  end

  describe "writes that always require explicit authority" do
    it "rejects creating an unrelated feature for on_call" do
      expect { as(:on_call) { flipper[:billing].add } }
        .to raise_error(described_class::NotAuthorized)
      expect(memory.features).to eq(Set.new)
    end

    it "leaves no feature record when a denied enable targets a new feature" do
      expect { as(:on_call) { flipper[:billing].enable } }
        .to raise_error(described_class::NotAuthorized)
      expect(memory.features).to eq(Set.new)
      expect(denial_events.size).to eq(1)
      expect(denial_events.first.payload[:operation]).to eq(:add)
    end

    it "rejects removing a feature for on_call" do
      as(:security) { flipper.add(:checkout) }

      expect { as(:on_call) { checkout.remove } }
        .to raise_error(described_class::NotAuthorized)
      expect(memory.features).to include("checkout")
    end

    it "rejects syncing a version for on_call" do
      expect { as(:on_call) { subject.sync_version = Flipper::SyncVersion.new("scope", 1) } }
        .to raise_error(described_class::NotAuthorized)
      expect(memory.sync_version).to be_nil
    end
  end

  describe "missing principal" do
    it "denies and instruments without a principal" do
      as(:security) { flipper.add(:checkout) }

      expect { checkout.disable }
        .to raise_error(described_class::NotAuthorized, /requires a principal/)

      expect(denial_events.size).to eq(1)
      expect(denial_events.first.payload).to include(
        principal: nil,
        feature_name: :checkout,
        reason: :missing_principal,
      )
    end
  end

  describe "policy" do
    it "lets deny rules override allow rules" do
      policy = described_class::Policy.new
      policy.allow(:security, :all)
      policy.deny(:security, :remove, features: "checkout")

      expect(policy.allowed?(:security, :enable, "checkout")).to be(true)
      expect(policy.allowed?(:security, :remove, "checkout")).to be(false)
      expect(policy.allowed?(:on_call, :enable, "checkout")).to be(false)
      expect(policy.allowed?(nil, :enable, "checkout")).to be(false)
    end

    it "supports feature/action pairs" do
      policy = described_class::Policy.new(
        on_call: { actions: :disable, features: %w[checkout search] },
      )

      expect(policy.allowed?(:on_call, :disable, :checkout)).to be(true)
      expect(policy.allowed?(:on_call, :disable, :search)).to be(true)
      expect(policy.allowed?(:on_call, :clear, :checkout)).to be(false)
      expect(policy.allowed?(:on_call, :disable, :billing)).to be(false)
    end

    it "supports regular expressions for feature names" do
      policy = described_class::Policy.new(on_call: { %r{\Acheckout} => :disable })

      expect(policy.allowed?(:on_call, :disable, :checkout)).to be(true)
      expect(policy.allowed?(:on_call, :disable, "checkout_v2")).to be(true)
      expect(policy.allowed?(:on_call, :disable, "old_checkout")).to be(false)
    end

    it "yields the configured policy to the block" do
      policy = described_class::Policy.new({ on_call: :disable }) do |p|
        p.allow(:security, :all)
      end

      expect(policy.allowed?(:on_call, :disable, :checkout)).to be(true)
      expect(policy.allowed?(:security, :enable, :checkout)).to be(true)
    end
  end

  describe "adapter-wide writes" do
    it "requires :import authority across every feature" do
      source = Flipper::Adapters::Memory.new
      Flipper.new(source).enable(:checkout)

      expect { as(:on_call) { subject.import(source) } }
        .to raise_error(described_class::NotAuthorized)
      expect(memory.features).to eq(Set.new)

      as(:security) { expect(subject.import(source)).to be(true) }
      expect(memory.features).to eq(Set["checkout"])
    end
  end

  describe "with_principal" do
    it "restores the previous principal, including on error" do
      described_class.principal = :security
      expect do
        described_class.with_principal(:on_call) { raise "boom" }
      end.to raise_error("boom")
      expect(described_class.principal).to eq(:security)
    end

    it "is scoped to the current thread" do
      as(:on_call) do
        expect(Thread.new { described_class.principal }.value).to be_nil
      end
    end
  end
end
