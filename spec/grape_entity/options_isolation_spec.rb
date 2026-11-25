# frozen_string_literal: true

describe 'representation option isolation' do
  # Plain POROs so the examples do not depend on optional stdlib gems.
  Item = Struct.new(:id, :label)
  Box = Struct.new(:id, :items)

  # Every representation call is appended here together with the *effective*
  # options the child entity observed. A mutex keeps the log thread safe while
  # the assertions below reason about paths and conditions instead of JSON.
  module RepresentationLog
    @entries = []
    @mutex = Mutex.new

    class << self
      attr_reader :entries

      def record!(entry)
        @mutex.synchronize { @entries << entry }
      end

      def reset!
        @mutex.synchronize { @entries.clear }
      end

      def violations
        @mutex.synchronize { (@violations ||= []).dup }
      end

      def report_violation(message)
        @mutex.synchronize { (@violations ||= []) << message }
      end

      def reset_violations!
        @mutex.synchronize { @violations = [] }
      end

      def interleave!
        Thread.pass if interleave?
      end

      def interleave?
        @interleave == true
      end

      def interleave=(value)
        @interleave = value
      end
    end
  end

  # Snapshot the effective path, runtime condition and projection each child
  # receives while it is being represented.
  class RecordingItemEntity < Grape::Entity
    expose :effective_path do |_item, options|
      RepresentationLog.interleave!
      path = options[:attr_path]&.dup
      # Yield again while the path is still pushed, so concurrent threads can
      # interleave between the push and the matching pop.
      RepresentationLog.interleave!
      path
    end

    expose :effective_mode do |_item, options|
      options[:mode]
    end

    expose :permitted_fields do |_item, options|
      options.opts_hash[:only]&.dup
    end

    expose :label
  end

  class RecordingBoxEntity < Grape::Entity
    expose :id
    expose :items, using: RecordingItemEntity
  end

  # A stand-in child that fails while representing one specific object, while
  # the sibling object goes through the same parent options.
  class FailingItemEntity < Grape::Entity
    class RepresentationFailed < StandardError; end

    expose :effective_path do |item, options|
      RepresentationLog.record!(
        id: item.id,
        path: options[:attr_path]&.dup,
        mode: options[:mode],
        only: options.opts_hash[:only]&.dup
      )
      raise RepresentationFailed, "item #{item.id} failed" if item.id == :boom
      options[:attr_path]&.dup
    end
  end

  class FailingBoxEntity < Grape::Entity
    expose :id
    expose :items, using: FailingItemEntity
  end

  # The sibling is represented before the failing object so it really runs
  # while sharing the parent options, and its observations are still in the log
  # when the failure unwinds.
  let(:items) { [Item.new(:sibling, 'second'), Item.new(:boom, 'first')] }
  let(:box) { Box.new(:box, items) }
  let(:expected_item_path) { %i[items effective_path] }

  around do |example|
    RepresentationLog.reset!
    RepresentationLog.reset_violations!
    RepresentationLog.interleave = false
    example.run
    RepresentationLog.interleave = false
  end

  describe 'deep option inheritance still works' do
    it 'hands every nested entity its own path while inheriting parent conditions and permissions' do
      output = RecordingBoxEntity.represent(
        box,
        mode: :shared,
        only: [{ items: %i[effective_path effective_mode permitted_fields label] }]
      ).serializable_hash

      represented = output[:items]
      expect(represented.size).to eq(2)

      represented.each do |item|
        expect(item[:effective_path]).to eq(expected_item_path)
        expect(item[:effective_mode]).to eq(:shared)
        expect(item[:permitted_fields]).to eq(%i[effective_path effective_mode permitted_fields label])
      end

      expect(represented.map { |item| item[:label] }).to eq(%w[second first])
    end
  end

  describe 'one child failing' do
    it 'does not leave its path behind on the shared parent options' do
      presenter = FailingBoxEntity.new(box, mode: :shared)

      expect { presenter.serializable_hash }.to raise_error(FailingItemEntity::RepresentationFailed)

      logged = RepresentationLog.entries
      expect(logged.map { |entry| entry[:id] }).to eq(%i[sibling boom])

      logged.each do |entry|
        expect(entry[:path]).to eq(expected_item_path),
                                "item #{entry[:id]} observed polluted path #{entry[:path].inspect}"
        expect(entry[:mode]).to eq(:shared)
      end

      # The failure must unwind every pushed path part; a later representation
      # must not inherit the failed child's path.
      expect(presenter.options.opts_hash[:attr_path]).to be_nil
    end

    it 'keeps a sibling representation effective when the failing stand-in shares parent options' do
      projected = %i[effective_path effective_mode permitted_fields]
      shared_options = { mode: :shared, only: [{ items: projected }] }
      clean_box = Box.new(:clean, [Item.new(:one, 'a'), Item.new(:two, 'b')])

      begin
        FailingBoxEntity.represent(box, **shared_options).serializable_hash
      rescue FailingItemEntity::RepresentationFailed
        # expected: one child fails, the options object must stay reusable
      end

      output = RecordingBoxEntity.represent(clean_box, **shared_options).serializable_hash
      output[:items].each do |item|
        expect(item[:effective_path]).to eq(expected_item_path),
                                         "sibling received polluted path #{item[:effective_path].inspect}"
        expect(item[:effective_mode]).to eq(:shared)
        expect(item[:permitted_fields]).to eq(projected)
      end
    end
  end

  describe 'concurrent representations of a shared presenter' do
    it 'keeps each thread on its own attribute path and conditions' do
      presenter = RecordingBoxEntity.new(box, mode: :shared)

      # Warm up the for_nesting cache on one thread first. Every later
      # representation reuses that cached Options object, which is exactly
      # where cross-thread mutation would otherwise leak.
      warmup = presenter.serializable_hash
      warmup[:items].each { |item| expect(item[:effective_path]).to eq(expected_item_path) }

      RepresentationLog.interleave = true
      thread_count = 12
      iterations = 100

      threads = Array.new(thread_count) do |thread_index|
        Thread.new do
          iterations.times do
            output = presenter.serializable_hash(thread: thread_index)

            output[:items].each do |item|
              unless item[:effective_path] == expected_item_path
                RepresentationLog.report_violation(
                  "thread #{thread_index}: path leaked to #{item[:effective_path].inspect}"
                )
              end
              unless item[:effective_mode] == :shared
                RepresentationLog.report_violation(
                  "thread #{thread_index}: mode leaked to #{item[:effective_mode].inspect}"
                )
              end
            end
          end
        end
      end

      threads.each(&:join)

      violations = RepresentationLog.violations
      expect(violations).to be_empty, violations.first(5).join("\n")
      expect(presenter.options.opts_hash[:attr_path]).to be_nil
    end
  end
end
