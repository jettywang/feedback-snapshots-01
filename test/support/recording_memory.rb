require "flipper"
require "flipper/adapters/wrapper"

# In-memory adapter doubles used by the stack-order review.
#
# RecordingMemory wraps any adapter and records every adapter-contract call
# (reads and writes) with its result or raised error. It can also fail an
# individual operation or take the whole store down, so a test can model a
# primary outage, a read-only timeout, or a store that is still writable while
# its reads fail.
class RecordingMemory < Flipper::Adapters::Wrapper
  READ_OPERATIONS = %i[features get get_multi get_all sync_version export].freeze
  WRITE_OPERATIONS = %i[add remove clear enable disable import sync_version=].freeze

  Call = Struct.new(:operation, :feature, :gate, :value, :result, :error, keyword_init: true) do
    def ok?
      error.nil?
    end

    def failed?
      !ok?
    end
  end

  attr_reader :calls

  def initialize(inner = Flipper::Adapters::Memory.new)
    super(inner)
    @calls = []
    @faults = {}
    @down = false
  end

  if RUBY_VERSION >= "3.0"
    def wrap(operation, *args, **kwargs, &block)
      record(operation, args, &block)
    end
  else
    def wrap(operation, *args, &block)
      record(operation, args, &block)
    end
  end

  # Public: Make one operation raise. Other operations keep working.
  def fail_operation(operation, error = IOError.new("operation failed"))
    @faults[operation.to_sym] = error
  end

  # Public: Make every read and write raise, like a lost primary.
  def down!
    @down = true
  end

  def up!
    @down = false
  end

  def down?
    @down
  end

  def clear_faults
    @faults.clear
  end

  def reset!
    @calls.clear
    self
  end

  def reads
    calls.select { |call| READ_OPERATIONS.include?(call.operation) }
  end

  def writes
    calls.select { |call| WRITE_OPERATIONS.include?(call.operation) }
  end

  def operations
    calls.map(&:operation)
  end

  # Public: Seed through the normal adapter API, then clear the seed calls so
  # assertions only see the scenario under test.
  def seed
    yield Flipper.new(self, memoize: false)
    reset!
    self
  end

  def seed_actors(feature_key, ids)
    seed do |flipper|
      ids.each { |id| flipper[feature_key].enable_actor(Flipper::Actor.new(id)) }
    end
  end

  private

  def record(operation, args)
    call = Call.new(
      operation: operation,
      feature: feature_for(args),
      gate: gate_for(args),
      value: value_for(args)
    )

    begin
      if (fault = fault_for(operation))
        raise fault
      end

      call.result = yield
      call.result
    rescue Exception => error
      call.error = error
      raise
    ensure
      @calls << call
    end
  end

  def fault_for(operation)
    @faults[operation] || begin
      if @down && (READ_OPERATIONS.include?(operation) || WRITE_OPERATIONS.include?(operation))
        IOError.new("adapter unavailable")
      end
    end
  end

  def feature_for(args)
    first = args[0]
    if first.is_a?(Array)
      first.map { |feature| feature.respond_to?(:key) ? feature.key : feature }
    elsif first.respond_to?(:key)
      first.key
    end
  end

  def gate_for(args)
    second = args[1]
    second.key if second.respond_to?(:key)
  end

  def value_for(args)
    third = args[2]
    third.value if third.respond_to?(:value)
  end
end

# A memory adapter that already holds a malformed pilot roster. Invalid entries
# cannot be written through the public API, but they can arrive in an imported
# or fallback snapshot. They still occupy slots in the actor cap.
class InvalidRosterMemory < RecordingMemory
  DEFAULT_ACTORS = [nil, "", "   ", "User;1"].freeze

  def initialize(feature_key: :pilot, actors: DEFAULT_ACTORS)
    source = {
      feature_key.to_s => {
        actors: actors.to_set,
      },
    }
    super(Flipper::Adapters::Memory.new(source))
    reset!
  end
end

# A memory adapter that looks present but is unavailable for every read and
# write. Use two of these to model "no available source".
class UnavailableMemory < RecordingMemory
  def initialize(inner = Flipper::Adapters::Memory.new)
    super(inner)
    down!
  end
end
