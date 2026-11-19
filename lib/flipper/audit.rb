require "set"
require "time"
require "flipper"
require "flipper/adapters/wrapper"
require "flipper/feature"
require "flipper/gate_values"
require "flipper/typecast"

module Flipper
  # Public: Adapter wrapper that records an audit trail for successful gate
  # changes and for writes that did not change anything.
  #
  # Flipper's feature_operation events describe the operation that was asked
  # for. They do not, on their own, prove that the adapter changed. This
  # wrapper compares the feature state before and after each write, so an
  # incident review can reconcile every recorded change with the final state
  # and see why a write did not take effect.
  #
  #   audit = Flipper::Audit.new(Flipper::Adapters::Memory.new)
  #   flipper = Flipper.new(audit)
  #
  #   Flipper::Audit.with_operator("operator-123") do
  #     flipper.enable(:search)
  #   end
  #
  #   audit.events.last.applied?    # => true
  #   audit.events.last.operator_id # => "operator-123"
  #
  # Only an opaque operator identifier is stored. Pass a public id (or an
  # object responding to #flipper_id / #operator_id); names, email addresses,
  # and other operator attributes are deliberately ignored.
  class Audit < Adapters::Wrapper
    # Public: The name of each audit instrumentation event.
    InstrumentationName = "audit.flipper".freeze

    OPERATOR_KEY = :flipper_audit_operator_id

    class << self
      # Public: The public identifier of the operator for the current thread.
      def operator_id
        normalize_operator_id(Thread.current[OPERATOR_KEY])
      end
      alias_method :operator, :operator_id

      # Public: Set the public identifier of the operator for the current
      # thread. Pass nil to clear it.
      def operator_id=(value)
        Thread.current[OPERATOR_KEY] = normalize_operator_id(value)
      end
      alias_method :operator=, :operator_id=

      # Public: Run the block with an operator identifier attached to audit
      # events emitted on this thread. The previous identifier is restored
      # even when the block raises.
      #
      # value - A public operator id String or Symbol, an object responding to
      #         #flipper_id or #operator_id, or a Hash with an :id,
      #         "id", :operator_id, or "operator_id" key. Anything else is
      #         not recorded, so raw user objects cannot leak into the trail.
      def with_operator(value)
        previous = Thread.current[OPERATOR_KEY]
        Thread.current[OPERATOR_KEY] = normalize_operator_id(value)
        yield
      ensure
        Thread.current[OPERATOR_KEY] = previous
      end

      # Internal: Reduce an operator-like value to an opaque public id.
      def normalize_operator_id(value)
        case value
        when nil
          nil
        when String
          value.empty? ? nil : value.dup.freeze
        when Symbol, Numeric
          value.to_s.freeze
        when Hash
          normalize_operator_id(
            value[:operator_id] || value["operator_id"] ||
              value[:id] || value["id"]
          )
        else
          if value.respond_to?(:operator_id)
            normalize_operator_id(value.operator_id)
          elsif value.respond_to?(:flipper_id)
            normalize_operator_id(value.flipper_id)
          end
        end
      end
    end

    # Public: A single gate value change within a feature.
    class Change
      attr_reader :gate_name, :from, :to

      def initialize(gate_name, from, to)
        @gate_name = gate_name
        @from = from
        @to = to
      end

      def changed?
        from != to
      end

      def to_h
        { gate_name: gate_name, from: from, to: to }
      end

      def inspect
        "#<#{self.class.name} gate_name=#{gate_name.inspect} from=#{from.inspect} to=#{to.inspect}>"
      end
    end

    # Public: A feature whose state changed during an import.
    class FeatureChange
      attr_reader :feature_name, :before, :after, :changes

      def initialize(feature_name, before, after, changes = [])
        @feature_name = feature_name
        @before = before
        @after = after
        @changes = changes.freeze
      end

      def added?
        before.nil?
      end

      def removed?
        after.nil?
      end

      def changed?
        !changes.empty?
      end

      def to_h
        {
          feature_name: feature_name,
          before: before,
          after: after,
          changes: changes.map(&:to_h),
          added: added?,
          removed: removed?,
        }
      end

      def inspect
        "#<#{self.class.name} feature_name=#{feature_name.inspect} added=#{added?} removed=#{removed?} changes=#{changes.inspect}>"
      end
    end

    # Public: A write that was attempted, whether it changed anything, and the
    # reason it did not.
    class Event
      attr_reader :operation, :feature_name, :gate_name, :value,
                  :before, :after, :changes, :feature_changes,
                  :effective, :applied, :reason, :operator_id,
                  :error_class, :at

      def initialize(operation:, feature_name: nil, gate_name: nil, value: nil,
                     before: nil, after: nil, changes: [], feature_changes: [],
                     effective: false, applied: false, reason: nil,
                     operator_id: nil, error_class: nil, at: nil)
        @operation = operation
        @feature_name = feature_name && feature_name.to_s.freeze
        @gate_name = gate_name && gate_name.to_sym
        @value = Audit.deep_freeze(value)
        @before = Audit.deep_freeze(before)
        @after = Audit.deep_freeze(after)
        @changes = changes.freeze
        @feature_changes = feature_changes.freeze
        @effective = !!effective
        @applied = !!applied
        @reason = reason
        @operator_id = operator_id && operator_id.to_s.freeze
        @error_class = error_class && error_class.to_s.freeze
        @at = at || Time.now
        freeze
      end

      alias_method :feature, :feature_name
      alias_method :feature_key, :feature_name
      alias_method :gate, :gate_name
      alias_method :operator, :operator_id

      def [](key)
        to_h[key]
      end

      def applied?
        applied
      end

      def effective?
        effective
      end

      alias_method :changed?, :effective?

      def failed?
        !reason.nil? && %i[error read_only limit_exceeded reserved_key].include?(reason)
      end

      def unchanged?
        reason == :unchanged || reason == :stale
      end
      alias_method :noop?, :unchanged?

      def stale?
        reason == :stale
      end

      def unsupported?
        reason == :unsupported
      end

      # Public: :applied, :unchanged, or :failed.
      def outcome
        return :failed if failed?
        effective? ? :applied : :unchanged
      end

      # Public: The first changed gate, if this event changed exactly one gate.
      def from
        changes.first && changes.first.from
      end

      def to
        changes.first && changes.first.to
      end

      # Public: Every gate change this event applied, including changes made by
      # an import.
      def gate_changes
        changes + feature_changes.flat_map(&:changes)
      end

      # Public: The write the caller asked for. Kept as an alias so an incident
      # review can tell intent (operation) from effect (changes).
      alias_method :intent, :operation

      # Public: True when the write raised after some state had already
      # changed.
      def partial?
        failed? && effective?
      end

      def to_h
        {
          operation: operation,
          feature_name: feature_name,
          feature_key: feature_name,
          gate_name: gate_name,
          value: value,
          before: before,
          after: after,
          changes: changes.map(&:to_h),
          feature_changes: feature_changes.map(&:to_h),
          effective: effective?,
          applied: applied?,
          outcome: outcome,
          reason: reason,
          operator_id: operator_id,
          operator: operator_id,
          error_class: error_class,
          at: at,
        }
      end

      alias_method :to_hash, :to_h

      def inspect
        attributes = [
          "operation=#{operation.inspect}",
          "feature_name=#{feature_name.inspect}",
          "gate_name=#{gate_name.inspect}",
          "outcome=#{outcome.inspect}",
          "reason=#{reason.inspect}",
          "operator_id=#{operator_id.inspect}",
        ]
        "#<#{self.class.name}:#{object_id} #{attributes.join(', ')}>"
      end
    end

    # Public: A feature whose audited state does not match the adapter.
    class Mismatch
      attr_reader :feature_name, :expected, :actual, :changes

      def initialize(feature_name, expected, actual, changes)
        @feature_name = feature_name
        @expected = expected
        @actual = actual
        @changes = changes
      end

      def to_h
        {
          feature_name: feature_name,
          expected: expected,
          actual: actual,
          changes: changes.map(&:to_h),
        }
      end
    end

    # Public: The result of comparing the latest audited state with the state
    # the adapter actually holds.
    class Reconciliation
      include Enumerable

      attr_reader :mismatches

      def initialize(mismatches)
        @mismatches = mismatches.freeze
      end

      def each(&block)
        mismatches.each(&block)
      end

      def empty?
        mismatches.empty?
      end

      def ok?
        empty?
      end

      def to_a
        mismatches
      end
    end

    attr_reader :instrumenter

    # Public: Build an audit wrapper around an adapter.
    #
    # adapter - The adapter to wrap. The same local adapter keeps serving all
    #           reads and writes.
    # options - Hash of options:
    #           :instrumenter - Instrumenter used for "audit.flipper" events.
    #           :operator_id  - Default public operator id. May be a value or
    #                           a callable evaluated for every event. A
    #                           thread-local id set with .with_operator wins.
    def initialize(adapter, options = {})
      super(adapter)
      @instrumenter = options.fetch(:instrumenter, Instrumenters::Noop)
      @configured_operator = options[:operator_id] || options[:operator]
      @events = []
      @events_mutex = Mutex.new
    end

    # Public: All audit events, oldest first.
    def events
      @events_mutex.synchronize { @events.dup }
    end

    alias_method :entries, :events

    # Public: The most recent audit event, or nil.
    def last_event
      @events_mutex.synchronize { @events.last }
    end
    alias_method :last, :last_event

    # Public: Audit events that changed adapter state.
    def applied_events
      events.select(&:applied?)
    end

    # Public: Audit events that did not change adapter state.
    def ineffective_events
      events.reject(&:effective?)
    end
    alias_method :unapplied_events, :ineffective_events

    # Public: Audit events for writes that raised.
    def failed_events
      events.select(&:failed?)
    end

    # Public: Audit events for one feature.
    def events_for(feature_name)
      key = feature_name.to_s
      events.select do |event|
        event.feature_name == key ||
          event.feature_changes.any? { |change| change.feature_name == key }
      end
    end

    # Public: Remove all audit events without touching adapter state.
    def clear_events
      @events_mutex.synchronize { @events.clear }
      self
    end

    # Public: The public operator id that will be attached to new events.
    def operator_id
      configured = if @configured_operator.respond_to?(:call)
        @configured_operator.call
      else
        @configured_operator
      end
      self.class.operator_id || self.class.normalize_operator_id(configured)
    end

    # Public: Set a thread-local operator id for new events.
    def with_operator(value, &block)
      self.class.with_operator(value, &block)
    end

    # Public: Reconcile the latest audited state per feature with what the
    # adapter currently holds.
    #
    # adapter - Optional adapter to check instead of the wrapped one.
    #
    # Returns a Reconciliation. It is empty when every audited feature still
    # matches the last observed state.
    def reconcile(adapter = @adapter)
      expected = expected_state_by_feature
      actual_features = adapter.features.to_set
      actual_all = adapter.get_all
      mismatches = []

      expected.each do |feature_name, expected_state|
        actual_state = {
          exists: actual_features.include?(feature_name),
          gates: snapshot_from(actual_all[feature_name]),
        }
        next if expected_state == actual_state

        mismatches << Mismatch.new(
          feature_name,
          expected_state,
          actual_state,
          self.class.diff(expected_state[:gates], actual_state[:gates])
        )
      end

      Reconciliation.new(mismatches)
    end

    # Public: True when #reconcile finds no differences.
    def reconciled?(adapter = @adapter)
      reconcile(adapter).ok?
    end

    # Public: A compact, public-safe summary of the trail.
    def summary
      events.group_by(&:outcome).each_with_object({}) do |(outcome, grouped), result|
        result[outcome] = grouped.size
      end
    end

    # Public: Adds a feature to the adapter and audits whether the set of
    # known features actually changed.
    def add(feature)
      before_state = nil
      before_exists = nil

      begin
        before_exists = feature_exists?(feature)
        before_state = snapshot(feature)
        result = @adapter.add(feature)
      rescue Exception => exception
        emit_failure(:add, feature, nil, exception, before_state)
        raise
      end

      after_exists = safe { feature_exists?(feature) }
      after_state = safe_snapshot(feature)
      changed = before_exists == false && after_exists == true
      emit(
        operation: :add,
        feature_name: feature_name_for(feature),
        before: before_state,
        after: after_state,
        effective: changed,
        applied: changed,
        reason: changed ? nil : :unchanged
      )

      result
    end

    # Public: Removes a feature and audits whether it was present before.
    def remove(feature)
      before_state = nil
      before_exists = nil

      begin
        before_exists = feature_exists?(feature)
        before_state = snapshot(feature)
        result = @adapter.remove(feature)
      rescue Exception => exception
        emit_failure(:remove, feature, nil, exception, before_state)
        raise
      end

      after_exists = safe { feature_exists?(feature) }
      after_state = safe_snapshot(feature)
      removed = before_exists == true && after_exists == false
      changed = removed || (before_state && before_state != after_state)
      emit(
        operation: :remove,
        feature_name: feature_name_for(feature),
        before: before_state,
        after: after_state,
        effective: changed,
        applied: changed,
        reason: changed ? nil : :unchanged
      )

      result
    end

    # Public: Clears a feature's gates and audits the gate diffs.
    def clear(feature)
      before_state = nil

      begin
        before_state = snapshot(feature)
        result = @adapter.clear(feature)
      rescue Exception => exception
        emit_failure(:clear, feature, nil, exception, before_state)
        raise
      end

      after_state = safe_snapshot(feature)
      changes = before_state && after_state ? self.class.diff(before_state, after_state) : []
      emit(
        operation: :clear,
        feature_name: feature_name_for(feature),
        before: before_state,
        after: after_state,
        changes: changes,
        effective: !changes.empty?,
        applied: !changes.empty?,
        reason: changes.empty? ? :unchanged : nil
      )

      result
    end

    # Public: Enables a gate and audits the effective gate diff.
    def enable(feature, gate, thing)
      write_gate(:enable, feature, gate, thing) { @adapter.enable(feature, gate, thing) }
    end

    # Public: Disables a gate and audits the effective gate diff.
    def disable(feature, gate, thing)
      write_gate(:disable, feature, gate, thing) { @adapter.disable(feature, gate, thing) }
    end

    # Public: Imports flags and audits the whole resulting feature diff.
    #
    # source - The DSL, adapter, export, or export contents to import.
    #
    # A failed import gets a failed event with reason :error and is re-raised,
    # so callers behave exactly as they did before the audit wrapper. A source
    # that cannot be read before the adapter is touched is reported the same
    # way, without changing any flags.
    def import(source)
      begin
        source_snapshot = snapshot_import_source(source)
      rescue Exception => exception
        emit(
          operation: :import,
          effective: false,
          applied: false,
          reason: error_reason(exception),
          error_class: exception.class.name
        )
        raise
      end

      before_state = snapshot_all

      begin
        result = @adapter.import(source)
      rescue Exception => exception
        after_state = safe_snapshot_all || before_state
        feature_changes = self.class.feature_diff(before_state, after_state)
        emit(
          operation: :import,
          effective: !feature_changes.empty?,
          applied: false,
          reason: error_reason(exception),
          error_class: exception.class.name,
          feature_changes: feature_changes
        )
        raise
      end

      after_state = snapshot_all
      feature_changes = self.class.feature_diff(before_state, after_state)
      reason = if feature_changes.empty?
        if result == false
          :unsupported
        else
          import_no_change_reason(source_snapshot)
        end
      end

      emit(
        operation: :import,
        before: source_snapshot && source_snapshot[:features],
        effective: !feature_changes.empty?,
        applied: !feature_changes.empty?,
        reason: reason,
        feature_changes: feature_changes
      )

      result
    end

    def inspect
      stack = @adapter.respond_to?(:adapter_stack) ? @adapter.adapter_stack : @adapter.name
      "#<#{self.class.name} adapter=#{stack.inspect} events=#{events.size}>"
    end

    class << self
      # Internal: Compare two gate snapshots and return Change instances.
      def diff(before, after)
        before.each_with_object([]) do |(gate_name, from), changes|
          to = after[gate_name]
          changes << Change.new(gate_name, from, to) if from != to
        end
      end

      # Internal: Compare two full feature snapshots and return FeatureChange
      # instances for added, removed, and changed features.
      def feature_diff(before, after)
        keys = (before.keys | after.keys).sort
        keys.each_with_object([]) do |feature_name, changes|
          before_state = before[feature_name]
          after_state = after[feature_name]
          next if before_state == after_state

          gate_changes = diff(before_state || {}, after_state || {})
          changes << FeatureChange.new(
            feature_name,
            before_state,
            after_state,
            gate_changes
          )
        end
      end

      # Internal: Deep copy and freeze structures so an audit event cannot be
      # changed by a caller or by later adapter mutation.
      def deep_freeze(value)
        case value
        when Hash
          value.each_with_object({}) do |(key, nested), copy|
            copy[deep_freeze(key)] = deep_freeze(nested)
          end.freeze
        when Array
          value.map { |nested| deep_freeze(nested) }.freeze
        when Set
          Set.new(value.map { |nested| deep_freeze(nested) }).freeze
        else
          value.freeze
        end
      end
    end

    private

    def write_gate(operation, feature, gate, thing)
      feature_name = feature_name_for(feature)
      gate_name = gate.respond_to?(:name) ? gate.name : gate
      value = thing.respond_to?(:value) ? thing.value : nil
      before_state = nil

      begin
        before_state = snapshot(feature)
        result = yield
      rescue Exception => exception
        after_state = safe_snapshot(feature) || before_state
        changes = before_state && after_state ? self.class.diff(before_state, after_state) : []
        emit(
          operation: operation,
          feature_name: feature_name,
          gate_name: gate_name,
          value: value,
          before: before_state,
          after: after_state,
          changes: changes,
          effective: !changes.empty?,
          applied: false,
          reason: error_reason(exception),
          error_class: exception.class.name
        )
        raise
      end

      after_state = safe_snapshot(feature)
      changes = before_state && after_state ? self.class.diff(before_state, after_state) : []
      emit(
        operation: operation,
        feature_name: feature_name,
        gate_name: gate_name,
        value: value,
        before: before_state,
        after: after_state,
        changes: changes,
        effective: !changes.empty?,
        applied: !changes.empty?,
        reason: changes.empty? ? :unchanged : nil
      )

      result
    end

    def emit_failure(operation, feature, gate, exception, before_state = nil)
      emit(
        operation: operation,
        feature_name: feature_name_for(feature),
        gate_name: gate && gate.respond_to?(:name) ? gate.name : gate,
        before: before_state,
        reason: error_reason(exception),
        error_class: exception.class.name
      )
    rescue Exception
      # Auditing must never replace the exception the caller cares about.
      nil
    end

    def safe
      yield
    rescue Exception
      nil
    end

    def emit(operation:, feature_name: nil, gate_name: nil, value: nil,
             before: nil, after: nil, changes: [], feature_changes: [],
             effective: false, applied: false, reason: nil,
             error_class: nil)
      event = Event.new(
        operation: operation,
        feature_name: feature_name,
        gate_name: gate_name,
        value: value,
        before: before,
        after: after,
        changes: changes,
        feature_changes: feature_changes,
        effective: effective,
        applied: applied,
        reason: reason,
        operator_id: operator_id,
        error_class: error_class,
        at: Time.now
      )

      @events_mutex.synchronize { @events << event }
      instrument(event)
      event
    end

    def instrument(event)
      payload = event.to_h
      @instrumenter.instrument(Audit::InstrumentationName, payload) do |instrumented_payload|
        instrumented_payload[:result] = event
      end
    end

    def error_reason(exception)
      case exception.class.name
      when "Flipper::Adapters::ReadOnly::WriteAttempted"
        :read_only
      when "Flipper::Adapters::ActorLimit::LimitExceeded"
        :limit_exceeded
      when "Flipper::ReservedKeyError"
        :reserved_key
      else
        :error
      end
    end

    # Internal: Read enough of the import source to store what was asked for
    # and to explain why nothing changed. Never returns operator details.
    def snapshot_import_source(source)
      return nil if source.nil?

      adapter = self.class.from(source)
      features = adapter.get_all.each_with_object({}) do |(feature_name, values), result|
        result[feature_name.to_s] = snapshot_from(values)
      end
      version = adapter.sync_version if adapter.respond_to?(:sync_version)

      { features: features, sync_version: version }
    end

    def import_no_change_reason(source_snapshot)
      source_version = source_snapshot && source_snapshot[:sync_version]
      local_version = @adapter.sync_version if @adapter.respond_to?(:sync_version)

      if source_version && source_version.older_than?(local_version)
        :stale
      else
        :unchanged
      end
    rescue Exception
      :unchanged
    end

    def feature_exists?(feature)
      @adapter.features.include?(feature.key)
    end

    def feature_name_for(feature)
      feature.respond_to?(:key) ? feature.key : feature.to_s
    end

    def snapshot(feature)
      snapshot_from(@adapter.get(feature))
    end

    def safe_snapshot(feature)
      snapshot(feature)
    rescue Exception
      nil
    end

    def snapshot_all
      @adapter.get_all.each_with_object({}) do |(feature_name, values), result|
        result[feature_name.to_s] = snapshot_from(values)
      end
    end

    def safe_snapshot_all
      snapshot_all
    rescue Exception
      nil
    end

    def snapshot_from(values)
      values ||= @adapter.default_config
      value = ->(key) { values.key?(key) ? values[key] : values[key.to_s] }
      percentage_of_actors = value.call(:percentage_of_actors)
      percentage_of_time = value.call(:percentage_of_time)

      {
        boolean: value.call(:boolean).nil? ? nil : Typecast.to_boolean(value.call(:boolean)),
        groups: Set.new(Typecast.to_set(value.call(:groups)).map(&:to_s)).freeze,
        actors: Set.new(Typecast.to_set(value.call(:actors)).map(&:to_s)).freeze,
        expression: self.class.deep_freeze(value.call(:expression)),
        percentage_of_actors: percentage_of_actors.nil? ? nil : Typecast.to_number(percentage_of_actors),
        percentage_of_time: percentage_of_time.nil? ? nil : Typecast.to_number(percentage_of_time),
      }
    end

    def expected_state_by_feature
      expected = {}

      events.each do |event|
        if event.feature_name && event.effective? && event.after
          expected[event.feature_name] = {
            exists: event.operation != :remove,
            gates: event.after,
          }
        end

        event.feature_changes.each do |change|
          expected[change.feature_name] = {
            exists: !change.removed? && !change.after.nil?,
            gates: change.after || snapshot_from(@adapter.default_config),
          }
        end
      end

      expected
    end
  end

  AuditLog = Audit
end

module Flipper
  module Adapters
    # Public: Alias for the adapter wrapper so configurations that list their
    # adapters under Flipper::Adapters can find it.
    Audit = Flipper::Audit
  end
end
