# frozen_string_literal: true

module ActionPolicy
  # A verifiable scope contract wraps a collection and records which
  # authorized scope(s) it was derived from.
  #
  # It is meant for pipelines where data leaves the authorization layer
  # (e.g. background exports) and is then transformed in-memory by
  # plugins: sorting, column selection and concatenation all preserve
  # the provenance chain.
  #
  # A contract is _verified_ only if every source in its provenance
  # chain is an authorized scope. Concatenating with a source that was
  # not authorized keeps the result _traceable_ (the evidence is still
  # recorded) but it can no longer be marked as verified:
  #
  #   scope = authorized_scope(ExportRow.all, contract: true)
  #   scope.verified?  #=> true
  #   scope.derived_from #=> [#<Source policy=ExportRowPolicy type=:relation name=:default>]
  #
  #   page = scope.sort_by(:created_at, allow: %i[created_at id]).select_columns(:id, :title)
  #   page.verified? #=> true
  #
  #   mixed = page.concat(ActionPolicy::ScopeContract.unverified(plugin_rows, label: :csv_import))
  #   mixed.verified?   #=> false
  #   mixed.traceable?  #=> true
  class ScopeContract
    # A single provenance record: either an authorized scope
    # (policy + scope type + scope name) or an unverified source
    # identified by a label.
    class Source
      attr_reader :policy, :type, :name, :label

      def self.authorized(policy:, type:, name:)
        new(policy: policy, type: type, name: name)
      end

      def self.unverified(label)
        new(label: label)
      end

      def initialize(policy: nil, type: nil, name: nil, label: nil)
        @policy = policy
        @type = type
        @name = name
        @label = label
      end

      def authorized?
        !policy.nil?
      end

      def ==(other)
        other.is_a?(Source) &&
          policy == other.policy &&
          type == other.type &&
          name == other.name &&
          label == other.label
      end

      alias_method :eql?, :==

      def hash
        [policy, type, name, label].hash
      end

      def inspect
        if authorized?
          "#<#{self.class.name} authorized policy=#{policy} type=#{type.inspect} name=#{name.inspect}>"
        else
          "#<#{self.class.name} unverified label=#{label.inspect}>"
        end
      end
    end

    attr_reader :data

    class << self
      # Wrap a collection obtained from an authorized scope.
      # The resulting contract is verified.
      def authorize(data, policy:, type:, name: :default)
        new(data, provenance: [Source.authorized(policy: policy, type: type, name: name)])
      end

      # Wrap a collection that was NOT authorized. The source is still
      # recorded (traceable), but the contract is not verified.
      def unverified(data, label: :external)
        new(data, provenance: [Source.unverified(label)])
      end

      # Wrap a collection without any provenance evidence.
      def untracked(data)
        new(data)
      end
    end

    def initialize(data, provenance: [])
      @data = data
      @provenance = provenance.freeze
    end

    # Provenance evidence: which scopes/sources the current data
    # was derived from (in order of concatenation).
    def derived_from
      provenance.dup
    end

    # True only if there is provenance evidence and every source
    # is an authorized scope.
    def verified?
      provenance.any? && provenance.all?(&:authorized?)
    end

    # True if there is any provenance evidence, even if some sources
    # were not authorized.
    def traceable?
      provenance.any?
    end

    # In-memory sorting restricted to legal keys.
    #
    # Pass `allow:` with a list of permitted keys to reject anything
    # else; sorting by a key outside the list raises ArgumentError.
    def sort_by(*keys, allow: nil)
      keys = keys.flatten
      if allow
        illegal = keys.map(&:to_sym) - allow.map(&:to_sym)
        unless illegal.empty?
          label = (illegal.size == 1) ? "key" : "keys"
          raise ArgumentError, "Illegal sort #{label}: #{illegal.join(", ")}"
        end
      end

      derive(data.sort_by { |row| keys.map { |key| read_attribute(row, key) } })
    end

    # In-memory column selection. Returns rows as hashes containing
    # only the selected columns.
    def select_columns(*columns)
      columns = columns.flatten
      derive(data.map { |row| columns.to_h { |column| [column, read_attribute(row, column)] } })
    end

    # Concatenate with another source. The other source may be a
    # ScopeContract or a raw collection (coerced to an unverified
    # source). Provenance chains are merged, so the result is verified
    # only if BOTH sources are verified.
    def concat(other)
      other = ScopeContract.unverified(other) unless other.is_a?(ScopeContract)

      self.class.new(data.to_a + other.data.to_a, provenance: provenance + other.provenance)
    end

    alias_method :+, :concat

    def to_a
      data.to_a
    end

    def ==(other)
      other.is_a?(ScopeContract) && data == other.data && provenance == other.provenance
    end

    protected

    attr_reader :provenance

    private

    def derive(new_data)
      self.class.new(new_data, provenance: provenance)
    end

    def read_attribute(row, key)
      if row.is_a?(Hash)
        row.key?(key) ? row[key] : row[key.to_s]
      else
        row.public_send(key)
      end
    end
  end
end
