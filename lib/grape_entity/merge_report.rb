# frozen_string_literal: true

module Grape
  class Entity
    # Maps every emitted output field back to the exposure that produced it.
    # Collected while a represented entity serializes so an enclosing safe
    # merge can authorize individual fields by their real source.
    class Provenance
      attr_reader :sources

      def initialize
        @sources = {}
      end

      def record(path, field, merge_source, attribute, entity_class, override)
        @sources[[Array(path).freeze, field]] =
          MergeSource.new(merge_source, attribute, entity_class, override)
      end

      def source_for(path, field)
        @sources[[Array(path).freeze, field]]
      end
    end

    # A serialized hash together with the provenance collected while building
    # it. Internal carrier; safe consumers unwrap to #hash before emitting.
    class MergePayload
      attr_reader :hash, :provenance

      def initialize(hash, provenance)
        @hash = hash
        @provenance = provenance
      end
    end

    # Provenance for a single value contributed to a safe merge.
    # Authorization is decided against this declared source label, never
    # against the (spoofable) string name of the output field.
    class MergeSource
      attr_reader :label, :attribute, :entity_class, :override

      def initialize(label, attribute, entity_class, override = false)
        @label = label
        @attribute = attribute
        @entity_class = entity_class
        @override = override
      end

      def override?
        @override == true
      end

      def ==(other)
        other.is_a?(self.class) &&
          label == other.label &&
          attribute == other.attribute &&
          entity_class == other.entity_class &&
          override == other.override
      end
      alias eql? ==

      def hash
        [label, attribute, entity_class, override].hash
      end

      def to_s
        label.to_s
      end
    end

    # A value offered to a merged field together with the exposure it came from.
    class MergeEvidence
      attr_reader :source, :value, :authorized, :override

      def initialize(source, value, authorized, override)
        @source = source
        @value = value
        @authorized = authorized
        @override = override
      end

      def authorized?
        @authorized
      end

      def unauthorized?
        !@authorized
      end

      def override?
        @override == true
      end

      def ==(other)
        other.is_a?(self.class) &&
          source == other.source &&
          value == other.value &&
          authorized == other.authorized &&
          override == other.override
      end
    end

    # Outcome of merging every contribution made to one output field.
    class MergeEntry
      STATUSES = %i[merged replaced conflict].freeze

      attr_reader :field, :path, :evidence, :status

      def initialize(field, path)
        @field = field
        @path = path
        @evidence = []
        @status = :conflict
      end

      def record(evidence_item)
        @evidence << evidence_item
      end

      def resolve(status)
        @status = status
      end

      def merged?
        @status == :merged
      end

      def replaced?
        @status == :replaced
      end

      def conflict?
        @status == :conflict
      end

      def sources
        @evidence.map(&:source)
      end

      # The exposure whose value currently wins. Authorized evidence always
      # precedes unauthorized evidence, so this is the concrete declaration
      # backing any emitted value.
      def winning_evidence
        @evidence.reverse.find(&:authorized?) || @evidence.last
      end

      def value
        winning_evidence&.value
      end

      def reason
        return unless conflict?

        if @evidence.none?(&:authorized?)
          :unauthorized_source
        elsif @evidence.map(&:value).uniq.size > 1
          :incompatible_values
        else
          :unresolved
        end
      end
    end

    # Collects the provenance of every field produced through safe merges for
    # one entity representation.
    class MergeReport
      include Enumerable

      def initialize
        @entries = {}
      end

      def entry_for(path, field)
        @entries[[Array(path).freeze, field]] ||= MergeEntry.new(field, Array(path))
      end

      def each(&block)
        @entries.values.each(&block)
      end

      def entries
        @entries.values
      end

      def conflicts
        entries.select(&:conflict?)
      end

      def conflicts?
        entries.any?(&:conflict?)
      end

      def find(path, field)
        @entries[[Array(path).freeze, field]]
      end

      def empty?
        @entries.empty?
      end
    end
  end
end
