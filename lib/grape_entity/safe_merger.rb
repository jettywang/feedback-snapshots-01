# frozen_string_literal: true

module Grape
  class Entity
    # Merges hash exposures into an output hash while keeping a provenance
    # record of every contribution. Unlike a plain Hash#merge, an emitted
    # value is only kept when it can be traced to an exposure whose declared
    # source is explicitly authorized. Incompatible collisions are withheld
    # from the output but retained, with their evidence, in the report.
    class SafeMerger
      def initialize(output_hash, report, entity, path, provenance = nil, provenance_path = nil)
        @output_hash = output_hash
        @report = report
        @entity = entity
        @path = path
        @provenance = provenance
        @provenance_path = provenance_path
      end

      def merge!(result, exposure)
        result.each do |field, value|
          entry = @report.entry_for(@path, field)
          evidence = build_evidence(field, value, exposure)
          entry.record(evidence)
          apply(entry, field, evidence)
        end
      end

      private

      def build_evidence(field, value, exposure)
        source = source_for(field, exposure)
        MergeEvidence.new(source, value, authorized?(source), source.override?)
      end

      def source_for(field, exposure)
        provenance_source = @provenance&.source_for(@provenance_path || @path, field)
        return provenance_source if provenance_source

        MergeSource.new(exposure.merge_source, exposure.attribute, exposure.class, exposure.override?)
      end

      # Permission follows the declared data source, not the field name.
      def authorized?(source)
        !source.label.nil? && @entity.class.authorized_merge_sources.include?(source.label)
      end

      def apply(entry, field, evidence)
        if entry.evidence.one?
          apply_first(entry, field, evidence)
        else
          apply_contribution(entry, field, evidence)
        end
      end

      def apply_first(entry, field, evidence)
        if evidence.authorized?
          @output_hash[field] = evidence.value
          entry.resolve(:merged)
        else
          withhold(entry, field)
        end
      end

      def apply_contribution(entry, field, evidence)
        previous = entry.evidence[-2]

        if !evidence.authorized?
          handle_unauthorized(entry, field, evidence, previous)
        elsif !previous.authorized?
          handle_first_authorized(entry, field, evidence)
        elsif same_value?(entry)
          handle_agreement(entry, field, evidence)
        elsif evidence.override?
          handle_replacement(entry, field, evidence)
        else
          withhold(entry, field)
        end
      end

      def handle_unauthorized(entry, field, evidence, previous)
        return unless previous.authorized? && entry.merged? && previous.value == evidence.value

        # An unauthorized echo of an already authorized value adds no data.
        @output_hash[field] = previous.value
        entry.resolve(:merged)
      end

      def handle_first_authorized(entry, field, evidence)
        if entry.evidence.one? { |item| item.authorized? } &&
           entry.evidence.reject(&:authorized?).all? { |item| item.value == evidence.value }
          @output_hash[field] = evidence.value
          entry.resolve(:merged)
        else
          # Earlier unauthorized claims remain unresolved evidence; the
          # authorized value is kept but the collision is reported.
          @output_hash[field] = evidence.value
          withhold(entry, field)
        end
      end

      def handle_agreement(entry, field, evidence)
        @output_hash[field] = evidence.value
        entry.resolve(entry.replaced? ? :replaced : :merged)
      end

      def handle_replacement(entry, field, evidence)
        @output_hash[field] = evidence.value
        entry.resolve(:replaced)
      end

      def withhold(entry, field)
        @output_hash.delete(field)
        entry.resolve(:conflict)
      end

      def same_value?(entry)
        entry.evidence.select(&:authorized?).map(&:value).uniq.one?
      end
    end
  end
end
