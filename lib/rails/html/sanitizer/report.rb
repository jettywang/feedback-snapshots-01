# frozen_string_literal: true

module Rails
  module HTML
    class Sanitizer
      # === Rails::HTML::Sanitizer::Report
      #
      # A report collects one entry for every sanitization decision that
      # removed or adjusted content. Entries carry structural metadata only:
      #
      # - +tag+: the name of the element, or +"comment"+ for an HTML comment.
      # - +attribute+: the name of the attribute, when the disposition is
      #   +:attribute+.
      # - +disposition+: what happened to the content (see below).
      # - +reason+: why it happened.
      #
      # Text and attribute values are never copied into the report.
      #
      # Pass a report to a sanitizer with the +report:+ option. The sanitized
      # HTML is returned as usual and is identical to the output when reporting
      # is disabled:
      #
      #   report = Rails::HTML::Sanitizer::Report.new
      #   html = safe_list_sanitizer.sanitize(input, report: report)
      #
      #   report.entries
      #   # => [#<struct Rails::HTML::Sanitizer::Report::Entry tag="script",
      #   #       attribute=nil, disposition=:strip, reason=:not_allowed>]
      #
      # An Array (or any object that responds to +<<+) may be passed instead,
      # in which case entries are appended to it:
      #
      #   entries = []
      #   safe_list_sanitizer.sanitize(input, report: entries)
      #
      # The three dispositions are:
      #
      # - +:prune+: the element and its subtree were removed.
      # - +:strip+: the element was unwrapped, keeping its children.
      # - +:attribute+: an attribute was removed or its value was adjusted.
      class Report
        Entry = Struct.new(:tag, :attribute, :disposition, :reason, keyword_init: true) do
          def to_s
            details = [tag, attribute].compact.join(" ")
            "#{details} #{disposition} (#{reason})"
          end
        end

        include Enumerable

        attr_reader :entries

        def initialize
          @entries = []
        end

        def each(&block)
          entries.each(&block)
        end

        # Accepts an entry, or the same keyword arguments as Entry.new.
        def <<(entry)
          entries << (entry.is_a?(Entry) ? entry : Entry.new(**entry))
          self
        end

        def size
          entries.size
        end
        alias length size

        def empty?
          entries.empty?
        end

        def clear
          entries.clear
          self
        end

        def tags
          entries.filter_map(&:tag).uniq
        end

        def attributes
          entries.filter_map(&:attribute).uniq
        end
        alias attribute_names attributes

        def dispositions
          entries.map(&:disposition).uniq
        end

        def reasons
          entries.map(&:reason).uniq
        end

        def pruned
          entries.select { |entry| entry.disposition == :prune }
        end

        def stripped
          entries.select { |entry| entry.disposition == :strip }
        end

        def attribute_changes
          entries.select { |entry| entry.disposition == :attribute }
        end

        # Normalizes the +report:+ option. +nil+ disables reporting. A Report is
        # used as-is and an Array receives entries directly. Any other object
        # that responds to +<<+ is treated as a collector. Unknown objects raise
        # so a typo cannot silently discard the audit trail.
        def self.sink(report)
          case report
          when nil
            nil
          when Report, Array
            report
          else
            if report.respond_to?(:<<) && !report.is_a?(String)
              report
            else
              raise ArgumentError, "report should be a Report, an Array, or an object that responds to <<"
            end
          end
        end
      end
    end

    # Internal helpers mixed into the built-in scrubbers. They only read
    # structural information (element and attribute names) and never copy text
    # or attribute values into the report.
    module Recorder # :nodoc:
      private
        def record_tag(node, disposition, reason)
          return unless @report

          tag = if node.element?
            node.name
          elsif node.comment?
            "comment"
          end
          return unless tag

          @report << Sanitizer::Report::Entry.new(tag: tag, disposition: disposition, reason: reason)
        end

        def record_attribute(node, attribute, reason)
          return unless @report && node.element?

          @report << Sanitizer::Report::Entry.new(
            tag: node.name, attribute: attribute, disposition: :attribute, reason: reason
          )
        end

        def record_attribute_changes(node, before, removal_reasons = {})
          return unless @report

          before.each do |attr_node, value|
            name = Loofah::HTML5::Scrub.prefixed_attribute_name(attr_node)

            if !node.attribute_nodes.include?(attr_node)
              reason = removal_reasons[attr_node] || removed_attribute_reason(name, value)
              record_attribute(node, name, reason)
            elsif attr_node.value != value
              record_attribute(node, name, :value_adjusted)
            end
          end
        end

        def snapshot_attributes(node)
          node.attribute_nodes.map { |attr_node| [attr_node, attr_node.value] }
        end

        def removed_attribute_reason(name, value)
          if value !~ /[^[:space:]]/
            :empty_value
          elsif permitted_attribute_name?(name)
            :unsafe_value
          else
            :not_allowed
          end
        end

        def permitted_attribute_name?(name)
          Loofah::HTML5::SafeList::ALLOWED_ATTRIBUTES.include?(name)
        rescue NameError
          false
        end
    end

    Sanitizer.include(Recorder)

    Report = Sanitizer::Report # :nodoc:
  end
end
