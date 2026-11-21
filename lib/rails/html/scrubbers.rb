# frozen_string_literal: true

module Rails
  module HTML
    # === Rails::HTML::PermitScrubber
    #
    # +Rails::HTML::PermitScrubber+ allows you to permit only your own tags and/or attributes.
    #
    # +Rails::HTML::PermitScrubber+ can be subclassed to determine:
    # - When a node should be skipped via +skip_node?+.
    # - When a node is allowed via +allowed_node?+.
    # - When an attribute should be scrubbed via +scrub_attribute?+.
    #
    # Subclasses don't need to worry if tags or attributes are set or not.
    # If tags or attributes are not set, Loofah's behavior will be used.
    # If you override +allowed_node?+ and no tags are set, it will not be called.
    # Instead Loofahs behavior will be used.
    # Likewise for +scrub_attribute?+ and attributes respectively.
    #
    # Text and CDATA nodes are skipped by default.
    # Unallowed elements will be stripped, i.e. element is removed but its subtree kept.
    # Supplied tags and attributes should be Enumerables.
    #
    # +tags=+
    # If set, elements excluded will be stripped.
    # If not, elements are stripped based on Loofahs +HTML5::Scrub.allowed_element?+.
    #
    # +attributes=+
    # If set, attributes excluded will be removed.
    # If not, attributes are removed based on Loofahs +HTML5::Scrub.scrub_attributes+.
    #
    #  class CommentScrubber < Rails::HTML::PermitScrubber
    #    def initialize
    #      super
    #      self.tags = %w(form script comment blockquote)
    #    end
    #
    #    def skip_node?(node)
    #      node.text?
    #    end
    #
    #    def scrub_attribute?(name)
    #      name == "style"
    #    end
    #  end
    #
    # See the documentation for +Nokogiri::XML::Node+ to understand what's possible
    # with nodes: https://nokogiri.org/rdoc/Nokogiri/XML/Node.html
    class PermitScrubber < Loofah::Scrubber
      include Rails::HTML::Recorder

      attr_reader :tags, :attributes, :prune

      def initialize(prune: false, report: nil)
        @prune = prune
        @direction = @prune ? :top_down : :bottom_up
        @tags, @attributes = nil, nil
        @report = Rails::HTML::Sanitizer::Report.sink(report)
      end

      def tags=(tags)
        @tags = validate!(tags.dup, :tags)
      end

      def attributes=(attributes)
        @attributes = validate!(attributes.dup, :attributes)
      end

      def scrub(node)
        if Loofah::HTML5::Scrub.cdata_needs_escaping?(node)
          replacement = Loofah::HTML5::Scrub.cdata_escape(node)
          node.replace(replacement)
          return CONTINUE
        end
        return CONTINUE if skip_node?(node)

        unless (node.element? || node.comment?) && keep_node?(node)
          disposition = removal_disposition(node)
          reason = removal_reason(node)
          result = scrub_node(node)
          unless result == CONTINUE
            # A subclass may return STOP without detaching the node; only report
            # content that actually left the tree.
            record_tag(node, disposition, reason) if node.parent.nil?
            return STOP
          end
        end

        scrub_attributes(node)
        CONTINUE
      end

      protected
        def allowed_node?(node)
          @tags.include?(node.name)
        end

        def skip_node?(node)
          node.text?
        end

        def scrub_attribute?(name)
          !@attributes.include?(name)
        end

        def keep_node?(node)
          if @tags
            allowed_node?(node)
          else
            Loofah::HTML5::Scrub.allowed_element?(node.name)
          end
        end

        def scrub_node(node)
          # If a node has a namespace, then it's a tag in either a `math` or `svg` foreign context,
          # and we should always prune it to avoid namespace confusion and mutation XSS vectors.
          unless prune || node.namespace
            node.before(node.children)
          end
          node.remove
        end

        def scrub_attributes(node)
          before = snapshot_attributes(node) if @report
          removal_reasons = {}

          if @attributes
            node.attribute_nodes.each do |attr|
              if scrub_attribute?(attr.name)
                removal_reasons[attr] = attribute_removal_reason(attr) if @report
                attr.remove
              else
                scrub_attribute(node, attr)
              end
            end

            scrub_css_attribute(node)
          else
            Loofah::HTML5::Scrub.scrub_attributes(node)
          end

          if @report
            record_attribute_changes(node, before, removal_reasons)
          end
        end

        def removal_disposition(node)
          if prune || node.namespace
            :prune
          else
            :strip
          end
        end

        def removal_reason(node)
          return :comment if node.comment?
          return :namespace if node.namespace

          :not_allowed
        end

        def attribute_name(attr)
          Loofah::HTML5::Scrub.prefixed_attribute_name(attr)
        end

        def attribute_removal_reason(_attr)
          :not_allowed
        end

        def scrub_css_attribute(node)
          if Loofah::HTML5::Scrub.respond_to?(:scrub_css_attribute)
            Loofah::HTML5::Scrub.scrub_css_attribute(node)
          else
            style = node.attributes["style"]
            style.value = Loofah::HTML5::Scrub.scrub_css(style.value) if style
          end
        end

        def validate!(var, name)
          if var && !var.is_a?(Enumerable)
            raise ArgumentError, "You should pass :#{name} as an Enumerable"
          end

          if var && name == :tags
            if var.include?("mglyph")
              warn("WARNING: 'mglyph' tags cannot be allowed by the PermitScrubber and will be scrubbed")
              var.delete("mglyph")
            end

            if var.include?("malignmark")
              warn("WARNING: 'malignmark' tags cannot be allowed by the PermitScrubber and will be scrubbed")
              var.delete("malignmark")
            end

            if var.include?("noscript")
              warn("WARNING: 'noscript' tags cannot be allowed by the PermitScrubber and will be scrubbed")
              var.delete("noscript")
            end
          end

          var
        end

        def scrub_attribute(node, attr_node)
          attr_name = Loofah::HTML5::Scrub.prefixed_attribute_name(attr_node)

          return if Loofah::HTML5::Scrub.scrub_attribute_value(node, attr_node, attr_name)

          node.remove_attribute(attr_node.name) if attr_name == "src" && attr_node.value !~ /[^[:space:]]/

          Loofah::HTML5::Scrub.force_correct_attribute_escaping! node
        end
    end

    # === Rails::HTML::TargetScrubber
    #
    # Where +Rails::HTML::PermitScrubber+ picks out tags and attributes to permit in
    # sanitization, +Rails::HTML::TargetScrubber+ targets them for removal.
    #
    # +tags=+
    # If set, elements included will be stripped.
    #
    # +attributes=+
    # If set, attributes included will be removed.
    class TargetScrubber < PermitScrubber
      def allowed_node?(node)
        !super
      end

      def scrub_attribute?(name)
        !super
      end

      protected
        def removal_reason(node)
          return :comment if node.comment?
          return :namespace if node.namespace

          :targeted
        end

        def attribute_removal_reason(_attr)
          :targeted
        end
    end

    # === Rails::HTML::ReportingStripScrubber
    #
    # Behaves exactly like Loofah's +:strip+ scrubber, but also records each
    # unwrapped element in an optional report.
    class ReportingStripScrubber < Loofah::Scrubbers::Strip
      include Rails::HTML::Recorder

      def initialize(report: nil)
        super()
        @report = Rails::HTML::Sanitizer::Report.sink(report)
      end

      def scrub(node)
        result = super
        if result == STOP && @report
          reason = node.comment? ? :comment : :not_allowed
          record_tag(node, :strip, reason)
        end
        result
      end
    end

    # === Rails::HTML::TextOnlyScrubber
    #
    # +Rails::HTML::TextOnlyScrubber+ allows you to permit text nodes.
    #
    # Unallowed elements will be stripped, i.e. element is removed but its subtree kept.
    class TextOnlyScrubber < Loofah::Scrubber
      include Rails::HTML::Recorder

      def initialize(report: nil)
        @direction = :bottom_up
        @report = Rails::HTML::Sanitizer::Report.sink(report)
      end

      def scrub(node)
        if node.text?
          CONTINUE
        else
          if @report && !node.comment?
            record_tag(node, :strip, :not_allowed)
          elsif @report
            record_tag(node, :strip, :comment)
          end
          node.before node.children
          node.remove
        end
      end
    end
  end
end
