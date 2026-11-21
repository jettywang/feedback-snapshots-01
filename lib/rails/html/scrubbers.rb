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
      attr_reader :tags, :attributes, :prune

      def initialize(prune: false)
        @prune = prune
        @direction = @prune ? :top_down : :bottom_up
        @tags, @attributes = nil, nil
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
          return STOP unless scrub_node(node) == CONTINUE
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
          if @attributes
            node.attribute_nodes.each do |attr|
              if scrub_attribute?(attr.name)
                attr.remove
              else
                scrub_attribute(node, attr)
              end
            end

            scrub_css_attribute(node)
          else
            Loofah::HTML5::Scrub.scrub_attributes(node)
          end
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
    end

    # === Rails::HTML::TextOnlyScrubber
    #
    # +Rails::HTML::TextOnlyScrubber+ allows you to permit text nodes.
    #
    # Unallowed elements will be stripped, i.e. element is removed but its subtree kept.
    class TextOnlyScrubber < Loofah::Scrubber
      def initialize
        @direction = :bottom_up
      end

      def scrub(node)
        if node.text?
          CONTINUE
        else
          node.before node.children
          node.remove
        end
      end
    end

    # === Rails::HTML::LinkTargetScrubber
    #
    # +Rails::HTML::LinkTargetScrubber+ enforces a per-channel policy on the
    # destination of +a+ tags, so the same sanitized content can be published
    # to channels with different link requirements (e.g. web pages and email).
    #
    # Relative links, such as internal documentation paths, are kept as-is on
    # the +web+ channel. On the +email+ channel they are resolved against
    # +base_url+, because relative destinations are broken in mail clients;
    # without a +base_url+ their +href+ is removed.
    #
    # Absolute +http+/+https+ links are kept only when their host matches one
    # of +approved_domains+ (subdomains included). Any other destination is
    # unapproved: the +href+ attribute is removed at publish time, while the
    # link text and all other attributes are left untouched. The scrubber
    # never annotates the output with its decisions.
    #
    #   policy = Rails::HTML::LinkTargetScrubber.new(
    #     channel: :email,
    #     approved_domains: %w(help.example.com),
    #     base_url: "https://help.example.com",
    #   )
    #   Rails::HTML::SafeListSanitizer.new.sanitize(html, link_policy: policy)
    class LinkTargetScrubber < Loofah::Scrubber
      CHANNELS = %i(web email).freeze

      attr_reader :channel, :approved_domains, :base_url

      def initialize(channel: :web, approved_domains: [], base_url: nil)
        @channel = channel.to_sym
        unless CHANNELS.include?(@channel)
          raise ArgumentError, "unknown link policy channel: #{channel.inspect}"
        end

        @approved_domains = approved_domains.map { |domain| domain.to_s.downcase }.freeze
        @base_url = base_url
        @direction = :top_down
      end

      def scrub(node)
        return CONTINUE unless node.element? && node.name == "a"

        href = node["href"]
        return CONTINUE if href.nil? || href.strip.empty?

        uri = parse_uri(href)
        if uri.nil?
          node.remove_attribute("href")
        elsif relative?(uri)
          scrub_relative(node, href)
        elsif !approved?(uri)
          node.remove_attribute("href")
        end

        CONTINUE
      end

      private
        def parse_uri(href)
          URI.parse(href.strip)
        rescue URI::InvalidURIError
          nil
        end

        def relative?(uri)
          uri.scheme.nil? && uri.host.nil?
        end

        def approved?(uri)
          return false unless %w(http https).include?(uri.scheme.to_s.downcase)

          host = uri.host.to_s.downcase
          approved_domains.any? { |domain| host == domain || host.end_with?(".#{domain}") }
        end

        def scrub_relative(node, href)
          return if channel == :web

          resolved = resolve(href)
          if resolved && approved?(resolved)
            node["href"] = resolved.to_s
          else
            node.remove_attribute("href")
          end
        end

        def resolve(href)
          return unless base_url

          parse_uri(URI.join(base_url, href).to_s)
        rescue URI::InvalidURIError
          nil
        end
    end
  end
end
