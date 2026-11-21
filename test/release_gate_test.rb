# frozen_string_literal: true

require_relative "test_helper"

# Release-gate coverage for the Ruby platform migration: after the migration
# some services select the HTML4 vendor while others select the HTML5 vendor.
# These tests prove that the same approved content survives the full pipeline
# -- sanitize-on-save, re-sanitize-on-load, and render -- with the protection
# rules intact under each vendor, and that both vendors preserve the same
# legal content.
#
# The gate compares re-parsed node trees and legal content, never literal
# output strings: the vendors may serialize identical structures differently
# (KNOWN_SERIALIZATION_DIFFERENCES) and may build slightly different trees
# for a small, recorded set of constructs (KNOWN_STRUCTURAL_DIFFERENCES).
class ReleaseGateTest < Minitest::Test
  FIXTURE_DIR = File.expand_path("fixtures/release_gate", __dir__)
  FIXTURES = %w[rich_text nested_fragment preserved_text].freeze

  URI_ATTRIBUTES = %w[href src cite].freeze

  ALLOWED_TAGS = Rails::HTML::Concern::Scrubber::SafeList::DEFAULT_ALLOWED_TAGS
  ALLOWED_ATTRIBUTES = Rails::HTML::Concern::Scrubber::SafeList::DEFAULT_ALLOWED_ATTRIBUTES

  # Catalog of structural differences the two vendors are allowed to produce.
  # Every entry is executable: the cross-vendor tests reconcile exactly these
  # differences and fail if a recorded difference stops occurring or a new,
  # unrecorded difference appears.
  STRUCTURAL_DIFFERENCE_CATALOG = {
    serializer_whitespace:
      "html4's libxml2 serializer injects newline-only text nodes around " \
        "elements it treats as non-inline (observed inside <li>); html5 does " \
        "not. Whitespace-only text nodes outside <pre> collapse when rendered " \
        "and are reconciled by dropping them.",
    pre_leading_newline:
      "html5 drops the first newline inside <pre> (WHATWG HTML parsing rule); " \
        "html4 preserves it as leading text.",
  }.freeze

  # Which recorded differences apply to each fixture.
  KNOWN_STRUCTURAL_DIFFERENCES = {
    "rich_text" => %i[serializer_whitespace],
    "nested_fragment" => %i[serializer_whitespace],
    "preserved_text" => %i[pre_leading_newline],
  }.freeze

  # Serialization-only differences: the rendered strings differ, but the
  # re-parsed nodes are identical, so these never require reconciliation.
  KNOWN_SERIALIZATION_DIFFERENCES = {
    "preserved_text" => [
      "html4 serializes U+00A0 as a raw UTF-8 character; html5 serializes it as &nbsp;",
    ].freeze,
  }.freeze

  FIXTURES.each do |fixture|
    define_method "test_#{fixture}_save_resanitize_render_is_idempotent_per_vendor" do
      each_vendor do |vendor, sanitizer|
        saved = sanitizer.sanitize(read_fixture(fixture))
        rendered = sanitizer.sanitize(saved)

        assert_equal signature_for(vendor, saved), signature_for(vendor, rendered),
          "#{vendor}: re-sanitizing saved #{fixture} content changed the node tree"
      end
    end

    define_method "test_#{fixture}_rendered_output_obeys_protection_rules" do
      each_vendor do |vendor, _sanitizer|
        rendered = save_resanitize_render(vendor, read_fixture(fixture))

        assert_protection_rules(parse_fragment(vendor, rendered), "#{fixture}/#{vendor}")
      end
    end

    define_method "test_#{fixture}_vendors_render_equivalent_legal_content" do
      skip "html5 vendor unavailable on this platform" unless html5_available?

      signatures = vendor_names.to_h do |vendor|
        [vendor, signature_for(vendor, save_resanitize_render(vendor, read_fixture(fixture)))]
      end

      recorded_rules = KNOWN_STRUCTURAL_DIFFERENCES.fetch(fixture, [])
      if recorded_rules.empty?
        assert_equal signatures["html4"], signatures["html5"],
          "#{fixture}: vendors diverged on an unrecorded structure"
      else
        refute_equal signatures["html4"], signatures["html5"],
          "#{fixture}: a recorded difference no longer occurs; update " \
            "KNOWN_STRUCTURAL_DIFFERENCES (#{describe_rules(recorded_rules)})"
      end

      reconciled = signatures.to_h do |vendor, signature|
        [vendor, reconcile_recorded_differences(fixture, vendor, signature)]
      end
      assert_equal reconciled["html4"], reconciled["html5"],
        "#{fixture}: vendors differ beyond the recorded structures " \
          "(#{describe_rules(recorded_rules)})"
    end
  end

  def test_literal_string_equality_is_not_the_gate
    skip "html5 vendor unavailable on this platform" unless html5_available?

    fixture = KNOWN_SERIALIZATION_DIFFERENCES.keys.fetch(0)
    rendered = vendor_names.to_h do |vendor|
      [vendor, save_resanitize_render(vendor, read_fixture(fixture))]
    end

    refute_equal rendered["html4"], rendered["html5"],
      "expected the recorded serialization differences to keep the rendered " \
        "strings distinct: #{KNOWN_SERIALIZATION_DIFFERENCES[fixture].join}"

    reconciled = rendered.to_h do |vendor, html|
      [vendor, reconcile_recorded_differences(fixture, vendor, signature_for(vendor, html))]
    end
    assert_equal reconciled["html4"], reconciled["html5"],
      "rendered strings differ, but the re-parsed legal content must still match"
  end

  private
    def html5_available?
      Rails::HTML::Sanitizer.html5_support?
    end

    def vendor_names
      html5_available? ? %w[html4 html5] : %w[html4]
    end

    def each_vendor
      yield "html4", Rails::HTML4::SafeListSanitizer.new
      yield "html5", Rails::HTML5::SafeListSanitizer.new if html5_available?
    end

    def save_resanitize_render(vendor, content)
      sanitizer = vendor == "html5" ? Rails::HTML5::SafeListSanitizer.new : Rails::HTML4::SafeListSanitizer.new
      sanitizer.sanitize(sanitizer.sanitize(content))
    end

    def read_fixture(fixture)
      File.read(File.join(FIXTURE_DIR, "#{fixture}.html"), encoding: Encoding::UTF_8)
    end

    def parse_fragment(vendor, html)
      vendor == "html5" ? Loofah.html5_fragment(html) : Loofah.html4_fragment(html)
    end

    # A canonical, serialization-independent view of a fragment: element
    # names, sorted attribute name/value pairs, and exact text content.
    def node_signature(node)
      if node.element?
        attributes = node.attribute_nodes.map { |attr| [attr.name, attr.value] }.sort
        [:element, node.name, attributes, node.children.map { |child| node_signature(child) }]
      elsif node.text?
        [:text, node.content]
      else
        [:other, node.class.name]
      end
    end

    def signature_for(vendor, html)
      parse_fragment(vendor, html).children.map { |node| node_signature(node) }
    end

    def describe_rules(rules)
      rules.map { |rule| STRUCTURAL_DIFFERENCE_CATALOG.fetch(rule) }.join(" ")
    end

    # Reconciles exactly the differences recorded for +fixture+ in
    # KNOWN_STRUCTURAL_DIFFERENCES so the remaining trees must be identical.
    def reconcile_recorded_differences(fixture, vendor, signature)
      KNOWN_STRUCTURAL_DIFFERENCES.fetch(fixture, []).reduce(signature) do |reconciled, rule|
        case rule
        when :serializer_whitespace
          drop_insignificant_whitespace(reconciled)
        when :pre_leading_newline
          vendor == "html4" ? drop_pre_leading_newline(reconciled) : reconciled
        else
          raise "no reconciliation implemented for recorded difference #{rule.inspect}"
        end
      end
    end

    # Whitespace-only text nodes outside <pre> are insignificant: browsers
    # collapse them, so the vendors may legitimately disagree about them.
    def drop_insignificant_whitespace(nodes, in_pre = false)
      nodes.each_with_object([]) do |node, kept|
        if node.first == :text
          kept << node if in_pre || node[1] !~ /\A[ \t\r\n\f]*\z/
        elsif node.first == :element
          kept << [:element, node[1], node[2], drop_insignificant_whitespace(node[3], in_pre || node[1] == "pre")]
        else
          kept << node
        end
      end
    end

    def drop_pre_leading_newline(nodes)
      nodes.map do |node|
        next node unless node.first == :element

        children = drop_pre_leading_newline(node[3])
        if node[1] == "pre" && children.first&.first == :text
          children = children.dup
          children[0] = [:text, children.first[1].sub(/\A\n/, "")]
          children.shift if children.first[1].empty?
        end
        [:element, node[1], node[2], children]
      end
    end

    def assert_protection_rules(fragment, label)
      fragment.traverse do |node|
        if node.element?
          assert_includes ALLOWED_TAGS, node.name,
            "#{label}: tag <#{node.name}> is outside the safe list"
          node.attribute_nodes.each do |attr|
            assert_includes ALLOWED_ATTRIBUTES, attr.name,
              "#{label}: attribute #{attr.name} on <#{node.name}> is outside the safe list"
            refute_match(/\Aon/i, attr.name,
              "#{label}: event handler #{attr.name} survived sanitization")
            if URI_ATTRIBUTES.include?(attr.name)
              assert Rails::HTML::Sanitizer.allowed_uri?(attr.value),
                "#{label}: URI #{attr.value.inspect} on <#{node.name}> uses a disallowed scheme"
            end
          end
        end
        refute node.comment?, "#{label}: comment survived sanitization"
        refute node.processing_instruction?, "#{label}: processing instruction survived sanitization"
      end
    end
end
