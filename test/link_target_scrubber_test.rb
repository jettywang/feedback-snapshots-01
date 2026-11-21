# frozen_string_literal: true

require_relative "test_helper"

class LinkTargetScrubberTest < Minitest::Test
  APPROVED = %w(help.example.com).freeze
  BASE_URL = "https://help.example.com"

  def setup
    @sanitizer = Rails::HTML::Sanitizer.best_supported_vendor.safe_list_sanitizer.new
  end

  def sanitize(html, **policy_options)
    policy = Rails::HTML::LinkTargetScrubber.new(**policy_options)
    @sanitizer.sanitize(html, link_policy: policy)
  end

  def reparsed_links(html)
    Loofah.fragment(html).css("a")
  end

  def test_unknown_channel_is_rejected
    error = assert_raises(ArgumentError) do
      Rails::HTML::LinkTargetScrubber.new(channel: :print)
    end
    assert_includes error.message, "print"
  end

  def test_web_channel_keeps_relative_document_links
    output = sanitize('<a href="/docs/getting-started">指南</a>',
                      channel: :web, approved_domains: APPROVED)

    link = reparsed_links(output).first
    assert_equal "/docs/getting-started", link["href"]
    assert_equal "指南", link.text
  end

  def test_web_channel_keeps_approved_domains_and_subdomains
    output = sanitize('<a href="https://help.example.com/articles/1">一</a>' \
                      '<a href="https://docs.help.example.com/2">二</a>',
                      channel: :web, approved_domains: APPROVED)

    hrefs = reparsed_links(output).map { |link| link["href"] }
    assert_equal %w(https://help.example.com/articles/1 https://docs.help.example.com/2), hrefs
  end

  def test_web_channel_strips_href_of_unknown_targets_but_keeps_text_and_attributes
    output = sanitize('<a class="btn" title="参考" href="https://unknown.example.net/x">了解更多</a>',
                      channel: :web, approved_domains: APPROVED)

    link = reparsed_links(output).first
    assert_nil link["href"]
    assert_equal "了解更多", link.text
    assert_equal "btn", link["class"]
    assert_equal "参考", link["title"]
  end

  def test_web_channel_strips_unapproved_schemes_and_protocol_relative_targets
    output = sanitize('<a href="javascript:alert(1)">一</a>' \
                      '<a href="//unknown.example.net/x">二</a>',
                      channel: :web, approved_domains: APPROVED)

    reparsed_links(output).each do |link|
      assert_nil link["href"]
    end
    assert_equal %w(一 二), reparsed_links(output).map(&:text)
  end

  def test_email_channel_resolves_relative_documents_against_base_url
    output = sanitize('<a href="/docs/getting-started">指南</a>',
                      channel: :email, approved_domains: APPROVED, base_url: BASE_URL)

    link = reparsed_links(output).first
    assert_equal "https://help.example.com/docs/getting-started", link["href"]
    assert_equal "指南", link.text
  end

  def test_email_channel_removes_relative_href_without_base_url
    output = sanitize('<a href="/docs/getting-started">指南</a>',
                      channel: :email, approved_domains: APPROVED)

    link = reparsed_links(output).first
    assert_nil link["href"]
    assert_equal "指南", link.text
  end

  def test_email_channel_keeps_approved_absolute_links
    output = sanitize('<a href="https://help.example.com/articles/1">文章</a>',
                      channel: :email, approved_domains: APPROVED, base_url: BASE_URL)

    assert_equal "https://help.example.com/articles/1", reparsed_links(output).first["href"]
  end

  def test_email_channel_strips_unknown_absolute_targets
    output = sanitize('<a href="https://unknown.example.net/x">了解更多</a>',
                      channel: :email, approved_domains: APPROVED, base_url: BASE_URL)

    link = reparsed_links(output).first
    assert_nil link["href"]
    assert_equal "了解更多", link.text
  end

  def test_unparseable_href_is_removed
    output = sanitize('<a href="http://exa mple.com/">坏链接</a>',
                      channel: :web, approved_domains: APPROVED)

    link = reparsed_links(output).first
    assert_nil link["href"]
    assert_equal "坏链接", link.text
  end

  def test_link_policy_composes_with_safe_list_scrubbing
    output = sanitize('<p onclick="x()"><a href="/docs/a">文档</a></p><script>alert(1)</script>',
                      channel: :web, approved_domains: APPROVED)

    assert_nil Loofah.fragment(output).at_css("script")
    paragraph = Loofah.fragment(output).at_css("p")
    assert_nil paragraph["onclick"]
    assert_equal "/docs/a", paragraph.at_css("a")["href"]
  end

  def test_output_carries_no_internal_validation_information
    output = sanitize('<a href="https://unknown.example.net/x">一</a>' \
                      '<a href="/docs/a">二</a>',
                      channel: :web, approved_domains: APPROVED)

    reparsed_links(output).each do |link|
      extra = link.attribute_nodes.map(&:name) - %w(href class title)
      assert_empty extra
    end
    refute_match(/data-|policy|approved|scrub/i, output)
  end
end
