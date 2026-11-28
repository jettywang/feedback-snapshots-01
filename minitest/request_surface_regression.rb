require File.expand_path(File.dirname(__FILE__) + '/test_helper')
require File.expand_path(File.dirname(__FILE__) + '/support/request_surface_generator')

# Regression coverage for request-surface rewrites done by Ruby HTTP clients
# (and the gems they talk to) when they are upgraded.
#
# Every request is performed in-process through WebMock's Net::HTTP adapter.
# A catch-all stub is registered first, so it is only selected when no sample
# stub matches; nothing can reach the network. Each test compares:
#
#   * which stub was selected (response body),
#   * how many times each stub was selected, and
#   * whether a near miss still fails to match.
class RequestSurfaceRegression < Minitest::Test
  include WebMockSurfaceRegression

  def setup
    WebMock.reset!
    WebMockSurfaceRegression.reset_network_config
    @safety = stub_request(:any, /.*/).to_return(body: "no-stub-selected")
  end

  def teardown
    WebMock.reset!
    WebMockSurfaceRegression.reset_network_config
  end

  def test_seed_is_pinned
    assert_equal 20_261_129, WebMockSurfaceRegression::SEED
  end

  def test_generator_only_uses_declared_equivalence_and_guard_rules
    uri_rules = uri_samples.flat_map do |sample|
      generated_variants(sample).flat_map(&:rules)
    end
    guard_rules = uri_samples.flat_map { |sample| guard_variants(sample).map(&:first) }
    header_rules = header_variants.flat_map(&:rules)
    header_guard_rules = header_guards.map(&:first)

    assert_empty uri_rules - WebMockSurfaceRegression::EQUIVALENCE_RULES
    assert_empty header_rules - WebMockSurfaceRegression::EQUIVALENCE_RULES
    assert_empty guard_rules - WebMockSurfaceRegression::NON_EQUIVALENCE_RULES
    assert_empty header_guard_rules - WebMockSurfaceRegression::NON_EQUIVALENCE_RULES
  end

  def test_equivalent_uri_surfaces_select_the_same_stub
    uri_samples.each_with_index do |sample, offset|
      canonical = canonical_uri(sample)
      stub = stub_request(sample[:method], canonical).to_return(body: sample[:id])
      recorded_before = recorded_request_count

      generated_variants(sample, offset: offset).each_with_index do |variant, index|
        response = perform(variant.uri, method: sample[:method])

        assert_equal sample[:id], response.body,
          "variant #{variant.uri.inspect} did not select stub #{sample[:id].inspect} " \
          "(rules: #{variant.rules.sort.inspect})"
        assert_equal index + 1, times_executed(stub)
        assert_equal recorded_before + index + 1, recorded_request_count,
          "variant #{variant.uri.inspect} should have selected exactly one stub"
      end
    end
  end

  def test_equivalent_surfaces_are_symmetric_for_stub_and_request
    uri_samples.each_with_index do |sample, offset|
      canonical = canonical_uri(sample)
      pattern = WebMock::RequestPattern.new(sample[:method], canonical)

      generated_variants(sample, offset: offset).each do |variant|
        signature = WebMock::RequestSignature.new(sample[:method], variant.uri)
        assert pattern.matches?(signature),
          "pattern #{canonical.inspect} rejected equivalent #{variant.uri.inspect} " \
          "(rules: #{variant.rules.sort.inspect})"

        reverse = WebMock::RequestPattern.new(sample[:method], variant.uri)
        assert reverse.matches?(WebMock::RequestSignature.new(sample[:method], canonical)),
          "pattern #{variant.uri.inspect} rejected equivalent #{canonical.inspect}"
      end
    end
  end

  def test_near_miss_uri_surfaces_do_not_select_the_stub
    uri_samples.each_with_index do |sample, _offset|
      canonical = canonical_uri(sample)
      stub = stub_request(sample[:method], canonical).to_return(body: sample[:id])
      recorded_before = recorded_request_count
      safety_before = recorded_by_safety(canonical)

      guard_variants(sample).each_with_index do |(rule, guard_uri), index|
        response = perform(guard_uri, method: sample[:method])

        assert_equal "no-stub-selected", response.body,
          "guard #{rule.inspect} #{guard_uri.inspect} unexpectedly selected " \
          "stub #{sample[:id].inspect}"
        assert_equal 0, times_executed(stub)
        assert_equal recorded_before + index + 1, recorded_request_count
        assert_equal safety_before + index + 1, recorded_by_safety(canonical)
      end
    end
  end

  def test_guard_without_the_catch_all_raises_an_unregistered_request_error
    sample = uri_samples.find { |candidate| candidate[:id] == "uri-root-scalars" }
    canonical = canonical_uri(sample)
    WebMock.reset!
    WebMockSurfaceRegression.reset_network_config
    stub = stub_request(sample[:method], canonical).to_return(body: sample[:id])

    rule, guard_uri = guard_variants(sample).find { |name, _| name == :scalar_value_changed }

    error = assert_raises(WebMock::NetConnectNotAllowedError) do
      perform(guard_uri, method: sample[:method])
    end
    assert_match(/Real HTTP connections are disabled/, error.message)
    assert_includes error.message, "q=a-x",
      "the failure must name the guard request that did not match"
    assert_equal 0, times_executed(stub)
    assert_equal 1, recorded_request_count
    assert_equal rule, :scalar_value_changed
  end

  def test_repeated_query_array_items_are_order_insensitive_but_repeated_scalars_are_not
    WebMock.reset!
    WebMockSurfaceRegression.reset_network_config
    @safety = stub_request(:any, /.*/).to_return(body: "no-stub-selected")

    array_stub = stub_request(:get, "http://example.com/a?ids[]=v0&ids[]=v1").to_return(body: "array")
    assert_equal "array", perform("http://example.com/a?ids[1]=v1&ids[0]=v0").body
    assert_equal "array", perform("http://example.com/a?ids%5B%5D=v0&ids%5B%5D=v1").body
    assert_equal 2, times_executed(array_stub)

    WebMock.reset!
    WebMockSurfaceRegression.reset_network_config
    @safety = stub_request(:any, /.*/).to_return(body: "no-stub-selected")
    scalar_stub = stub_request(:get, "http://example.com/s?a=1&a=2").to_return(body: "scalar")
    assert_equal "scalar", perform("http://example.com/s?a=1&a=2").body
    assert_equal "no-stub-selected", perform("http://example.com/s?a=2&a=1").body,
      "the last value of a repeated scalar query key wins, so swapping it changes the request"
    assert_equal 1, times_executed(scalar_stub)
  end

  def test_equivalent_header_surfaces_select_the_same_stub
    sample = header_sample
    stub = stub_request(sample[:method], sample[:uri])
      .with(headers: header_hash(sample[:headers]))
      .to_return(body: sample[:id])

    header_variants(sample).each_with_index do |variant, index|
      response = perform(sample[:uri], headers: header_hash(variant.headers))

      assert_equal sample[:id], response.body,
        "header variant #{variant.headers.inspect} did not select the stub " \
        "(rules: #{variant.rules.sort.inspect})"
      assert_equal index + 1, times_executed(stub)
      assert_equal index + 1, recorded_request_count
    end
  end

  def test_near_miss_header_surfaces_do_not_select_the_stub
    sample = header_sample
    stub = stub_request(sample[:method], sample[:uri])
      .with(headers: header_hash(sample[:headers]))
      .to_return(body: sample[:id])

    header_guards(sample).each_with_index do |(rule, headers), index|
      response = perform(sample[:uri], headers: header_hash(headers))

      assert_equal "no-stub-selected", response.body,
        "header guard #{rule.inspect} #{headers.inspect} unexpectedly selected the stub"
      assert_equal 0, times_executed(stub)
      assert_equal index + 1, recorded_request_count
    end
  end

  def test_form_body_indexes_keep_numeric_order_beyond_ten_entries
    values = (0...12).map { |index| "v#{index}" }
    stub = stub_request(:post, "http://example.com/form")
      .with(body: { "ids" => values })
      .to_return(body: "indexed")

    reversed_indexes = (0...12).to_a.reverse
    shuffled_body = reversed_indexes.map { |index| "ids[#{index}]=#{values[index]}" }.join("&")

    response = perform(
      "http://example.com/form", method: :post, body: shuffled_body,
      headers: { "Content-Type" => "application/x-www-form-urlencoded" }
    )
    assert_equal "indexed", response.body,
      "indexed form values must be ordered by index number, not as text"
    assert_requested stub, times: 1
  end

  def test_content_type_given_more_than_once_uses_the_first_value_after_sorting
    stub = stub_request(:post, "http://example.com/upload")
      .with(body: { "a" => "1" })
      .to_return(body: "json")

    response = perform(
      "http://example.com/upload", method: :post,
      headers: { "Content-Type" => ["application/json", "application/json"] },
      body: '{"a":"1"}'
    )
    assert_equal "json", response.body
    assert_requested stub, times: 1
  end

  def test_allowed_uri_comparison_uses_the_same_equivalence_rules
    WebMock.disable_net_connect!(
      allow: "http://example.com/search?b=2&a=1&ids[]=v0&ids[]=v1"
    )

    assert WebMock.net_connect_allowed?(
      "http://Example.COM:80/search?a=1&b=2&ids[1]=v1&ids[0]=v0"
    ), "allowed URI should match its equivalent surface forms"
    refute WebMock.net_connect_allowed?(
      "http://example.com/search?a=1&b=2&ids[]=v0&ids[]=changed"
    ), "a changed array value must still be rejected"
    refute WebMock.net_connect_allowed?(
      "http://example.com/search?a=1&b=2&ids[]=v0&ids[]=v1&extra=1"
    ), "an extra query item must still be rejected"
  end

  # The seeded generator finds a repeated-array variant that only differs in
  # array order. The shrinker removes pairs shared by both surfaces; the
  # normalized rendering shows the shortest pair, and the report names the one
  # registered normal request the order-blind double wrongly swallowed.
  def test_seeded_variant_shrinks_to_the_shortest_multi_value_difference
    sample = uri_samples.find { |candidate| candidate[:id] == "uri-repeated-array" }
    offset = uri_samples.index(sample)
    endpoint = "http://example.com/form"
    canonical = canonical_uri(sample)
    canonical_query = canonical.split("?", 2).last

    variant = generated_variants(sample, count: 50, offset: offset).find do |candidate|
      form_order_only_difference?(canonical_query, candidate.uri.split("?", 2).last)
    end
    refute_nil variant, "the pinned seed should produce an order-only array variant"
    assert_includes variant.rules, :repeated_query_array_order
    swapped_query = variant.uri.split("?", 2).last

    shooter = lambda do |body|
      double = WebMockSurfaceRegression::OrderBlindDouble.new
      double.register("repeated-array", method: :post, uri: endpoint, body: canonical_query)
      double.register("distinct-fields", method: :post, uri: endpoint, body: "q=a&lang=en")
      double.dispatch(method: :post, uri: endpoint, body: body)
    end

    assert_equal "repeated-array", shooter.call(swapped_query),
      "the order-blind double treats the re-ordered array as the normal request"
    assert_equal "distinct-fields", shooter.call("lang=en&q=a"),
      "distinct form fields may be re-ordered without changing the request"

    left, right = shrink_pair(
      "#{endpoint}?#{canonical_query}", "#{endpoint}?#{swapped_query}", normalize: true
    ) do |one, two|
      selected = shooter.call(one)
      !selected.nil? && selected == shooter.call(two)
    end

    assert_equal "q=a&ids[]=v0&ids[]=v1", left
    assert_equal "ids[]=v1&q=a&ids[]=v0", right

    # The real matcher keeps the multi-value order significant.
    refute form_pattern(canonical_query).matches?(form_signature(right)),
      "WebMock's form-body matching must keep the repeated array item's order significant"

    # And end-to-end, only the normal request is counted once: the swapped
    # body falls through to the catch-all stub.
    stub = stub_request(:post, endpoint)
      .with(body: WebMock::Util::QueryMapper.query_to_values(canonical_query))
      .to_return(body: "normal")
    assert_equal "normal", perform(endpoint, method: :post, body: canonical_query,
      headers: { "Content-Type" => "application/x-www-form-urlencoded" }).body
    assert_equal "no-stub-selected", perform(endpoint, method: :post, body: right,
      headers: { "Content-Type" => "application/x-www-form-urlencoded" }).body
    assert_equal 1, times_executed(stub)

    assert_equal(
      "query item 1: \"ids[]=v0\" != \"ids[]=v1\"",
      shortest_difference(left, right)
    )
  end

  def test_shortest_difference_names_the_affected_query_item
    left = "http://example.com/a?q=b%20c&ids[]=v0&ids[]=v1"
    right = "http://example.com/a?q=b%20c&ids[]=v0&ids[]=v2"

    assert_equal(
      "query item 2: \"ids[]=v1\" != \"ids[]=v2\"",
      shortest_difference(left, right)
    )
  end

  private

  def form_pattern(body)
    WebMock::RequestPattern.new(:post, "http://example.com/form", body: WebMock::Util::QueryMapper.query_to_values(body))
  end

  def form_signature(body)
    WebMock::RequestSignature.new(
      :post, "http://example.com/form", body: body,
      headers: { "Content-Type" => "application/x-www-form-urlencoded" }
    )
  end

  # Counts recorded requests that the sample pattern does not match, i.e.
  # those that must have been served by the catch-all stub.
  def recorded_by_safety(canonical)
    sample_pattern = WebMock::RequestPattern.new(:get, canonical)
    WebMock::RequestRegistry.instance.requested_signatures.hash.sum do |signature, times|
      sample_pattern.matches?(signature) ? 0 : times
    end
  end
end
