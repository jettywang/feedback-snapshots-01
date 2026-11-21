# frozen_string_literal: true

require_relative "test_helper"
require "timeout"

class PolicyTest < Minitest::Test
  def setup
    @registry = Rails::HTML::Sanitizer::PolicyRegistry.new
  end

  def test_policy_is_an_immutable_value_object
    tags = %w[p b]
    attributes = %w[href]
    policy = Rails::HTML::Sanitizer::Policy.new(
      name: "tenant-a",
      version: 1,
      tags: tags,
      attributes: attributes,
    )

    tags << "u"
    attributes << "onclick"

    assert_equal %w[p b], policy.allowed_tags
    assert_equal %w[href], policy.allowed_attributes
    assert policy.frozen?
    assert policy.allowed_tags.frozen?
    assert policy.allowed_attributes.frozen?
    assert_equal "tenant-a@1", policy.reference
    assert_equal "tenant-a@1", policy.to_s
    assert_equal policy, policy.dup
    assert_equal policy.hash, policy.dup.hash
  end

  def test_policy_defaults_to_the_standard_safe_list
    policy = Rails::HTML::Sanitizer::Policy.new(name: "default", version: 1)

    assert_equal Rails::HTML::Concern::Scrubber::SafeList::DEFAULT_ALLOWED_TAGS.to_a.sort,
      policy.allowed_tags.sort
    assert_equal Rails::HTML::Concern::Scrubber::SafeList::DEFAULT_ALLOWED_ATTRIBUTES.to_a.sort,
      policy.allowed_attributes.sort
  end

  def test_policy_digest_depends_on_effective_permissions_not_order
    a = Rails::HTML::Sanitizer::Policy.new(name: "p", version: 1, tags: %w[p b], attributes: %w[href])
    b = Rails::HTML::Sanitizer::Policy.new(name: "p", version: 1, tags: %w[b p], attributes: %w[href])
    c = Rails::HTML::Sanitizer::Policy.new(name: "p", version: 2, tags: %w[p b], attributes: %w[href])

    assert_equal a.digest, b.digest
    refute_equal a.digest, c.digest
  end

  def test_policy_rejects_unsafe_permissions
    assert_raises(Rails::HTML::Sanitizer::InvalidPolicyError) do
      Rails::HTML::Sanitizer::Policy.new(name: "p", version: 1, tags: %w[p script])
    end

    assert_raises(Rails::HTML::Sanitizer::InvalidPolicyError) do
      Rails::HTML::Sanitizer::Policy.new(name: "p", version: 1, attributes: %w[href onclick])
    end

    assert_raises(Rails::HTML::Sanitizer::InvalidPolicyError) do
      Rails::HTML::Sanitizer::Policy.new(name: "p", version: 1, tags: "p")
    end

    assert_raises(Rails::HTML::Sanitizer::InvalidPolicyError) do
      Rails::HTML::Sanitizer::Policy.new(name: "", version: 1)
    end

    assert_raises(Rails::HTML::Sanitizer::InvalidPolicyError) do
      Rails::HTML::Sanitizer::Policy.new(name: "p", version: nil)
    end
  end

  def test_policy_errors_share_a_catch_all_module
    error = assert_raises(Rails::HTML::Sanitizer::PolicyError) do
      Rails::HTML::Sanitizer::Policy.new(name: "p", version: 1, tags: %w[script])
    end

    assert_kind_of ArgumentError, error
    assert_kind_of Rails::HTML::Sanitizer::InvalidPolicyError, error
  end

  def test_registry_publishes_and_resolves_versions
    @registry.publish(name: "tenant-a", version: 1, tags: %w[p b])
    v2 = @registry.publish(name: "tenant-a", version: 2, tags: %w[p b u])

    assert_equal "tenant-a@2", @registry.current("tenant-a").reference
    assert_equal v2, @registry.current("tenant-a")
    assert_equal "tenant-a@1", @registry.fetch("tenant-a", 1).reference
    assert_equal "tenant-a@1", @registry.resolve("tenant-a@1").reference
    assert_equal "tenant-a@2", @registry.resolve(:"tenant-a").reference
    assert_equal "tenant-a@1", @registry.resolve([:"tenant-a", "1"]).reference
    assert_equal "tenant-a@1", @registry.resolve({ name: "tenant-a", version: 1 }).reference
    assert_equal %w[1 2], @registry.versions("tenant-a")
    assert_equal 2, @registry.size
    assert @registry.published?("tenant-a", 2)
    refute @registry.published?("tenant-a", 99)
  end

  def test_republishing_identical_content_is_idempotent
    first = @registry.publish(name: "tenant-a", version: 1, tags: %w[p b])
    second = @registry.publish(name: "tenant-a", version: 1, tags: %w[b p])

    assert_same first, second
    assert_equal 1, @registry.size
  end

  def test_republishing_a_version_with_different_content_is_a_conflict
    @registry.publish(name: "tenant-a", version: 1, tags: %w[p b])

    error = assert_raises(Rails::HTML::Sanitizer::PolicyConflictError) do
      @registry.publish(name: "tenant-a", version: 1, tags: %w[p b i])
    end

    assert_match(/tenant-a@1/, error.message)
    assert_equal %w[p b], @registry.fetch("tenant-a", 1).allowed_tags
    assert_equal 1, @registry.size
  end

  def test_unknown_policy_and_version_are_locatable
    @registry.publish(name: "tenant-a", version: 1, tags: %w[p])

    error = assert_raises(Rails::HTML::Sanitizer::PolicyNotFoundError) do
      @registry.fetch("tenant-b")
    end
    assert_match(/tenant-b/, error.message)
    assert_match(/tenant-a/, error.message)

    error = assert_raises(Rails::HTML::Sanitizer::PolicyNotFoundError) do
      @registry.fetch("tenant-a", 9)
    end
    assert_match(/tenant-a/, error.message)
    assert_match(/9/, error.message)
    assert_match(/1/, error.message)
  end

  def test_backfill_of_an_older_version_does_not_change_current
    @registry.publish(name: "tenant-a", version: 2, tags: %w[p b u])
    @registry.publish(name: "tenant-a", version: 1, tags: %w[p b], current: false)

    assert_equal "tenant-a@2", @registry.current("tenant-a").reference
    assert_equal "tenant-a@1", @registry.fetch("tenant-a", 1).reference
  end

  def test_managed_sanitize_returns_text_and_provenance
    @registry.publish(name: "tenant-a", version: 1, tags: %w[p b], attributes: %w[href])
    managed = Rails::HTML5::SafeListSanitizer.managed(@registry)

    result = managed.sanitize("<p onclick='x'>hi <b>b</b> <u>u</u></p>", policy: "tenant-a@1")

    assert_kind_of String, result
    assert_equal "<p>hi <b>b</b> u</p>", result
    assert_equal "tenant-a@1", result.policy_reference
    assert_equal 1, result.policy_version
    assert_equal "tenant-a", result.policy_name
    assert_equal %w[p b], result.tags
    assert_equal %w[href], result.attributes
    assert_equal result.policy_digest, result.to_h[:digest]
  end

  def test_managed_result_compares_as_string_across_policies
    @registry.publish(name: "tenant-a", version: 1, tags: %w[p])
    @registry.publish(name: "tenant-a", version: 2, tags: %w[p])
    managed = Rails::HTML5::SafeListSanitizer.managed(@registry)

    r1 = managed.sanitize("<p>x</p>", policy: "tenant-a@1")
    r2 = managed.sanitize("<p>x</p>", policy: "tenant-a@2")

    assert_equal "<p>x</p>", r1
    assert_equal r1, "<p>x</p>"
    assert_equal r1, r2, "identical text is the same for legacy string callers"
    refute_equal r1.policy_reference, r2.policy_reference
  end

  def test_managed_sanitize_rejects_permission_overrides
    @registry.publish(name: "tenant-a", version: 1, tags: %w[p])
    managed = Rails::HTML5::SafeListSanitizer.managed(@registry)

    error = assert_raises(Rails::HTML::Sanitizer::InvalidPolicyError) do
      managed.sanitize("<p>x</p>", policy: "tenant-a@1", tags: %w[p script])
    end

    assert_match(/tags/, error.message)
    assert_match(/publish a new policy version/, error.message)
  end

  def test_managed_sanitize_requires_a_policy
    managed = Rails::HTML5::SafeListSanitizer.managed(@registry)

    assert_raises(Rails::HTML::Sanitizer::InvalidPolicyError) do
      managed.sanitize("<p>x</p>")
    end

    assert_raises(Rails::HTML::Sanitizer::InvalidPolicyError) do
      managed.sanitize("<p>x</p>", policy: "tenant-a@1", policy_name: "tenant-a")
    end
  end

  def test_managed_sanitize_can_resolve_current_version_by_name
    @registry.publish(name: "tenant-a", version: 1, tags: %w[p])
    @registry.publish(name: "tenant-a", version: 2, tags: %w[p b])
    managed = Rails::HTML5::SafeListSanitizer.managed(@registry)

    result = managed.sanitize("<p>x <b>b</b></p>", policy_name: "tenant-a")

    assert_equal "tenant-a@2", result.policy_reference
    assert_equal "<p>x <b>b</b></p>", result
  end

  def test_policy_session_pins_one_version_for_the_whole_message
    @registry.publish(name: "tenant-a", version: 1, tags: %w[p])
    managed = Rails::HTML5::SafeListSanitizer.managed(@registry)
    session = managed.with_policy("tenant-a@1")

    header = session.sanitize("<p>head <b>b</b></p>")

    @registry.publish(name: "tenant-a", version: 2, tags: %w[p b])

    body = session.sanitize("<p>body <b>b</b></p>")
    fresh = managed.sanitize("<p>fresh <b>b</b></p>", policy: "tenant-a@2")

    assert_equal "tenant-a@1", session.reference
    assert_equal "tenant-a@1", header.policy_reference
    assert_equal "tenant-a@1", body.policy_reference
    assert_equal "<p>body b</p>", body
    assert_equal "tenant-a@2", fresh.policy_reference
    assert_equal "<p>fresh <b>b</b></p>", fresh
  end

  def test_explain_reports_the_resolved_policy
    @registry.publish(name: "tenant-a", version: 1, tags: %w[p b], attributes: %w[href])
    managed = Rails::HTML5::SafeListSanitizer.managed(@registry)

    explanation = managed.explain("tenant-a@1")

    assert_equal "tenant-a", explanation[:name]
    assert_equal 1, explanation[:version]
    assert_equal "tenant-a@1", explanation[:reference]
    assert_equal %w[p b], explanation[:allowed_tags]
    assert_equal %w[href], explanation[:allowed_attributes]
  end

  def test_managed_supports_prune_policies
    @registry.publish(name: "pruner", version: 1, tags: %w[p b], prune: true)
    managed = Rails::HTML5::SafeListSanitizer.managed(@registry)

    result = managed.sanitize("<p>keep <unknown>drop</unknown></p>", policy: "pruner@1")

    assert_equal "<p>keep </p>", result
    assert_equal "pruner@1", result.policy_reference
  end

  def test_legacy_class_configuration_still_runs
    old_tags = Rails::HTML5::SafeListSanitizer.allowed_tags
    old_attributes = Rails::HTML5::SafeListSanitizer.allowed_attributes

    Rails::HTML5::SafeListSanitizer.allowed_tags = %w[p u]
    Rails::HTML5::SafeListSanitizer.allowed_attributes = %w[class]

    sanitizer = Rails::HTML5::SafeListSanitizer.new
    assert_equal '<p class="x">hi</p> <u>u</u> b',
      sanitizer.sanitize('<p class="x" id="y">hi</p> <u>u</u> <b>b</b>')
    assert_equal "<p>hi</p>", sanitizer.sanitize("<p>hi</p>", tags: %w[p])
  ensure
    Rails::HTML5::SafeListSanitizer.allowed_tags = old_tags
    Rails::HTML5::SafeListSanitizer.allowed_attributes = old_attributes
  end

  # A small "synthetic template" renderer: tokens in the template are replaced
  # with HTML fragments, then the whole body is sanitized once. Running two
  # policy versions alternately through the same template is the scenario from
  # the ticket.
  def render_template(template, values, managed, policy:)
    body = template.gsub(/\{\{(\w+)\}\}/) { values.fetch($1) }
    managed.sanitize(body, policy: policy)
  end

  def test_synthetic_templates_interleave_policy_versions
    @registry.publish(name: "tenant-mail", version: 1, tags: %w[p b i a], attributes: %w[href])
    @registry.publish(name: "tenant-mail", version: 2, tags: %w[p b i u mark a], attributes: %w[href class])
    managed = Rails::HTML5::SafeListSanitizer.managed(@registry)

    template = <<~HTML
      <p>{{greeting}} <b>{{name}}</b></p>
      <p><u>{{promo}}</u> <mark>{{badge}}</mark> <script>{{evil}}</script></p>
      <a href="https://example.com" onclick="steal()">{{link}}</a>
    HTML

    values = {
      "greeting" => "Hello",
      "name" => "Ada",
      "promo" => "20% off",
      "badge" => "new",
      "evil" => "alert(1)",
      "link" => "shop",
    }

    v1_first = render_template(template, values, managed, policy: "tenant-mail@1")
    v2_first = render_template(template, values, managed, policy: "tenant-mail@2")
    v1_again = render_template(template, values, managed, policy: "tenant-mail@1")
    v2_again = render_template(template, values, managed, policy: "tenant-mail@2")

    expected_v1 = "<p>Hello <b>Ada</b></p>\n<p>20% off new alert(1)</p>\n" \
      "<a href=\"https://example.com\">shop</a>\n"
    expected_v2 = "<p>Hello <b>Ada</b></p>\n<p><u>20% off</u> <mark>new</mark> alert(1)</p>\n" \
      "<a href=\"https://example.com\">shop</a>\n"

    assert_equal expected_v1, v1_first
    assert_equal expected_v2, v2_first
    assert_equal v1_first, v1_again
    assert_equal v2_first, v2_again
    assert_equal "tenant-mail@1", v1_first.policy_reference
    assert_equal "tenant-mail@2", v2_first.policy_reference
  end

  def test_failed_publication_leaves_previous_versions_usable
    @registry.publish(name: "tenant-mail", version: 1, tags: %w[p])
    managed = Rails::HTML5::SafeListSanitizer.managed(@registry)
    before = managed.sanitize("<p>before</p>", policy: "tenant-mail@1")

    assert_raises(Rails::HTML::Sanitizer::InvalidPolicyError) do
      @registry.publish(name: "tenant-mail", version: 1, tags: %w[p script])
    end
    assert_raises(Rails::HTML::Sanitizer::PolicyConflictError) do
      @registry.publish(name: "tenant-mail", version: 1, tags: %w[p b])
    end

    after = managed.sanitize("<p>after</p>", policy: "tenant-mail@1")
    assert_equal "<p>after</p>", after
    assert_equal before.policy_digest, after.policy_digest
    assert_equal "tenant-mail@1", after.policy_reference
    assert_equal 1, @registry.size
  end

  def test_failed_validation_does_not_publish_a_partial_version
    error = assert_raises(Rails::HTML::Sanitizer::InvalidPolicyError) do
      @registry.publish(name: "tenant-mail", version: 2, tags: %w[p script])
    end
    assert_match(/script/, error.message)

    assert_empty @registry.names
    assert_equal 0, @registry.size
  end

  def test_parallel_calls_each_keep_their_own_policy_version
    @registry.publish(name: "tenant-mail", version: 1, tags: %w[p], attributes: %w[href])
    @registry.publish(name: "tenant-mail", version: 2, tags: %w[p b], attributes: %w[href title])
    managed = Rails::HTML5::SafeListSanitizer.managed(@registry)

    results = Array.new(8) do |index|
      Thread.new do
        policy_ref = index.even? ? "tenant-mail@1" : "tenant-mail@2"
        Array.new(50) do |iteration|
          html = "<p>#{index}-#{iteration} <b>b</b></p>"
          [policy_ref, managed.sanitize(html, policy: policy_ref)]
        end
      end
    end.map(&:value).flatten(1)

    results.each do |policy_ref, result|
      assert_equal policy_ref, result.policy_reference
      if policy_ref.end_with?("@1")
        assert_match(/<p>\d+-\d+ b<\/p>/, result)
      else
        assert_match(/<p>\d+-\d+ <b>b<\/b><\/p>/, result)
      end
    end
  end

  def test_parallel_reads_are_consistent_while_versions_are_published
    @registry.publish(name: "tenant-mail", version: 0, tags: %w[p])
    managed = Rails::HTML5::SafeListSanitizer.managed(@registry)
    errors = Queue.new
    seen = Queue.new
    stop = false

    readers = Array.new(4) do
      Thread.new do
        until stop
          begin
            result = managed.sanitize("<p>x <b>b</b></p>", policy_name: "tenant-mail")
            reference = result.policy_reference
            seen << reference
            errors << "policy digest mismatch for #{reference}" unless result.policy_digest == result.policy.digest
            errors << "policy object mismatch for #{reference}" unless result.policy.reference == reference
          rescue => e
            errors << "#{e.class}: #{e.message}"
          end
        end
      end
    end

    Timeout.timeout(10) do
      20.times do |version|
        @registry.publish(name: "tenant-mail", version: version + 1, tags: %w[p b])
      end
      sleep 0.05
      stop = true
      readers.each(&:join)
    end

    known = (@registry.versions("tenant-mail").map { |v| "tenant-mail@#{v}" } +
      (0..20).map { |v| "tenant-mail@#{v}" }).uniq
    observed = []
    observed << seen.pop until seen.empty?
    unexpected = observed.uniq - known

    assert errors.empty?, "parallel readers observed inconsistent state: #{errors.size} error(s)"
    assert_empty unexpected, "parallel readers observed unknown policy versions: #{unexpected.inspect}"
    refute_empty observed, "expected parallel readers to complete at least one sanitization"
  end

  def test_in_flight_message_is_unaffected_by_a_conflicting_republish
    @registry.publish(name: "tenant-mail", version: 1, tags: %w[p])
    managed = Rails::HTML5::SafeListSanitizer.managed(@registry)
    started = Queue.new
    release = Queue.new

    worker = Thread.new do
      session = managed.with_policy("tenant-mail@1")
      first = session.sanitize("<p>a <b>b</b></p>")
      started << true
      release.pop
      [first, session.sanitize("<p>c <b>d</b></p>")]
    end

    started.pop
    assert_raises(Rails::HTML::Sanitizer::PolicyConflictError) do
      @registry.publish(name: "tenant-mail", version: 1, tags: %w[p b])
    end
    @registry.publish(name: "tenant-mail", version: 2, tags: %w[p b])
    release << true

    first, second = worker.value
    assert_equal "<p>a b</p>", first
    assert_equal "<p>c d</p>", second
    assert first.same_policy?(second)
    assert_equal "tenant-mail@1", second.policy_reference
    assert_equal "<p>c <b>d</b></p>",
      managed.sanitize("<p>c <b>d</b></p>", policy: "tenant-mail@2")
  end

  def test_concurrent_publication_of_one_version_has_a_single_winner
    policies = Array.new(8) do |index|
      Rails::HTML::Sanitizer::Policy.new(
        name: "tenant-race",
        version: 1,
        tags: index.even? ? %w[p] : %w[p b],
      )
    end

    outcomes = Queue.new
    threads = policies.map do |policy|
      Thread.new do
        begin
          outcome = @registry.publish(policy)
          outcomes << [:ok, outcome]
        rescue Rails::HTML::Sanitizer::PolicyConflictError => e
          outcomes << [:conflict, e]
        end
      end
    end
    threads.each(&:join)

    results = []
    results << outcomes.pop until outcomes.empty?
    successes = results.select { |status, _| status == :ok }

    assert_operator successes.size, :>=, 1
    assert_equal 1, successes.map { |_, policy| policy.digest }.uniq.size,
      "only one distinct definition may win"
    assert_equal 8 - successes.size, results.count { |status, _| status == :conflict }
    assert_equal successes.first.last.digest, @registry.current("tenant-race").digest
    assert_equal 1, @registry.size
  end

  def test_html4_and_html5_share_the_policy_contract
    @registry.publish(name: "tenant-mail", version: 1, tags: %w[p b], attributes: %w[href])
    html4 = Rails::HTML4::SafeListSanitizer.managed(@registry)
    html5 = Rails::HTML5::SafeListSanitizer.managed(@registry)

    r4 = html4.sanitize("<p>x <b>b</b> <u>u</u></p>", policy: "tenant-mail@1")
    r5 = html5.sanitize("<p>x <b>b</b> <u>u</u></p>", policy: "tenant-mail@1")

    assert_equal "tenant-mail@1", r4.policy_reference
    assert_equal "tenant-mail@1", r5.policy_reference
    assert_equal "<p>x <b>b</b> u</p>", r4
    assert_equal "<p>x <b>b</b> u</p>", r5
  end

  def test_instance_sanitize_switches_to_the_managed_path_only_with_a_policy
    @registry.publish(name: "tenant-a", version: 1, tags: %w[p])
    sanitizer = Rails::HTML5::SafeListSanitizer.new

    legacy = sanitizer.sanitize("<p onclick='x'>hi <u>u</u></p>")
    assert_equal "<p>hi u</p>", legacy

    managed = sanitizer.sanitize("<p onclick='x'>hi <u>u</u></p>", policy: "tenant-a@1", registry: @registry)
    assert_equal "<p>hi u</p>", managed
    assert_equal "tenant-a@1", managed.policy_reference
  end

  def test_instance_sanitize_keeps_legacy_positional_options
    @registry.publish(name: "tenant-a", version: 1, tags: %w[p])
    sanitizer = Rails::HTML5::SafeListSanitizer.new

    assert_equal "<p>hi</p> b", sanitizer.sanitize("<p>hi</p> <b>b</b>", { tags: %w[p] })
    assert_equal "tenant-a@1",
      sanitizer.sanitize("<p>hi</p>", { policy: "tenant-a@1", registry: @registry }).policy_reference
  end

  def test_publish_next_derives_the_next_version_from_current
    @registry.publish(name: "tenant-a", version: 1, tags: %w[p b], attributes: %w[href])
    v2 = @registry.publish_next("tenant-a", tags: %w[p b u])

    assert_equal 2, v2.version
    assert_equal %w[p b u], v2.allowed_tags
    assert_equal %w[href], v2.allowed_attributes, "omitted permissions are inherited"
    assert_equal "tenant-a@2", @registry.current("tenant-a").reference
    assert_equal %w[1 2], @registry.versions("tenant-a")
  end

  def test_publish_next_accepts_an_explicit_version_and_non_integer_sequences
    @registry.publish(name: "tenant-b", version: "2026.11", tags: %w[p])

    assert_raises(Rails::HTML::Sanitizer::InvalidPolicyError) do
      @registry.publish_next("tenant-b", tags: %w[p b])
    end

    v = @registry.publish_next("tenant-b", version: "2026.12", tags: %w[p b])
    assert_equal "2026.12", v.version
    assert_equal "tenant-b@2026.12", @registry.current("tenant-b").reference
  end

  def test_rollback_promotes_an_existing_version_without_changing_it
    v1 = @registry.publish(name: "tenant-a", version: 1, tags: %w[p])
    @registry.publish(name: "tenant-a", version: 2, tags: %w[p b])

    assert_equal v1, @registry.rollback("tenant-a", 1)
    assert_equal "tenant-a@1", @registry.current("tenant-a").reference
    assert_equal %w[1 2], @registry.versions("tenant-a")
    assert_raises(Rails::HTML::Sanitizer::PolicyNotFoundError) { @registry.rollback("tenant-a", 99) }
  end

  def test_with_policy_block_form_scopes_the_session
    @registry.publish(name: "tenant-a", version: 1, tags: %w[p])
    managed = Rails::HTML5::SafeListSanitizer.managed(@registry)

    result = managed.with_policy("tenant-a@1") do |session|
      session.sanitize("<p>a</p><b>b</b>") + session.sanitize("<p>c</p><b>d</b>")
    end

    assert_equal "<p>a</p>b<p>c</p>d", result
  end

  def test_session_reports_the_policy_definition
    @registry.publish(name: "tenant-a", version: 1, tags: %w[p], attributes: %w[href])
    session = Rails::HTML5::SafeListSanitizer.managed(@registry).with_policy("tenant-a@1")

    assert_equal "tenant-a@1", session.reference
    assert_equal "tenant-a", session.name
    assert_equal 1, session.version
    assert_equal %w[p], session.to_h[:allowed_tags]
  end

  def test_nil_input_stays_nil_for_managed_calls
    @registry.publish(name: "tenant-a", version: 1, tags: %w[p])
    managed = Rails::HTML5::SafeListSanitizer.managed(@registry)

    assert_nil managed.sanitize(nil, policy: "tenant-a@1")
    assert_equal "", managed.sanitize("", policy: "tenant-a@1")
  end

  def test_policy_rejects_markup_in_names
    assert_raises(Rails::HTML::Sanitizer::InvalidPolicyError) do
      Rails::HTML::Sanitizer::Policy.new(name: "p", version: 1, tags: ["p onclick=x"])
    end

    assert_raises(Rails::HTML::Sanitizer::InvalidPolicyError) do
      Rails::HTML::Sanitizer::Policy.new(name: "p", version: 1, attributes: ["href=javascript:x"])
    end
  end

  def test_global_registry_can_be_replaced_and_restored
    original = Rails::HTML::Sanitizer.policy_registry
    replacement = Rails::HTML::Sanitizer::PolicyRegistry.new
    replacement.publish(name: "tenant-global", version: 1, tags: %w[p])

    Rails::HTML::Sanitizer.policy_registry = replacement
    assert_equal "tenant-global@1",
      Rails::HTML5::SafeListSanitizer.managed.sanitize("<p>x</p>", policy: "tenant-global@1").policy_reference
  ensure
    Rails::HTML::Sanitizer.policy_registry = original
  end
end
