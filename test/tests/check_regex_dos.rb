require_relative '../test'
require 'brakeman/tracker/controller'

class CheckRegexDoSTests < Minitest::Test
  FIXTURE = <<-'CODE'
    class RegexFixtureController
      # Escaped so the pattern cannot be injected, but no bound on matching
      # cost against a long matched input.
      def escaped_but_unbounded
        /#{Regexp.escape(params[:q])}/
      end

      # The actual match is wrapped in a call-level timeout.
      def call_level_timeout
        Timeout.timeout(2) do
          /#{params[:q]}/
        end
      end

      # The length check guards a different value than the one interpolated.
      def invalid_length_check
        return if params[:q].length > 100
        /#{params[:other]}/
      end

      # An ordinary constant regex has no interpolation and is never reported.
      def constant_regex
        /foo[abc]+/
      end

      # Plain unescaped, unbounded dynamic regex.
      def plain_dynamic
        /#{params[:q]}/
      end

      # Escaped and length bounded: both risk dimensions are covered.
      def escaped_and_bounded
        return if params[:q].length > 100
        /#{Regexp.escape(params[:q])}/
      end

      # A process-wide timeout is not proof for an individual call site.
      def global_timeout_only
        Regexp.timeout = 5
        /#{params[:q]}/
      end

      # The escape is invalidated because the variable is reassigned to raw
      # input before it reaches the regex.
      def escape_then_reassign
        q = Regexp.escape(params[:q])
        q = params[:raw]
        /#{q}/
      end

      # A valid length check on the exact value reaching the regex.
      def valid_length_check
        return if params[:q].length > 100
        /#{params[:q]}/
      end

      # The timeout wraps an unrelated call, not the regex match.
      def unrelated_timeout
        Timeout.timeout(2) { something_else }
        /#{params[:q]}/
      end
    end
  CODE

  def setup
    Brakeman.set_default_logger({})
    @tracker = Brakeman::Tracker.new(
      Brakeman::AppTree.new("/tmp/FAKE_BRAKEMAN_#{rand(10_000)}"),
      nil,
      {}
    )

    file = "app/controllers/regex_fixture_controller.rb"
    ast = RubyParser.new.parse(FIXTURE, file)
    processed = Brakeman::AliasProcessor.new(@tracker).process_safely(ast)

    @controller = Brakeman::Controller.new(
      :RegexFixtureController,
      nil,
      file,
      processed,
      @tracker
    )
    @tracker.controllers[:RegexFixtureController] = @controller

    processed.body.each do |defn|
      next unless defn.is_a?(Sexp) && defn.node_type == :defn

      @controller.add_method :public, defn.method_name, defn, file
    end

    @tracker.index_call_sites

    @check = Brakeman::CheckRegexDoS.new(@tracker)
    @check.run_check
  end

  def warning_for method_name
    @check.warnings.find { |w| w.method == method_name }
  end

  def reported_methods
    @check.warnings.map(&:method).sort
  end

  def test_only_unbounded_dynamic_regexes_are_reported
    assert_equal %i[
      escaped_but_unbounded
      escape_then_reassign
      global_timeout_only
      invalid_length_check
      plain_dynamic
      unrelated_timeout
    ].sort, reported_methods
  end

  def test_constant_regex_is_not_reported
    assert_nil warning_for(:constant_regex)
  end

  def test_escaped_regex_still_warns_about_cost
    warning = warning_for(:escaped_but_unbounded)

    refute_nil warning
    assert_match(/cannot be injected/, warning.message.to_s)
    assert_match(/escaping does not limit matching cost/, warning.message.to_s)
    assert_match(/Matching cost is not bounded/, warning.message.to_s)
  end

  def test_call_level_timeout_suppresses_cost_warning
    assert_nil warning_for(:call_level_timeout)
  end

  def test_invalid_length_check_is_not_accepted
    warning = warning_for(:invalid_length_check)

    refute_nil warning
    assert_match(/can be injected/, warning.message.to_s)
    assert_match(/Matching cost is not bounded/, warning.message.to_s)
  end

  def test_escaped_and_bounded_is_fully_suppressed
    assert_nil warning_for(:escaped_and_bounded)
  end

  def test_global_timeout_is_not_treated_as_local_proof
    warning = warning_for(:global_timeout_only)

    refute_nil warning
    assert_match(/Matching cost is not bounded/, warning.message.to_s)
  end

  def test_escape_is_invalidated_by_reassignment
    warning = warning_for(:escape_then_reassign)

    refute_nil warning
    assert_match(/can be injected/, warning.message.to_s)
  end

  def test_valid_length_check_bounds_cost_and_suppresses_the_warning
    assert_nil warning_for(:valid_length_check)
  end

  def test_unrelated_timeout_does_not_wrap_the_regex
    warning = warning_for(:unrelated_timeout)

    refute_nil warning
    assert_match(/Matching cost is not bounded/, warning.message.to_s)
  end

  def test_warning_code_and_type_are_preserved
    @check.warnings.each do |warning|
      assert_equal 76, warning.warning_code
      assert_equal "Denial of Service", warning.warning_type
      assert_equal [20, 185], warning.cwe_id
    end
  end
end
