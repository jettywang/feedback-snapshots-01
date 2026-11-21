# frozen_string_literal: true

require_relative "test_helper"

class BudgetTest < Minitest::Test
  def setup
    @sanitizer = Rails::HTML::SafeListSanitizer.new
  end

  # Two valid documents generated in memory: one flat, one with
  # multi-level formatting (deeply nested markup).
  def flat_document
    "<p>Hello <b>world</b>, this is a plain import.</p>"
  end

  def nested_document(depth = 50)
    tags = %w(div section blockquote p span em strong)
    opening = depth.times.map { |i| "<#{tags[i % tags.size]}>" }.join
    closing = (depth - 1).downto(0).map { |i| "</#{tags[i % tags.size]}>" }.join
    "#{opening}deep content#{closing}"
  end

  def test_document_within_budget_sanitizes_normally
    result = @sanitizer.sanitize(flat_document, budget: { max_input_bytes: 1024, max_depth: 10, max_nodes: 100, max_output_bytes: 1024 })
    assert_equal "<p>Hello <b>world</b>, this is a plain import.</p>", result
  end

  def test_input_size_budget_reports_parse_phase
    error = assert_raises(Rails::HTML::Sanitizer::BudgetExceededError) do
      @sanitizer.sanitize(flat_document, budget: { max_input_bytes: 10 })
    end
    assert_equal :parse, error.phase
    assert_equal :max_input_bytes, error.limit
    assert_equal 10, error.threshold
    assert_operator error.actual, :>, error.threshold
  end

  def test_deeply_nested_document_aborts_during_scrub_phase
    error = assert_raises(Rails::HTML::Sanitizer::BudgetExceededError) do
      @sanitizer.sanitize(nested_document, budget: { max_depth: 10 })
    end
    assert_equal :scrub, error.phase
    assert_equal :max_depth, error.limit
    assert_equal 10, error.threshold
    assert_operator error.actual, :>, error.threshold
  end

  def test_node_count_budget_reports_scrub_phase
    error = assert_raises(Rails::HTML::Sanitizer::BudgetExceededError) do
      @sanitizer.sanitize(nested_document, budget: { max_nodes: 20 })
    end
    assert_equal :scrub, error.phase
    assert_equal :max_nodes, error.limit
    assert_equal 20, error.threshold
  end

  def test_output_budget_reports_serialize_phase_and_publishes_no_partial_result
    # A script payload expands into nothing; padding makes the output exceed
    # the threshold only after scrubbing, so the check lands in serialize.
    document = "<p>#{"padding " * 100}</p><script>alert(1)</script>"
    error = assert_raises(Rails::HTML::Sanitizer::BudgetExceededError) do
      @sanitizer.sanitize(document, budget: { max_output_bytes: 100 })
    end
    assert_equal :serialize, error.phase
    assert_equal :max_output_bytes, error.limit
    assert_equal 100, error.threshold
    # The oversized output is raised away, never returned to the caller.
  end

  def test_sanitizer_remains_usable_after_abort
    assert_raises(Rails::HTML::Sanitizer::BudgetExceededError) do
      @sanitizer.sanitize(nested_document, budget: { max_depth: 10 })
    end

    # Subsequent tasks on the same instance are unaffected.
    assert_equal "<p>still working</p>", @sanitizer.sanitize("<p>still working</p>")
    assert_equal "<p>still working</p>", @sanitizer.sanitize("<p>still working</p>", budget: { max_depth: 10 })
  end

  def test_parallel_batch_isolates_aborted_documents
    documents = [flat_document, nested_document, flat_document.dup, "<p>fourth</p>"]
    budget = { max_depth: 10, max_input_bytes: 4096, max_output_bytes: 4096 }

    results = documents.map do |doc|
      Thread.new do
        begin
          @sanitizer.sanitize(doc, budget: budget)
        rescue Rails::HTML::Sanitizer::BudgetExceededError => e
          e
        end
      end
    end.map(&:value)

    assert_equal flat_document, results[0]
    assert_kind_of Rails::HTML::Sanitizer::BudgetExceededError, results[1]
    assert_equal :scrub, results[1].phase
    assert_equal flat_document, results[2]
    assert_equal "<p>fourth</p>", results[3]
  end

  def test_budget_is_optional_and_per_call
    assert_equal flat_document, @sanitizer.sanitize(flat_document)
    assert_includes @sanitizer.sanitize(nested_document(5)), "deep content"
  end
end
