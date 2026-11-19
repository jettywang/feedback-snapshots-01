# frozen_string_literal: true

require "test_helper"
require "action_policy/test_helper"

# Acceptance tests for a batch "retain" interface.
#
# The goal is to prove, using Action Policy's testing tools, that:
#   * every document that could be changed is authorized for the matching action first;
#   * an explicit denial is honored and only the expected scope is processed;
#   * skipped objects, cache hits and really executed rules are told apart per object,
#     not inferred from aggregate counts.
#
# Everything below is plain Ruby data + recordable doubles (no Rails, no DB).
class BatchRetainTest < Minitest::Test
  include ActionPolicy::TestHelper

  # Authorization context actor. It exposes `#policy_cache_key` so it can be
  # embedded into a long-lived policy cache key (plain objects are not cacheable).
  class Operator
    attr_reader :name

    def initialize(name)
      @name = name
    end

    def policy_cache_key() = "operator/#{name}"

    def inspect() = "#<Operator #{name}>"
  end

  # Pure-Ruby record under retention. `#policy_cache_key` makes it cacheable and
  # `#policy_class` makes the policy lookup deterministic.
  class Document
    attr_reader :id, :sensitivity, :retained_by
    attr_accessor :retained

    def initialize(id, sensitivity: :low)
      @id = id
      @sensitivity = sensitivity
      @retained = false
      @retained_by = nil
    end

    def retain!(actor)
      @retained = true
      @retained_by = actor
    end

    def retained?() = @retained

    def restricted?() = sensitivity == :restricted

    def policy_class() = DocumentPolicy

    def policy_cache_key() = "document/#{id}"

    def inspect() = "#<Document id=#{id} sensitivity=#{sensitivity}>"
  end

  # Counts how many times the rule body is really evaluated, keyed by record id,
  # so a cache hit (body skipped) can be attributed to a concrete document.
  class DocumentPolicy < ActionPolicy::Base
    self.identifier = :document

    class << self
      attr_accessor :rule_executions

      def reset_executions
        @rule_executions = Hash.new(0)
      end

      def executions_for(document)
        rule_executions.fetch(document.id, 0)
      end
    end

    reset_executions

    # Long-lived cache for the batch rule; backed by the recording store below.
    cache :retain?

    def retain?
      self.class.rule_executions[record.id] += 1
      # Restricted documents are never retainable by this context.
      !record.restricted?
    end
  end

  # Cache store double that logs every read/write with the cache key, so a hit
  # can be attributed back to a concrete document via its stable cache key.
  class RecordingCacheStore
    attr_reader :reads, :writes, :hits

    def initialize
      @reads = []
      @writes = []
      @hits = []
      @store = {}
    end

    def read(key)
      reads << key
      value = @store[key]
      hits << key unless value.nil?
      value
    end

    def write(key, value, _options = nil)
      writes << key
      @store[key] = value
    end

    def hit_for?(document)
      hits.any? { |key| key.include?(document.policy_cache_key) }
    end

    def read_for?(document)
      reads.any? { |key| key.include?(document.policy_cache_key) }
    end
  end

  # Modification double: instead of touching a database it records every
  # attempted retain and flips the document's in-memory flag.
  class RetentionRecorder
    attr_reader :applied

    def initialize
      @applied = []
    end

    def call(document)
      document.retain!(:batch_service)
      applied << document
    end

    def applied?(document)
      applied.include?(document)
    end
  end

  # The batch interface under test. Each entry is authorized before it is
  # touched. A denial skips that single document but does not abort the batch,
  # so the processed scope is observable through the returned report.
  class BatchRetainService
    include ActionPolicy::Behaviour

    attr_reader :user, :events

    authorize :user

    def initialize(user:)
      @user = user
      @events = []
    end

    def call(documents, recorder)
      documents.each_with_object(Report.new) do |document, report|
        events << [:authorize, document]
        authorize! document, to: :retain?
        events << [:retain, document]
        recorder.call(document)
        report.processed << document
      rescue ActionPolicy::Unauthorized
        events << [:skip, document]
        report.skipped << document
      end
    end

    # Structured outcome of a batch run, kept separate from aggregate counters.
    class Report
      attr_reader :processed, :skipped

      def initialize
        @processed = []
        @skipped = []
      end
    end
  end

  attr_reader :actor, :recorder, :documents

  def setup
    DocumentPolicy.reset_executions
    ActionPolicy.cache_store = RecordingCacheStore.new

    @actor = Operator.new("operator")
    @recorder = RetentionRecorder.new
    @documents = [
      Document.new("doc-1"),
      Document.new("doc-2"),
      Document.new("doc-3")
    ]
  end

  def teardown
    ActionPolicy.cache_store = nil
  end

  def test_all_documents_authorized_then_retained_when_allowed
    service = BatchRetainService.new(user: actor)
    report = nil

    assert_authorized_to(:retain?, documents.first, with: DocumentPolicy) do
      report = service.call(documents, recorder)
    end

    # Per-object authorization: each document is checked with its own policy,
    # not just one call for the whole collection.
    documents.each do |document|
      assert tracked?(document),
        "expected #{document.inspect} to be authorized with DocumentPolicy#retain?"
      assert events_for(service, document) == [:authorize, :retain],
        "expected #{document.inspect} to be authorized before it was retained"
    end
    assert_equal documents.size, tracker_calls.size

    # Every allowed document is actually retained, in input order.
    assert_equal documents, report.processed
    assert_empty report.skipped
    documents.each do |document|
      assert document.retained?, "expected #{document.inspect} to be retained"
      assert recorder.applied?(document)
      assert_equal 1, DocumentPolicy.executions_for(document)
      refute cache_store.hit_for?(document)
    end
  end

  def test_explicit_denial_skips_only_the_rejected_document
    denied = Document.new("doc-secret", sensitivity: :restricted)
    allowed = documents
    list = [denied] + allowed

    service = BatchRetainService.new(user: actor)
    report = nil
    assert_authorized_to(:retain?, denied, with: DocumentPolicy) do
      report = service.call(list, recorder)
    end

    # The denied document was still presented to the policy ...
    assert tracked?(denied)
    # ... evaluated (and cached as a denial) but skipped rather than modified.
    assert_equal 1, DocumentPolicy.executions_for(denied)
    assert cache_store.read_for?(denied)
    refute cache_store.hit_for?(denied)
    assert_equal [:authorize, :skip], events_for(service, denied)
    assert_includes report.skipped, denied
    refute denied.retained?
    refute recorder.applied?(denied)

    # The denial did not abort the batch: every other document was processed.
    assert_equal allowed, report.processed
    allowed.each do |document|
      assert tracked?(document)
      assert_equal [:authorize, :retain], events_for(service, document)
      assert document.retained?
      assert recorder.applied?(document)
      refute_includes report.skipped, document
    end

    # Exact processed scope, expressed per object rather than a bare count.
    assert_equal(%w[doc-secret], report.skipped.map(&:id))
    assert_equal(%w[doc-1 doc-2 doc-3], report.processed.map(&:id))
  end

  def test_duplicate_object_is_reauthorized_but_served_from_cache
    shared = Document.new("doc-dup")
    service = BatchRetainService.new(user: actor)
    report = nil

    assert_authorized_to(:retain?, shared, with: DocumentPolicy) do
      report = service.call([shared, shared], recorder)
    end

    # Both occurrences go through authorization (two tracked calls) ...
    assert_equal 2, tracker_calls.size
    assert tracker_calls.all? { |call| call.matches?(DocumentPolicy, :retain?, shared, nil) }

    # ... yet the rule body runs only once: the second occurrence is a cache hit.
    assert_equal 1, DocumentPolicy.executions_for(shared)
    assert_equal 2, cache_store.reads.size
    assert cache_store.hit_for?(shared)
    assert_equal 1, cache_store.writes.size

    # Both occurrences are processed, but the modification double sees the
    # single underlying object twice (no dedup at the batch layer).
    assert_equal [shared, shared], report.processed
    assert_empty report.skipped
    assert shared.retained?
    assert_equal 2, recorder.applied.size
  end

  def test_skipped_cached_and_executed_objects_are_distinguished
    restricted = Document.new("doc-locked", sensitivity: :restricted)
    shared = Document.new("doc-shared")
    single = Document.new("doc-once")
    list = [restricted, shared, shared, single]

    service = BatchRetainService.new(user: actor)
    report = ActionPolicy::Testing::AuthorizeTracker.tracking do
      service.call(list, recorder)
    end

    # 1) Skipped: authorized and evaluated, but denied and never modified.
    assert_includes report.skipped, restricted
    assert tracked?(restricted)
    assert_equal [:authorize, :skip], events_for(service, restricted)
    assert_equal 1, DocumentPolicy.executions_for(restricted)
    refute cache_store.hit_for?(restricted)
    refute restricted.retained?
    refute recorder.applied?(restricted)

    # 2) Cache hit: the duplicated object is authorized twice but executed once.
    assert_equal 2, tracker_calls.count { |call| call.policy.record == shared }
    assert cache_store.hit_for?(shared)
    assert_equal 1, DocumentPolicy.executions_for(shared)
    assert shared.retained?

    # 3) Really executed: a unique object authorizes, misses the cache, runs the
    #    rule once and is retained.
    assert tracked?(single)
    assert cache_store.read_for?(single)
    refute cache_store.hit_for?(single)
    assert_equal 1, DocumentPolicy.executions_for(single)
    assert single.retained?
    assert_includes report.processed, single

    # Global cross-checks stay consistent with the per-object story.
    assert_equal [restricted], report.skipped
    assert_equal [shared, shared, single], report.processed
    assert_equal 3, DocumentPolicy.rule_executions.values.sum
    assert_equal 4, tracker_calls.size
  end

  private

  def cache_store() = ActionPolicy.cache_store

  def tracker_calls
    ActionPolicy::Testing::AuthorizeTracker.calls
  end

  def tracked?(document, rule = :retain?)
    tracker_calls.any? { |call| call.matches?(DocumentPolicy, rule, document, nil) }
  end

  def events_for(service, document)
    service.events.select { |_name, record| record == document }.map(&:first)
  end
end
