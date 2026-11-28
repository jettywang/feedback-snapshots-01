# frozen_string_literal: true

require 'thread'

module WebMock
  # Collects verifiable request evidence when explicitly enabled. Disabled by
  # default, so enabling it never changes how requests are stubbed or counted.
  #
  # Adapters call #start_request when they begin handling a request and report
  # the terminal outcome through #record, which freezes an immutable
  # RequestEvidence entry. Helpers expose the evidence by outcome and verify
  # that a stored signature still matches a given RequestSignature.
  class RequestEvidenceRegistry
    include Singleton

    def initialize
      @enabled = false
      @records = []
      @sequence = 0
      @context_id = 0
      @lock = Mutex.new
    end

    def enable!
      @lock.synchronize { @enabled = true }
    end

    def disable!
      @lock.synchronize { @enabled = false }
    end

    def enabled?
      @lock.synchronize { @enabled }
    end

    def reset!
      @lock.synchronize do
        @records = []
        @sequence = 0
        @context_id = 0
      end
    end

    # Adapter hook: opens a mutable tracking context for the request so a
    # callback interruption can still be recorded as incomplete.
    def start_request(request_signature, lib)
      return nil unless enabled?

      TrackingContext.new(request_signature, lib, next_context_id)
    end

    # Adapter hook: persists the terminal outcome of a tracked request. No-op
    # when evidence collection is disabled or no context was started.
    def record(context, outcome, real_request_sent, diagnostics = nil)
      return nil if context.nil?
      return nil unless enabled?

      evidence = nil
      @lock.synchronize do
        @sequence += 1
        evidence = build_evidence(context, outcome, real_request_sent, diagnostics)
        @records << evidence
      end
      evidence
    end

    # Replaces the provisional record for a context with a new outcome, used
    # when an adapter callback interrupts a request that had already been
    # logged as a normal stub/real hit.
    def replace(context, outcome, real_request_sent, diagnostics = nil)
      return nil if context.nil?
      return nil unless enabled?

      evidence = nil
      @lock.synchronize do
        @records.reject! { |entry| entry.context_id == context.id }
        @sequence += 1
        evidence = build_evidence(context, outcome, real_request_sent, diagnostics)
        @records << evidence
      end
      evidence
    end

    def build_evidence(context, outcome, real_request_sent, diagnostics)
      RequestEvidence.new(
        request_signature: context.request_signature,
        outcome: outcome,
        lib: context.lib,
        real_request_sent: real_request_sent,
        diagnostics: diagnostics || context.diagnostics,
        sequence: @sequence,
        context_id: context.id
      )
    end
    private :build_evidence

    def next_context_id
      @lock.synchronize { @context_id += 1 }
    end

    def evidence
      @lock.synchronize { @records.dup }
    end
    alias to_a evidence

    def any?
      !evidence.empty?
    end

    def empty?
      evidence.empty?
    end

    def size
      evidence.size
    end
    alias count size

    def for_outcome(outcome)
      evidence.select { |entry| entry.outcome == outcome.to_sym }
    end

    def for_lib(lib)
      evidence.select { |entry| entry.lib == lib.to_sym }
    end

    # Cross-checks stored evidence against a request signature rather than
    # trusting stored content alone. Returns only the matching records.
    def matching(request_signature)
      evidence.select { |entry| entry.matches_signature?(request_signature) }
    end

    def signature_for(request_signature)
      RequestEvidence.signature_for(request_signature)
    end

    # Mutable per-request handle owned by an adapter while a request runs.
    class TrackingContext
      attr_reader :request_signature, :lib, :diagnostics, :id

      def initialize(request_signature, lib, id)
        @request_signature = request_signature
        @lib = lib.to_sym
        @diagnostics = []
        @id = id
      end

      def annotate(note)
        @diagnostics << note
        self
      end
    end
  end
end
