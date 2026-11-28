# frozen_string_literal: true

require 'digest'
require 'singleton'

module WebMock
  # An immutable record of one response served by a stub. A version is
  # created whenever a registered stub is selected for a request, before any
  # bytes are delivered to the client. It names the request signature WebMock
  # replayed, the exact stub that was selected, and a digest of the response
  # that stub produced.
  #
  # +signature+ is the RequestSignature object so a verifier can re-match it
  # against a freshly built request; +request_signature+ is its stable string
  # form, and +request_signature_digest+ covers that string.
  class ReplayVersion
    attr_reader :id, :stub, :stub_id, :stub_pattern, :signature,
                :request_signature, :request_signature_digest, :source,
                :status, :headers_digest, :body_digest, :body_bytesize,
                :segment_sizes

    def initialize(id:, stub:, stub_id:, stub_pattern:, signature:,
                   request_signature:, request_signature_digest:, source:,
                   status:, headers_digest:, body_digest:, body_bytesize:,
                   segment_sizes:)
      @id = id
      @stub = stub
      @stub_id = stub_id
      @stub_pattern = stub_pattern
      @signature = signature
      @request_signature = request_signature
      @request_signature_digest = request_signature_digest
      @source = source
      @status = status.dup.freeze
      @headers_digest = headers_digest
      @body_digest = body_digest
      @body_bytesize = body_bytesize
      @segment_sizes = segment_sizes.dup.freeze
      freeze
    end

    # The response came from a Rack app (`to_rack`) or was written directly
    # in the stub (`to_return(body: ...)`).
    def rack?
      source == :rack
    end

    def to_h
      {
        id: id,
        stub_id: stub_id,
        stub_pattern: stub_pattern,
        request_signature: request_signature,
        request_signature_digest: request_signature_digest,
        source: source,
        status: status.dup,
        headers_digest: headers_digest,
        body_digest: body_digest,
        body_bytesize: body_bytesize,
        segment_sizes: segment_sizes.dup
      }
    end

    def inspect
      "#<#{self.class.name} id=#{id} stub_id=#{stub_id} source=#{source} " \
        "bytes=#{body_bytesize} digest=#{body_digest}>"
    end
  end

  # The progress of delivering one version to a client. A receipt starts
  # pending, becomes complete only after the client was handed every segment,
  # and becomes partial when the client stops early or delivery raises. A
  # partial receipt records only what actually happened: the bytes and digest
  # of the delivered prefix, never the whole response.
  class ReplayReceipt
    STATES = %i[pending complete partial].freeze

    attr_reader :version, :delivered_bytes, :delivered_segments

    def initialize(version)
      @version = version
      @delivered_bytes = 0
      @delivered_segments = []
      @digest = Digest::SHA256.new
      @state = :pending
    end

    def record(segment)
      return self if finished?

      bytes = segment.to_s.b
      @digest << bytes
      @delivered_bytes += bytes.bytesize
      @delivered_segments << bytes.bytesize
      @delivered_sha256 = nil
      self
    end

    def complete!
      @state = :complete
      self
    end

    def abort!
      @state = :partial unless complete?
      self
    end

    def state
      @state
    end

    def pending?
      @state == :pending
    end

    def complete?
      @state == :complete
    end

    def partial?
      @state == :partial
    end

    def finished?
      @state != :pending
    end

    def delivered_sha256
      @delivered_sha256 ||= @digest.hexdigest
    end

    def version_id
      version.id
    end

    def stub
      version.stub
    end

    def signature
      version.signature
    end

    def stub_id
      version.stub_id
    end

    def stub_pattern
      version.stub_pattern
    end

    def request_signature
      version.request_signature
    end

    def request_signature_digest
      version.request_signature_digest
    end

    def source
      version.source
    end

    def status
      version.status
    end

    def body_digest
      version.body_digest
    end

    def body_bytesize
      version.body_bytesize
    end

    def to_h
      {
        version_id: version_id,
        stub_id: stub_id,
        stub_pattern: stub_pattern,
        request_signature: request_signature,
        request_signature_digest: request_signature_digest,
        source: source,
        status: status.dup,
        body_digest: body_digest,
        body_bytesize: body_bytesize,
        state: state,
        complete: complete?,
        partial: partial?,
        delivered_bytes: delivered_bytes,
        delivered_segments: delivered_segments.dup,
        delivered_sha256: delivered_sha256
      }
    end

    def inspect
      "#<#{self.class.name} version=#{version_id} stub=#{stub_id} " \
        "state=#{state} bytes=#{delivered_bytes}/#{body_bytesize}>"
    end
  end

  # Holds response versions and delivery receipts for later inspection. It is
  # reset with the other WebMock registries, so evidence belongs to the
  # current test. Stub patterns are copied into versions, so a receipt still
  # names the stub after that stub was removed.
  class ReplayRegistry
    include Singleton

    def initialize
      @lock = Mutex.new
      @versions = []
      @receipts = []
      @next_version_id = 0
    end

    def reset!
      @lock.synchronize do
        @versions = []
        @receipts = []
        @next_version_id = 0
      end
    end

    def versions
      @lock.synchronize { @versions.dup }
    end

    def receipts
      @lock.synchronize { @receipts.dup }
    end

    def receipts_for_version(version_id)
      @lock.synchronize { @receipts.select { |receipt| receipt.version_id == version_id } }
    end

    def version(version_id)
      @lock.synchronize { @versions.detect { |version| version.id == version_id } }
    end

    def last_receipt
      @lock.synchronize { @receipts.last }
    end

    # Receipts for versions served by +stub+, or by the stub with that id.
    def receipts_for_stub(stub)
      stub_id = stub.respond_to?(:stub_id) ? stub.stub_id : stub.to_s
      @lock.synchronize { @receipts.select { |receipt| receipt.stub_id == stub_id } }
    end

    def versions_for_stub(stub)
      stub_id = stub.respond_to?(:stub_id) ? stub.stub_id : stub.to_s
      @lock.synchronize { @versions.select { |version| version.stub_id == stub_id } }
    end

    # Versions selected by a stub whose bytes were never handed to the client
    # (for example, the request failed before delivery started).
    def pending_receipts
      @lock.synchronize { @receipts.select(&:pending?) }
    end

    # Creates a version and its pending receipt for an evaluated response.
    # The response keeps references to both so adapters can report delivery.
    def record_version(response, request_signature:, stub:)
      segments = response.delivery_segments

      version = nil
      receipt = nil
      @lock.synchronize do
        @next_version_id += 1
        version = ReplayVersion.new(
          id: @next_version_id,
          stub: stub,
          stub_id: stub.stub_id,
          stub_pattern: stub.to_s,
          signature: request_signature,
          request_signature: request_signature.to_s,
          request_signature_digest: Digest::SHA256.hexdigest(request_signature.to_s),
          source: response.replay_source || :direct,
          status: response.status,
          headers_digest: digest_headers(response.headers),
          body_digest: digest_segments(segments),
          body_bytesize: segments.sum { |segment| segment.to_s.bytesize },
          segment_sizes: segments.map { |segment| segment.to_s.bytesize }
        )
        receipt = ReplayReceipt.new(version)
        @versions << version
        @receipts << receipt
      end

      response.replay_version = version
      response.replay_receipt = receipt
      version
    end

    private

    def digest_segments(segments)
      digest = Digest::SHA256.new
      segments.each { |segment| digest << segment.to_s.b }
      digest.hexdigest
    end

    def digest_headers(headers)
      return nil if headers.nil? || headers.respond_to?(:call)

      pairs = headers.to_a.map do |name, values|
        [name.to_s, Array(values).map(&:to_s)]
      end.sort_by(&:first)
      Digest::SHA256.hexdigest(pairs.inspect)
    end
  end
end
