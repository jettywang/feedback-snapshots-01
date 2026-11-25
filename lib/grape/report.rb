# frozen_string_literal: true

require 'cgi'

module Grape
  # One report, two answers under the same convention: a browsable inline
  # summary and, once the caller is allowed to download it, the rendered report
  # as an attachment. The attachment's filename, its body and the public
  # metadata (Content-Type and Content-Disposition) are all derived from the
  # format the request finally negotiated, so the two answers never disagree
  # about what they are serving.
  #
  # The attachment body is a Grape::ServeStream::SourceBody, so a source whose
  # contents only exist as Rack reads it is opened lazily and released once it
  # is open, whether the body is read fully, abandoned after the first chunk or
  # closed before being read.
  class Report
    # Header Rack 3.2 has no constant for yet.
    CONTENT_DISPOSITION = 'content-disposition'

    # Characters an RFC 6266 quoted-string filename cannot carry. The extended
    # +filename*+ parameter keeps the original name percent-encoded, so a
    # Unicode or punctuation-rich name is still recoverable there.
    UNSAFE_FILENAME = /[^0-9A-Za-z._-]/

    # @param base_name [String] the filename without an extension.
    # @param source [#read, #close, #call] the rendered report, or a callable
    #   that opens it when the attachment body is first read.
    # @param summary [#call] a callable taking the negotiated format and
    #   returning the inline summary body.
    # @param media_types [Hash] the API's content-type registry, format to type.
    # @param extensions [Hash] explicit filename extensions per format; the
    #   format name itself is used when none is given.
    def initialize(base_name, source:, summary:, media_types:, extensions: {})
      @base_name = base_name
      @source = source
      @summary = summary
      @media_types = media_types
      @extensions = extensions
    end

    # The approved download: the rendered report streamed as an attachment.
    #
    # @param format [Symbol] the negotiated format.
    # @param status [Integer] the response status.
    # @return [Array] a Rack response triplet.
    def attachment(format, status: 200)
      [
        status,
        public_headers(format, 'attachment'),
        Grape::ServeStream::SourceBody.new(source)
      ]
    end

    # The answer a request without a download still gets: the inline summary,
    # carrying the same negotiated type and filename metadata.
    #
    # @param format [Symbol] the negotiated format.
    # @param status [Integer] the response status.
    # @return [Array] a Rack response triplet.
    def summary_response(format, status: 200)
      [status, public_headers(format, 'inline'), [summary.call(format)]]
    end

    # Shared entry point for the two branches.
    #
    # @param format [Symbol] the negotiated format.
    # @param download [Boolean] whether the request is allowed the attachment.
    # @return [Array] a Rack response triplet.
    def answer(format, download:)
      return attachment(format) if download

      summary_response(format)
    end

    private

    attr_reader :source, :summary, :media_types, :extensions

    def public_headers(format, disposition)
      filename = filename_for(format)
      ascii_filename = filename.gsub(UNSAFE_FILENAME, '_')
      Rack::Headers.new.merge(
        Rack::CONTENT_TYPE => media_types[format],
        CONTENT_DISPOSITION => "#{disposition}; filename=\"#{ascii_filename}\"; filename*=UTF-8''#{CGI.escape(filename)}"
      )
    end

    def filename_for(format)
      extension = extensions.fetch(format, format.to_s)
      "#{@base_name}.#{extension}"
    end
  end
end
