# Copyright 2026 WinRM contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require 'digest'
require 'rexml/document'
require 'uri'
require_relative 'log_redactor/sanitizer'
require_relative 'log_redactor/summary'

module WinRM
  # Builds diagnostic copies of protocol messages for logging.
  #
  # The input payload is never modified. Sensitive nodes are replaced with a
  # stable digest of their original value, so the same secret always maps to
  # the same marker while remaining unusable outside this process. Payloads
  # that cannot be parsed, and binary payloads, are reduced to length and
  # digest summaries; their content is never echoed.
  module LogRedactor
    SHELL_SENSITIVE = %w[command arguments stream].freeze

    SEMANTIC_SENSITIVE = %w[
      password passwd pwd secret token credential credentials authorization
      apikey privatekey keypass clientkey clientsecret accesstoken refreshtoken
      creationxml
    ].freeze

    SENSITIVE_ATTRIBUTES = %w[
      password passwd pwd secret token credential credentials authorization
      apikey privatekey keypass clientsecret accesstoken refreshtoken
    ].freeze

    SENSITIVE_WORDS = %w[
      password passwd secret token credential credentials apikey privatekey
      keypass clientsecret accesstoken refreshtoken
    ].freeze

    URL_PATTERN = %r{https?://[^\s<>"']+}i.freeze

    CREDENTIAL_ASSIGNMENT = /
      (?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?token|client[_-]?secret)
      \s*[:=]\s*[^\s&"'<>]+
    /ix.freeze

    UUID_PATTERN = /\A(?:uuid:)?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/i.freeze

    KNOWN_OPERATIONS = %w[
      CommandLine Receive ReceiveResponse Send SendResponse Signal SignalResponse
      Create CreateResponse Delete DeleteResponse Get GetResponse Enumerate
      EnumerateResponse Pull PullResponse Fault Shell Session
    ].freeze

    SAFE_PATHS = %w[
      / /wsman /wsman/
      /ws/2004/08/addressing/role/anonymous
      /wbem/wsman/1/config
    ].freeze

    SAFE_PATH_PATTERNS = [
      %r{\A/ws/2004/09/(?:transfer|enumeration)/[A-Za-z]+/?\z},
      %r{\A/wbem/wsman/1/windows/shell/[A-Za-z]+/?\z}
    ].freeze

    IDENTIFIER_ELEMENTS = %w[messageid relatesto sessionid shellid].freeze
    IDENTIFIER_ATTRIBUTES = %w[commandid messageid relates to sessionid shellid].freeze

    module_function

    # Describes a payload for logging without exposing its sensitive content.
    #
    # @return [Hash] :summary is always safe; :redacted is pretty XML or nil.
    def describe(payload, operation: 'soap')
      raw = payload.is_a?(String) ? payload.dup : payload.to_s
      document = REXML::Document.new(raw)
      raise REXML::ParseException, 'empty document' unless document.root

      sanitizer = Sanitizer.new
      sanitizer.sanitize(document)
      {
        summary: Summary.new(document, raw, operation, sanitizer.redactions).to_s,
        redacted: Summary.pretty(document)
      }
    rescue REXML::ParseException => e
      { summary: Summary.parse(raw, operation, e), redacted: nil }
    rescue StandardError => e
      { summary: "#{operation} bytes=#{raw.to_s.bytesize} sha256:#{digest(raw)} " \
                 "log_error=#{error_summary(e)}", redacted: nil }
    end

    # Stable, non-reversible marker for a sensitive value.
    def redaction_marker(label, value)
      text = value.to_s
      "[REDACTED #{label} bytes=#{text.bytesize} sha256:#{digest(text)}]"
    end

    # Length and digest for opaque content such as ciphertext or a script.
    def content_summary(label, value)
      text = value.to_s
      "#{label}_bytes=#{text.bytesize} #{label}_sha256=sha256:#{digest(text)}"
    end

    # Safe summary of a PSRP message, replacing the raw serialized payload.
    def psrp_message(message)
      type = message.respond_to?(:type) ? format('0x%08x', message.type) : 'unknown'
      "message_type=#{type} " \
        "pipeline_id=#{scalar(message.respond_to?(:pipeline_id) ? message.pipeline_id : nil)} " \
        "runspace_pool_id=#{scalar(message.respond_to?(:runspace_pool_id) ? message.runspace_pool_id : nil)} " \
        "#{content_summary('data', message.respond_to?(:data) ? message.data : nil)}"
    end

    # Correlation identifiers are only recorded when they have the protocol's
    # UUID shape. Anything else may be content, so it is reduced to a digest.
    def identifier(value)
      text = value.to_s.strip
      return nil if text.empty?
      return text if text.match?(UUID_PATTERN)

      redaction_marker('identifier', text)
    end

    # Safe description of an endpoint: userinfo, query, and fragment are removed.
    def endpoint(value)
      uri = value.is_a?(URI) ? value : URI.parse(value.to_s)
      return '[endpoint redacted]' unless uri.scheme && uri.host

      userinfo = uri.userinfo ? '[REDACTED]@' : ''
      "#{uri.scheme}://#{userinfo}#{uri.host}:#{uri.port}#{sanitize_path(uri.path)}"
    rescue URI::InvalidURIError, ArgumentError
      '[endpoint redacted]'
    end

    # Header names are useful for diagnosis; values may contain challenge data.
    def header_names(headers)
      return '[]' unless headers.respond_to?(:keys)

      headers.keys.map { |key| key.to_s.gsub(/[^\w-]/, '')[0, 64] }.sort.inspect
    end

    # Describes an exception without echoing arbitrary message text. REXML parse
    # errors still expose their line and position so failures remain locatable.
    def error_summary(error)
      return 'class=nil' if error.nil?

      if error.is_a?(REXML::ParseException)
        return parse_error_fields(error).join(' ')
      end

      fields = ["class=#{error.class.name}"]
      fields << "status=#{error.status_code}" if error.respond_to?(:status_code) && error.status_code
      fields << "fault_code=#{scalar(error.fault_code)}" if error.respond_to?(:fault_code) && error.fault_code
      message = error.message.to_s
      fields << "message_bytes=#{message.bytesize} message_sha256=sha256:#{digest(message)}"
      fields.join(' ')
    end

    def digest(value)
      Digest::SHA256.hexdigest(value.to_s.b)[0, 16] if value
    end

    def scalar(value, limit = 128)
      text = value.to_s.gsub(/[[:cntrl:]]/, ' ')
      text = "#{text[0, limit]}..." if text.length > limit
      text.inspect
    end

    # Keeps scheme, host, port, and safe paths. Userinfo, query, and fragment
    # are dropped regardless of parameter names.
    def sanitize_url(url)
      uri = URI.parse(url)
      return '[REDACTED url]' unless uri.scheme && uri.host

      path = sanitize_path(uri.path)
      return url unless uri.userinfo || uri.query || uri.fragment || path != uri.path.to_s

      userinfo = uri.userinfo ? '[REDACTED]@' : ''
      result = "#{uri.scheme}://#{userinfo}#{uri.host}"
      result += ":#{uri.port}" unless uri.port == uri.default_port
      result += path
      result += '?[REDACTED]' if uri.query
      result += '#[REDACTED]' if uri.fragment
      result
    rescue URI::InvalidURIError, ArgumentError
      '[REDACTED url]'
    end

    # Only known WS-Management endpoints and action paths are reproduced. Any
    # other path may be peer-controlled content, including a secret, and is
    # replaced by a marker.
    def sanitize_path(path)
      text = path.to_s
      return '' if text.empty?
      return text if SAFE_PATHS.include?(text)
      return text if SAFE_PATH_PATTERNS.any? { |pattern| text.match?(pattern) }

      '/[REDACTED path]'
    end

    def redact_urls(text)
      text.to_s.gsub(URL_PATTERN) do |match|
        match.include?('[REDACTED') ? match : sanitize_url(match)
      end
    end

    def sensitive_element?(element)
      local = normalize(element.name)

      # Shell payload names are redacted by local name too: a peer or proxy can
      # rewrite a namespace prefix, and losing the diagnostic is preferable to
      # echoing a script under an unexpected namespace.
      return true if SHELL_SENSITIVE.include?(local)
      return true if local == 'creationxml'
      return true if local == 'variable' && sensitive_attribute_named?(element, 'name')

      semantic_sensitive?(local)
    end

    def sensitive_attribute?(attribute)
      semantic_sensitive?(attribute.name)
    end

    def identifier_attribute?(attribute)
      IDENTIFIER_ATTRIBUTES.include?(normalize(attribute.name))
    end

    def semantic_sensitive?(value)
      normalized = normalize(value)
      return true if SENSITIVE_ATTRIBUTES.include?(normalized)

      # Match whole words after splitting on separators (`db_password`) and a
      # suffix on the compacted name (`mytoken`), without matching unrelated
      # words such as `passenger`.
      return true if value.to_s.downcase.split(/[^a-z0-9]+/).any? { |token| SENSITIVE_WORDS.include?(token) }

      SENSITIVE_WORDS.any? { |word| normalized.end_with?(word) && normalized.length > word.length }
    end

    def sensitive_attribute_named?(element, name)
      element.attributes.each_attribute.any? do |attribute|
        attribute.name.to_s.downcase == name && semantic_sensitive?(attribute.value)
      end
    end

    def collected_text(node)
      case node
      when REXML::Text
        node.value.to_s
      when REXML::Element
        node.children.map { |child| collected_text(child) }.join
      else
        ''
      end
    end

    def normalize(name)
      name.to_s.downcase.gsub(/[^a-z0-9]/, '')
    end

    def parse_error_fields(error)
      line = error.respond_to?(:line) ? error.line : nil
      position = error.respond_to?(:position) ? error.position : nil
      tail = error.message.to_s[%r{Last \d+ unconsumed characters:\s*(.*)\z}m, 1]

      fields = ["class=#{error.class.name}"]
      fields << "line=#{line}" if line
      fields << "position=#{position}" if position
      if tail && !tail.empty?
        fields << "unparsed_bytes=#{tail.bytesize}"
        fields << "unparsed_sha256=sha256:#{digest(tail)}"
      end
      fields
    end
  end
end

