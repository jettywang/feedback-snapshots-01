# frozen_string_literal: true

require "json"

module WebMock
  # Decides which parts of a real request may appear in output that can leave
  # the machine, such as CI logs. The policy only changes how requests are
  # presented. Matching always runs against the real, unredacted request, so a
  # redaction policy can neither make a stub match nor stop it matching.
  #
  # Three independent switches control the three axes a request is made of:
  #
  #   show_structures - when false, nested hashes and arrays collapse to a
  #                     single marker, hiding their shape and depth.
  #   show_field_names - when false, the names of fields and parameters are
  #                      hidden while their presence is still reported.
  #   show_values - when false, concrete values are replaced with a marker.
  #
  # Every shareable surface (the exception message, the suggested stub snippet
  # and the body diff) renders through the same policy, so a value hidden in
  # one place cannot leak through another. The full request is still available
  # internally on the RequestSignature used for matching and callbacks.
  class RedactionPolicy
    REDACTED = "[REDACTED]"

    def self.from_config(config = Config.instance)
      new(
        show_structures: config.show_redacted_structures,
        show_field_names: config.show_redacted_field_names,
        show_values: config.show_redacted_values
      )
    end

    def initialize(show_structures: true, show_field_names: true, show_values: true)
      @show_structures = show_structures
      @show_field_names = show_field_names
      @show_values = show_values
    end

    # A permissive policy leaves everything visible, in which case callers keep
    # their original, unredacted rendering so the default output is unchanged.
    def permissive?
      @show_structures && @show_field_names && @show_values
    end

    def redact(value)
      return value if permissive?

      redact_value(value)
    end

    # Query string values are redacted without losing the parameter names or
    # the order of the query string.
    def redact_uri(uri)
      return uri if permissive?
      return uri if uri.nil?

      uri_str = uri.to_s
      return uri_str if uri_str.empty?

      base, _, query = uri_str.partition("?")
      return uri_str if query.empty?

      redacted_query = query.split("&").map do |pair|
        name, separator, value = pair.partition("=")
        shown_name = @show_field_names ? name : REDACTED
        shown_value = @show_values ? value : REDACTED
        next shown_name if separator.empty?

        "#{shown_name}=#{shown_value}"
      end.join("&")

      "#{base}?#{redacted_query}"
    end

    # Redacts the diff produced by Hashdiff. Each entry is one of:
    #   ["~", path, old_value, new_value]
    #   ["+", path, value]
    #   ["-", path]
    # The leading operation and the number of entries are always kept, since
    # they carry no request data and are what lets a maintainer locate the
    # mismatch.
    def redact_body_diff(entries)
      return entries if permissive?

      Array(entries).map do |entry|
        operation, path, *values = entry
        [operation, redact_diff_path(path), *values.map { |value| redact_diff_value(value) }]
      end
    end

    # Redacts a body as presented in a snippet. A hash or array is redacted as
    # data; a JSON string is parsed, redacted and serialized again so its
    # fields and values are protected rather than hidden behind an opaque
    # string; any other body is treated as a single scalar value.
    def redact_body_pattern(body)
      return body if permissive?

      case body
      when Hash, Array
        redact(body)
      when String
        redact_string_body(body)
      else
        redact_scalar(body)
      end
    end

    private

    def redact_string_body(body)
      parsed = JSON.parse(body)
      redacted = redact(parsed)
      return redacted if redacted == REDACTED

      JSON.generate(redacted)
    rescue JSON::ParserError
      redact_scalar(body)
    end

    def redact_value(value)
      case value
      when Hash
        redact_hash(value)
      when Array
        redact_array(value)
      else
        redact_scalar(value)
      end
    end

    def redact_hash(hash)
      return REDACTED unless @show_structures

      hash.each_with_object({}) do |(key, member), result|
        shown_key = @show_field_names ? key : REDACTED
        result[shown_key] = redact_value(member)
      end
    end

    def redact_array(array)
      return REDACTED unless @show_structures

      array.map { |member| redact_value(member) }
    end

    def redact_scalar(value)
      @show_values ? value : REDACTED
    end

    # A diff value may itself be a nested hash or array, for example when a
    # whole subtree was added or removed. Redact it through the same rules as a
    # body so nested field names and values obey their own switches.
    def redact_diff_value(value)
      case value
      when Hash, Array then redact(value)
      else redact_scalar(value)
      end
    end

    def redact_diff_path(path)
      parts = Array(path)
      return REDACTED if parts.empty?

      return path if @show_field_names

      parts.map { |part| part.is_a?(Integer) ? part : REDACTED }
    end
  end
end
