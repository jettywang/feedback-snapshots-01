# frozen-string-literal: true

#
class Roda
  module RodaPlugins
    # The json_parse_budget plugin allows selecting a bounded JSON parsing
    # policy on a per-route basis.  It is intended for JSON management
    # endpoints that accept request bodies from clients, where an unbounded
    # body or an unboundedly nested JSON document could otherwise consume
    # excessive memory or stack.
    #
    # == Usage
    #
    # Load the plugin with a default budget:
    #
    #   plugin :json_parse_budget, max_bytes: 16*1024, max_depth: 32
    #
    # Opt individual routes into the policy by calling +parse_json_budget!+
    # (or its alias +check_json_parse_budget!+):
    #
    #   route do |r|
    #     r.post 'admin/config' do
    #       r.parse_json_budget!
    #       # r.params now contains the parsed JSON document
    #     end
    #
    #     r.post 'admin/other' do
    #       # Not opted in, uses the application's normal request parsing.
    #     end
    #   end
    #
    # Since +parse_json_budget!+ is also available as an instance method in the
    # route block scope, +parse_json_budget!+ can be called without a receiver,
    # similar to +check_host_authorization!+ in the host_authorization plugin.
    #
    # == Behavior
    #
    # When +parse_json_budget!+ is called, the request body is read with a
    # length limit of +max_bytes+ plus one byte.  The extra byte is used to
    # detect that the body exceeds the budget without reading the rest of the
    # stream.  Successive reads never request more than the remaining budget,
    # so a large or unbounded stream is not read past the budget.  When a
    # request is rejected, the input stream is closed so the connection can
    # release any resources associated with the unread portion of the body,
    # and <tt>env["rack.input"]</tt> is replaced with an empty stream so the
    # raw request text cannot be read again by later code.  Successful
    # requests consume the body but leave the normal Rack lifecycle in place.
    #
    # If the body exceeds +max_bytes+, the request is rejected with reason
    # <tt>:too_large</tt>.  If the parsed document is nested more deeply than
    # +max_depth+, the request is rejected with reason <tt>:too_deep</tt>.  If
    # the body is not syntactically valid JSON, the request is rejected with
    # reason <tt>:invalid_json</tt>.  If the configured parser parses the body
    # but raises while converting it (for example, a custom parser that
    # builds application objects), the request is rejected with reason
    # <tt>:conversion_error</tt>.
    #
    # Rejected requests receive a JSON body containing the public diagnostic
    # and do not run the rest of the route block.  By default, budget
    # violations use status 413 (Payload Too Large) and malformed documents
    # use status 400 (Bad Request); the +:status+ option applies one status to
    # all rejections.  The diagnostic contains only limits and counts:
    #
    #   {"reason":"too_large","limit":16384,"max_depth":32,"bytes":16385}
    #
    # It never contains the request body, parser diagnostics, exception
    # messages, backtraces, or request headers.  On rejection, the parsed
    # values are removed from <tt>env["roda.json_params"]</tt>, and
    # <tt>env["rack.input"]</tt> is replaced with an empty input, so the raw
    # request text is not available to later code, audit callbacks, or error
    # handlers.  The diagnostic is also available as
    # +r.json_parse_budget_diagnostic+ after a rejection.
    #
    # A successful call returns the parsed value and stores it in
    # <tt>env["roda.json_params"]</tt>, so later +r.POST+ and +r.params+ calls
    # use it instead of re-reading the body.  Repeating the call on the same
    # request returns the cached value and re-checks nothing.
    #
    # == Options
    #
    # :max_bytes :: Maximum number of body bytes accepted (default: 65536).
    # :max_depth :: Maximum JSON nesting depth accepted (default: 64).
    # :status :: Rejection status code, between 400 and 599.  By default,
    #            budget violations (+:too_large+, +:too_deep+) use 413
    #            (Payload Too Large), and malformed documents
    #            (+:invalid_json+, +:conversion_error+) use 400 (Bad Request).
    #            Setting this option applies the given status to all
    #            rejections.
    # :content_type :: Content type for the rejection body
    #                  (default: <tt>application/json</tt>).
    # :on_reject :: A callable invoked as <tt>call(request, diagnostic)</tt>
    #               when a request is rejected.  A callable accepting a single
    #               argument is called with the diagnostic only.  It is the
    #               supported place to record an audit event.  The callable is
    #               not given the request body, and exceptions it raises do not
    #               change the rejection response.
    # :audit :: Alias for +on_reject+.
    #
    # All options can be overridden for an individual call:
    #
    #   r.parse_json_budget!(max_bytes: 4096, max_depth: 8)
    #
    # The parser used is the application's configured json_parser parser.  If
    # the parser accepts a <tt>max_nesting</tt> keyword, it is passed.  If it
    # does not, the parsed document is still checked against +max_depth+ after
    # parsing, so the budget is enforced either way.
    #
    # This plugin loads the json_parser plugin as a dependency, and follows
    # that plugin's +:wrap+, +:parser+, and +:include_request+ settings.  If a
    # value has already been parsed by the json_parser plugin, it is reused
    # instead of re-reading the body, but the depth budget is still enforced.
    # Non-JSON content types are left to the application's normal request
    # parsing, so routes that do not receive JSON behave as before.
    module JsonParseBudget
      DEFAULT_MAX_BYTES = 65536
      DEFAULT_MAX_DEPTH = 64
      DEFAULT_CONTENT_TYPE = 'application/json'.freeze

      REASON_TOO_LARGE = :too_large
      REASON_TOO_DEEP = :too_deep
      REASON_INVALID_JSON = :invalid_json
      REASON_CONVERSION_ERROR = :conversion_error

      # Default status for budget violations and for malformed documents.
      PAYLOAD_STATUS = 413
      MALFORMED_STATUS = 400

      ENV_PARSED = 'roda.json_parse_budget_parsed'.freeze
      ENV_DIAGNOSTIC = 'roda.json_parse_budget_diagnostic'.freeze

      # simplecov:disable
      MATCH_METHOD = RUBY_VERSION >= '2.4' ? :match? : :match
      # simplecov:enable
      private_constant :MATCH_METHOD

      # Empty rack input used to replace a consumed request body, so the raw
      # request text is not left available to later code.
      class EmptyInput
        def read(*)
          String.new
        end

        def gets(*)
          nil
        end

        def each
        end

        def close
        end

        def closed?
          true
        end

        def rewind
          nil
        end
      end

      def self.load_dependencies(app, opts=OPTS)
        app.plugin :json_parser, content_type_regexp: /\Aapplication\/(?:vnd\.api\+)?json\b/i
      end

      # Handle keyword arguments for the json_parse_budget plugin.
      def self.configure(app, opts=(no_positional_opts = true; OPTS),
          max_bytes: opts[:max_bytes],
          max_depth: opts[:max_depth],
          status: opts[:status],
          content_type: opts[:content_type],
          on_reject: opts[:on_reject],
          audit: opts[:audit],
          **kw)
        RodaPlugins.check_keywords("the json_parse_budget plugin", no_positional_opts, opts, kw)

        check_positive_integer("max_bytes", max_bytes) unless max_bytes.nil?
        check_positive_integer("max_depth", max_depth) unless max_depth.nil?
        check_status(status) unless status.nil?

        app.opts[:json_parse_budget_max_bytes] = max_bytes || app.json_parse_budget_max_bytes || DEFAULT_MAX_BYTES
        app.opts[:json_parse_budget_max_depth] = max_depth || app.json_parse_budget_max_depth || DEFAULT_MAX_DEPTH
        app.opts[:json_parse_budget_status] = status || app.json_parse_budget_status
        app.opts[:json_parse_budget_content_type] = content_type || app.json_parse_budget_content_type || DEFAULT_CONTENT_TYPE

        app.opts[:json_parse_budget_on_reject] = on_reject || audit if on_reject || audit
      end

      def self.check_positive_integer(name, value)
        unless value.is_a?(Integer) && value > 0
          raise RodaError, "json_parse_budget #{name} must be a positive Integer, got: #{value.inspect}"
        end
      end

      def self.check_status(status)
        unless status.is_a?(Integer) && status >= 400 && status <= 599
          raise RodaError, "json_parse_budget status must be an Integer between 400 and 599, got: #{status.inspect}"
        end
      end

      # Raise unless the json_parser plugin is loaded.  Since this plugin
      # loads it as a dependency, this only fails if another plugin or the
      # application removed the behavior.
      def self.ensure_json_parser!(app)
        return if app.plugins.include?(RodaPlugins::JsonParser)

        raise RodaError, "the json_parse_budget plugin requires the json_parser plugin"
      end

      def self.json_content_type?(regexp, content_type)
        regexp.send(MATCH_METHOD, content_type)
      end

      # Whether the parser accepts the max_nesting keyword, based on its
      # parameter list.  Defaults to true for parsers that do not expose
      # their parameters (for example, C methods that accept arbitrary
      # keywords).
      def self.parser_accepts_max_nesting?(parser)
        params = parser.respond_to?(:parameters) ? parser.parameters : nil
        return true unless params

        params.any? do |type, name|
          type == :keyrest || (type == :key && name == :max_nesting)
        end
      end

      module ClassMethods
        RodaPlugins.opt_attr_reader(self, :json_parse_budget_max_bytes)
        RodaPlugins.opt_attr_reader(self, :json_parse_budget_max_depth)
        RodaPlugins.opt_attr_reader(self, :json_parse_budget_status)
        RodaPlugins.opt_attr_reader(self, :json_parse_budget_content_type)
        RodaPlugins.opt_attr_reader(self, :json_parse_budget_on_reject)
      end

      module InstanceMethods
        # Parse the request body as JSON using the configured budget.  See
        # JsonParseBudget for details.
        def parse_json_budget!(*args, **kw)
          @_request.parse_json_budget!(*args, **kw)
        end

        # The public diagnostic hash from the most recent rejection, or nil.
        def json_parse_budget_diagnostic
          @_request.json_parse_budget_diagnostic
        end

        # Alias for parse_json_budget!, matching Roda's check_*! naming.
        alias check_json_parse_budget! parse_json_budget!
      end

      module RequestMethods
        # Parse the request body as JSON using the configured budget.  On
        # success, returns the parsed value and makes it available via
        # +r.POST+ and +r.params+.  On failure, halts with a rejection
        # response and a public diagnostic.
        def parse_json_budget!(opts=(no_positional_opts = true; OPTS),
            max_bytes: opts[:max_bytes],
            max_depth: opts[:max_depth],
            status: opts[:status],
            content_type: opts[:content_type],
            on_reject: opts[:on_reject],
            **kw)
          RodaPlugins.check_keywords("json_parse_budget!", no_positional_opts, opts, kw)

          klass = roda_class
          max_bytes ||= klass.json_parse_budget_max_bytes
          max_depth ||= klass.json_parse_budget_max_depth
          status ||= klass.json_parse_budget_status
          response_content_type = content_type || klass.json_parse_budget_content_type
          on_reject ||= klass.json_parse_budget_on_reject

          JsonParseBudget.ensure_json_parser!(klass)
          JsonParseBudget.check_positive_integer("max_bytes", max_bytes)
          JsonParseBudget.check_positive_integer("max_depth", max_depth)
          JsonParseBudget.check_status(status) if status

          env = @env

          if (cached = env[JsonParseBudget::ENV_PARSED])
            return cached
          end

          # Requests that are not JSON are parsed by the application's normal
          # request handling, matching the json_parser plugin's behavior.
          unless JsonParseBudget.json_content_type?(klass.json_parser_content_type_regexp, self.content_type)
            return self.POST
          end

          if (content_length = env["CONTENT_LENGTH"]) && content_length.to_i > max_bytes
            return reject_json_parse_budget(REASON_TOO_LARGE, max_bytes, max_depth, status, response_content_type, on_reject, content_length.to_i)
          end

          # Reuse a value already parsed by the json_parser plugin, but still
          # enforce the depth budget.  The byte budget cannot be checked
          # retroactively if no Content-Length was provided.
          if (existing = env["roda.json_params"])
            if json_parse_budget_too_deep?(existing, max_depth)
              return reject_json_parse_budget(REASON_TOO_DEEP, max_bytes, max_depth, status, response_content_type, on_reject)
            end
            env[JsonParseBudget::ENV_PARSED] = existing
            return existing
          end

          input = env["rack.input"]
          begin
            body = read_json_parse_budget_body(input, max_bytes)
          rescue StandardError
            return reject_json_parse_budget(REASON_CONVERSION_ERROR, max_bytes, max_depth, status, response_content_type, on_reject)
          end

          if body.bytesize > max_bytes
            return reject_json_parse_budget(REASON_TOO_LARGE, max_bytes, max_depth, status, response_content_type, on_reject, body.bytesize)
          end

          # Match the json_parser plugin: an empty body means no JSON params.
          # Cache an empty hash so later r.POST/r.params calls do not re-read
          # the body.
          if body.empty?
            env["roda.json_params"] = {}
            env[JsonParseBudget::ENV_PARSED] = {}
            return {}
          end

          begin
            value = parse_json_parse_budget_body(body, max_depth)
          rescue JSON::NestingError
            return reject_json_parse_budget(REASON_TOO_DEEP, max_bytes, max_depth, status, response_content_type, on_reject)
          rescue JSON::ParserError
            return reject_json_parse_budget(REASON_INVALID_JSON, max_bytes, max_depth, status, response_content_type, on_reject)
          rescue StandardError
            return reject_json_parse_budget(REASON_CONVERSION_ERROR, max_bytes, max_depth, status, response_content_type, on_reject)
          end

          if json_parse_budget_too_deep?(value, max_depth)
            return reject_json_parse_budget(REASON_TOO_DEEP, max_bytes, max_depth, status, response_content_type, on_reject)
          end

          value = wrap_json_parse_budget_value(value)
          env["roda.json_params"] = value
          env[JsonParseBudget::ENV_PARSED] = value

          value
        end

        # The public diagnostic hash from the most recent rejection, or nil.
        def json_parse_budget_diagnostic
          @env[JsonParseBudget::ENV_DIAGNOSTIC]
        end

        # Alias for parse_json_budget!, matching Roda's check_*! naming.
        alias check_json_parse_budget! parse_json_budget!

        private

        # Read at most max_bytes + 1 bytes.  The extra byte is enough to
        # determine the body is over budget, without reading the rest of a
        # potentially unbounded stream.
        def read_json_parse_budget_body(input, max_bytes)
          return String.new unless input && input.respond_to?(:read)

          body = String.new
          limit = max_bytes + 1

          while body.bytesize < limit
            chunk = input.read(limit - body.bytesize)
            break if chunk.nil? || chunk.empty?
            body << chunk
          end

          body
        end

        # Parse the body using the json_parser configured parser.  Pass the
        # max_nesting keyword if the parser accepts it.
        def parse_json_parse_budget_body(body, max_depth)
          parser = roda_class.json_parser_parser
          include_request = roda_class.json_parser_include_request?
          accepts_nesting = JsonParseBudget.parser_accepts_max_nesting?(parser)

          case
          when include_request && accepts_nesting
            parser.call(body, self, max_nesting: max_depth)
          when include_request
            parser.call(body, self)
          when accepts_nesting
            parser.call(body, max_nesting: max_depth)
          else
            parser.call(body)
          end
        end

        # Wrap non-hash values the same way the json_parser plugin does when
        # the :wrap option is configured.
        def wrap_json_parse_budget_value(value)
          wrap = roda_class.json_parser_wrap
          if wrap == :always || (wrap == :unless_hash && !value.is_a?(Hash))
            value = {"_json"=>value}
          end
          value
        end

        # Iteratively check the nesting depth of a parsed value.  Uses an
        # explicit stack, so it cannot overflow the Ruby stack on deeply
        # nested input.
        def json_parse_budget_too_deep?(value, max_depth)
          return false unless value.is_a?(Array) || value.is_a?(Hash)

          stack = [[value, 1]]
          until stack.empty?
            current, depth = stack.pop
            return true if depth > max_depth

            case current
            when Array
              current.each do |entry|
                stack << [entry, depth + 1] if entry.is_a?(Array) || entry.is_a?(Hash)
              end
            when Hash
              current.each_value do |entry|
                stack << [entry, depth + 1] if entry.is_a?(Array) || entry.is_a?(Hash)
              end
            end
          end

          false
        end

        # Close the input.  When +scrub+ is true (the rejection path), also
        # replace it with an empty input, so the raw request text is not left
        # available to later code (including audit callbacks and error
        # handlers).
        def close_json_parse_budget_input(input, scrub=true)
          input.close if input && input.respond_to?(:close)
        rescue StandardError
          nil
        ensure
          @env["rack.input"] = EmptyInput.new if scrub
        end

        # Build a public diagnostic and halt with a rejection response.  The
        # diagnostic intentionally contains only limits and counts.
        def reject_json_parse_budget(reason, max_bytes, max_depth, status, response_content_type, on_reject, bytes=nil)
          diagnostic = {reason: reason, limit: max_bytes, max_depth: max_depth}
          diagnostic[:bytes] = bytes if bytes
          diagnostic.freeze

          status ||= case reason
          when REASON_TOO_LARGE, REASON_TOO_DEEP
            PAYLOAD_STATUS
          else
            MALFORMED_STATUS
          end

          @env[JsonParseBudget::ENV_DIAGNOSTIC] = diagnostic
          @env.delete("roda.json_params")

          # Ensure the raw request text is not available to the audit callback
          # or to any later error/exception handling.
          close_json_parse_budget_input(@env["rack.input"])

          if on_reject
            begin
              if on_reject.respond_to?(:arity) && on_reject.arity == 1
                on_reject.call(diagnostic)
              else
                on_reject.call(self, diagnostic)
              end
            rescue StandardError => e
              if errors = @env["rack.errors"]
                errors.puts "json_parse_budget on_reject raised #{e.class}"
              end
            end
          end

          response.status = status
          response[RodaResponseHeaders::CONTENT_TYPE] = response_content_type
          response.write(roda_class.json_serializer.call(diagnostic))
          halt response.finish
        end
      end
    end

    register_plugin(:json_parse_budget, JsonParseBudget)
  end
end
