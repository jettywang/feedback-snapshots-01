# frozen-string-literal: true

require 'openssl'
require 'securerandom'
require 'uri'
require 'rack/utils'

class Roda
  module RodaPlugins
    # The route_csrf plugin is the recommended plugin to use to support
    # CSRF protection in Roda applications. This plugin allows you set
    # where in the routing tree to enforce CSRF protection.  Additionally,
    # the route_csrf plugin uses modern security practices.
    #
    # By default, the plugin requires tokens be specific to the request
    # method and request path, so a CSRF token generated for one form will
    # not be usable to submit a different form.
    #
    # This plugin also takes care to not expose the underlying CSRF key
    # (except in the session), so that it is not possible for an attacker
    # to generate valid CSRF tokens specific to an arbitrary request method
    # and request path even if they have access to a token that is not
    # specific to request method and request path.  To get this security
    # benefit, you must ensure an attacker does not have access to the
    # session.  Rack::Session::Cookie versions shipped with Rack before
    # Rack 3 use signed sessions, not encrypted
    # sessions, so if the attacker has the ability to read cookie data
    # and you are using one of those Rack::Session::Cookie versions,
    # it will still be possible
    # for an attacker to generate valid CSRF tokens specific to arbitrary
    # request method and request path.  Roda's session plugin uses
    # encrypted sessions and therefore is safe even if the attacker can
    # read cookie data.
    #
    # == Usage
    #
    # It is recommended to use the plugin defaults, loading the
    # plugin with no options:
    #
    #   plugin :route_csrf
    #
    # This plugin supports the following options:
    #
    # :field :: Form input parameter name for CSRF token (default: '_csrf')
    # :formaction_field :: Form input parameter name for path-specific CSRF tokens (used by the
    #                      +csrf_formaction_tag+ method).  If present, this parameter should be
    #                      submitted as a hash, keyed by path, with CSRF token values.
    # :header :: HTTP header name for CSRF token (default: 'X-CSRF-Token')
    # :key :: Session key for CSRF secret (default: '_roda_csrf_secret')
    # :require_request_specific_tokens :: Whether request-specific tokens are required (default: true).
    #                                     A false value will allow tokens that are not request-specific
    #                                     to also work.  You should only set this to false if it is
    #                                     impossible to use request-specific tokens.  If you must
    #                                     use non-request-specific tokens in certain cases, it is best
    #                                     to leave this option true by default, and override it on a
    #                                     per call basis in those specific cases.
    # :csrf_failure :: The action to taken if a request fails the CSRF check (default: :raise).  Options:
    #                  :raise :: raise a Roda::RodaPlugins::RouteCsrf::InvalidToken exception
    #                  :empty_403 :: return a blank 403 page (rack_csrf's default behavior)
    #                  :clear_session :: Clear the current session  (deprecated)
    #                  Proc :: Treated as a routing block, called with request object
    # :check_header :: Whether the HTTP header should be checked for the token value (default: false).
    #                  If true, checks the HTTP header after checking for the form input parameter.
    #                  If :only, only checks the HTTP header and doesn't check the form input parameter.
    # :check_request_methods :: Which request methods require CSRF protection
    #                           (default: <tt>['POST', 'DELETE', 'PATCH', 'PUT']</tt>)
    # :exempt_request_methods :: If given, specifies which request methods do not require CSRF protection.
    #                            It is recommended to set this so an allow list approach is used, as
    #                            :check_request_methods is the equivalent of a deny list
    #                            (recommended: <tt>['GET', 'HEAD', 'OPTIONS', 'QUERY']</tt>, which
    #                            will be the default in Roda 4)
    # :upgrade_from_rack_csrf_key :: If provided, the session key that should be checked for the
    #                                rack_csrf raw token.  If the session key is present, the value
    #                                will be checked against the submitted token, and if it matches,
    #                                the CSRF check will be passed.  Should only be set temporarily
    #                                if upgrading from using rack_csrf to the route_csrf plugin, and
    #                                should be removed as soon as you are OK with CSRF forms generated
    #                                before the upgrade not longer being usable. The default rack_csrf
    #                                key is <tt>'csrf.token'</tt>.
    #
    # The plugin also supports a block, in which case the block will be used
    # as the value of the :csrf_failure option.
    #
    # == Methods
    #
    # This adds the following instance methods:
    #
    # check_csrf!(opts={}) :: Used for checking if the submitted CSRF token is valid.
    #                         If a block is provided, it is treated as a routing block if the
    #                         CSRF token is not valid.  Otherwise, by default, raises a
    #                         Roda::RodaPlugins::RouteCsrf::InvalidToken exception if a CSRF
    #                         token is necessary for the request and there is no token provided
    #                         or the provided token is not valid. Options can be provided to
    #                         override any of the plugin options for this specific call.
    #                         The :token option can be used to specify the provided CSRF token
    #                         (instead of looking for the token in the submitted parameters).
    #                         The :action option can be used to check the token against a
    #                         specific stable action identifier.  If the routing branch
    #                         declared an action with +csrf_action+, that action is used by
    #                         default, and the :action option must match it.
    # csrf_action(action=nil) :: If an argument is given, declare the stable action identifier for
    #                            the current routing branch and return true.  With no argument,
    #                            return the action identifier declared for the current request,
    #                            or nil if no action was declared.  This is available both as an
    #                            instance method and as a request method, so it can be called
    #                            bare or on +r+.
    # csrf_action_tag(action, method='POST') :: An HTML hidden input tag string containing a CSRF
    #                                           token bound to the given stable action identifier.
    # csrf_action_token(action, method='POST') :: The value of a CSRF token bound to the given
    #                                             stable action identifier.
    # csrf_formaction_tag(path, method='POST') :: An HTML hidden input tag string containing the CSRF token, suitable
    #                                             for placing in an HTML form that has inputs that use formaction
    #                                             attributes to change the endpoint to which the form is submitted.
    #                                             Takes the same arguments as csrf_token.
    # csrf_field :: The field name to use for the hidden tag containing the CSRF token.
    # csrf_path(action) :: This takes an argument that would be the value of the HTML form's
    #                      action attribute, and returns a path you can pass to csrf_token
    #                      that should be valid for the form submission.  The argument should
    #                      either be nil or a string representing a relative path, absolute
    #                      path, or full URL (using appropriate URL encoding).
    # csrf_tag(path=nil, method='POST', action: nil) :: An HTML hidden input tag string containing the CSRF token, suitable
    #                                                   for placing in an HTML form.  Takes the same arguments as csrf_token.
    # csrf_token(path=nil, method='POST', action: nil) :: The value of the csrf token, in case it needs to be accessed
    #                                                    directly.  It is recommended to call this method with a
    #                                                    path, which will create a request-specific token.  Calling
    #                                                    this method without an argument will create a token that is
    #                                                    not specific to the request, but such a token will only
    #                                                    work if you set the :require_request_specific_tokens option
    #                                                    to false, which is a bad idea from a security standpoint.
    #                                                    If the :action keyword is given, the token is bound to that
    #                                                    stable action identifier instead of a request path.  If the
    #                                                    current routing branch declared an action with +csrf_action+,
    #                                                    calling this method without a path uses that action.
    # use_request_specific_csrf_tokens? :: Whether the plugin is configured to only support
    #                                      request-specific tokens, true by default.
    # valid_csrf?(opts={}) :: Returns whether the submitted CSRF token is valid (also true if
    #                         the request does not require a CSRF token).  Takes same option hash
    #                         as check_csrf!.
    # valid_csrf_action?(action, opts={}) :: Returns whether the submitted CSRF token is valid for
    #                                        the given stable action identifier.
    #
    # == Stable Action Identifiers
    #
    # By default, CSRF tokens are specific to the request method and path.  If the same
    # business action is reachable by multiple paths (for example, a form in the main
    # application and a mounted sub-application), a trusted route can declare a stable
    # action identifier and bind the token to that identifier instead:
    #
    #   r.get "admin/profile" do
    #     r.csrf_action :update_profile
    #     csrf_tag
    #   end
    #
    #   r.post "admin/profile" do
    #     r.csrf_action :update_profile
    #     check_csrf!
    #   end
    #
    # A token generated for :update_profile is accepted by every trusted route that
    # declares the same action and uses the same request method, regardless of the
    # route's actual path, how the application is mounted, or any internal path
    # rewriting.  Routes that declare a different action do not accept the token.
    #
    # Only declare an action inside the block of a route that actually handles
    # the request.  Declarations are scoped to the current request and are
    # discarded when matching moves on to a branch that does not handle the
    # request, so a branch that is passed over cannot leave an action behind.
    #
    # Forms that do not declare an action continue to use the existing path-specific
    # token behavior.  Action-specific and path-specific tokens are deliberately not
    # interchangeable, so a missing action identifier never falls back to a token for
    # another action or to the legacy path-specific check.
    #
    # This plugin also adds the following instance methods for compatibility with the
    # older csrf plugin, but it is not recommended to use these methods in new code:
    #
    # csrf_header :: The header name to use for submitting the CSRF token via an HTTP header
    #                (useful for javascript). Note that this plugin will not look in
    #                the HTTP header by default, it will only do so if the :check_header
    #                option is used.
    # csrf_metatag :: An HTML meta tag string containing the CSRF token, suitable
    #                 for placing in the page header.  It is not recommended to use
    #                 this method, as the token generated is not request-specific and
    #                 will not work unless you set the :require_request_specific_tokens option to
    #                 false, which is a bad idea from a security standpoint.
    #
    # == Token Cryptography
    #
    # route_csrf uses HMAC-SHA-256 to generate all CSRF tokens.  It generates a random 32-byte secret,
    # which is stored base64 encoded in the session.  For each CSRF token, it generates 31 bytes
    # of random data.
    #
    # For request-specific CSRF tokens, this pseudocode generates the HMAC:
    #
    #   hmac = HMAC(secret, method + path + random_data)
    #
    # For CSRF tokens specific to a stable action identifier, this pseudocode
    # generates the HMAC:
    #
    #   hmac = HMAC(secret, method + "\\0csrf_action\\0" + action + random_data)
    #
    # For CSRF tokens not specific to a request, this pseudocode generates the HMAC:
    #
    #   hmac = HMAC(secret, random_data)
    #
    # This pseudocode generates the final CSRF token in both cases:
    #
    #   token = Base64Encode(random_data + hmac)
    #
    # Using this construction for generating CSRF tokens means that generating any
    # valid CSRF token without knowledge of the secret is equivalent to a successful generic attack
    # on HMAC-SHA-256.
    #
    # By using an HMAC for tokens not specific to a request, it is not possible to use a
    # valid CSRF token that is not specific to a request to generate a valid request-specific
    # CSRF token.  
    #
    # By including random data in the HMAC for all tokens, different tokens are generated
    # each time, mitigating compression ratio attacks such as BREACH.
    #
    # == REQUEST_METHOD modifications
    #
    # It's possible to use Rack middleware that modify REQUEST_METHOD in the env hash,
    # such that it does not reflect that actual request method. One example of this is
    # Rack::MethodOverride. Using such middleware is generally bad from a security perspective,
    # but if you want to do so anyway, you need to override the request method that the
    # route_csrf plugin will use so it reflects the actual request method. If you are using
    # Rack::MethodOverride, you can use:
    #
    #   def csrf_request_method
    #     env['rack.methodoverride.original_method'] || super
    #   end
    module RouteCsrf
      # Default CSRF option values
      DEFAULTS = {
        :field => '_csrf'.freeze,
        :formaction_field => '_csrfs'.freeze,
        :header => 'X-CSRF-Token'.freeze,
        :key => '_roda_csrf_secret'.freeze,
        :require_request_specific_tokens => true,
        :csrf_failure => :raise,
        :check_header => false,
        # RODA4: Remove and set :exempt_request_methods by default
        :check_request_methods => %w'POST DELETE PATCH PUT'.freeze.each(&:freeze)
      }.freeze

      # Exception class raised when :csrf_failure option is :raise and
      # a valid CSRF token was not provided.
      class InvalidToken < RodaError; end

      # Prefix used to domain separate action-specific token HMACs from
      # path-specific and non-request-specific token HMACs.
      ACTION_HMAC_PREFIX = "\0csrf_action\0".freeze

      # Validate and normalize a stable action identifier.  Symbols and strings
      # are accepted; any other type, an empty identifier, or an identifier
      # containing a null byte is rejected.
      def self.action_identifier(action)
        unless action.is_a?(String) || action.is_a?(Symbol)
          raise RodaError, "CSRF action identifiers must be strings or symbols, not #{action.class}"
        end

        action = action.to_s
        if action.empty? || action.include?("\0")
          raise RodaError, "CSRF action identifiers must be non-empty and must not contain null bytes"
        end

        action
      end

      def self.load_dependencies(app, opts=OPTS, &_)
        app.plugin :_base64
      end

      def self.configure(app, opts=OPTS, &block)
        options = app.opts[:route_csrf] = (app.route_csrf_opts || DEFAULTS).merge(opts)
        if block || opts[:csrf_failure].is_a?(Proc)
          if block && opts[:csrf_failure]
            raise RodaError, "Cannot specify both route_csrf plugin block and :csrf_failure option"
          end
          block ||= opts[:csrf_failure]
          options[:csrf_failure] = :csrf_failure_method
          app.define_roda_method(:_roda_route_csrf_failure, 1, &app.send(:convert_route_block, block))
        end
        if opts[:csrf_failure] == :clear_session
          RodaPlugins.warn "Passing :clear_session as the :csrf_failure option to the route_csrf plugin is deprecated"
        end
        options[:env_header] = "HTTP_#{options[:header].to_s.tr('-', '_').upcase}".freeze
        options.freeze
      end

      module ClassMethods
        RodaPlugins.opt_attr_reader(self, :route_csrf, name: :route_csrf_opts)
      end

      module RequestMethods
        # With an argument, declare the stable action identifier for the current
        # routing branch.  Without an argument, return the action identifier
        # declared for the current request, or nil if none was declared.
        def csrf_action(action=nil)
          return @_csrf_action if action.nil?

          @_csrf_action = RouteCsrf.action_identifier(action)
          true
        end

        private

        # Restore any action declared while matching if the match does not
        # consume the request.  A successful match always throws :halt, so this
        # only runs when matching fails or is skipped via r.pass, ensuring a
        # branch that does not handle the request can never leak its action
        # identifier to a later branch.
        def if_match(args)
          action = @_csrf_action
          super
        ensure
          @_csrf_action = action
        end
      end

      module InstanceMethods
        # With an argument, declare the stable action identifier for the current
        # routing branch.  Without an argument, return the action identifier
        # declared for the current request, or nil if none was declared.  This is
        # a convenience method that delegates to the request method of the same
        # name, so it can be called either bare or on the request object.
        def csrf_action(action=nil)
          @_request.csrf_action(action)
        end

        # Check that the submitted CSRF token is valid, if the request requires a CSRF token.
        # If the CSRF token is valid or the request does not require a CSRF token, return nil.
        # Otherwise, if a block is given, treat it as a routing block and yield to it, and
        # if a block is not given, use the :csrf_failure option to determine how to handle it.
        def check_csrf!(opts=OPTS, &block)
          if msg = csrf_invalid_message(opts)
            if block
              @_request.on(&block)
            end
            
            case failure_action = opts.fetch(:csrf_failure, csrf_options[:csrf_failure])
            when :raise
              raise InvalidToken, msg
            when :empty_403
              @_response.status = 403
              headers = @_response.headers
              headers.clear
              headers[RodaResponseHeaders::CONTENT_TYPE] = 'text/html'
              headers[RodaResponseHeaders::CONTENT_LENGTH] ='0'
              throw :halt, @_response.finish_with_body([])
            when :clear_session
              RodaPlugins.warn "Passing :clear_session as the :csrf_failure option to check_csrf! is deprecated"
              session.clear
            when :csrf_failure_method
              @_request.on{_roda_route_csrf_failure(@_request)}
            when Proc
              RodaPlugins.warn "Passing a Proc as the :csrf_failure option value to check_csrf! is deprecated"
              @_request.on{instance_exec(@_request, &failure_action)} # Deprecated
            else
              raise RodaError, "Unsupported :csrf_failure option: #{failure_action.inspect}"
            end
          end
        end

        # The name of the hidden input tag containing the CSRF token.  Also used as the name
        # for the meta tag.
        def csrf_field
          csrf_options[:field]
        end

        # The HTTP header name to use when submitting CSRF tokens in an HTTP header, if
        # such support is enabled (it is not by default).
        def csrf_header
          csrf_options[:header]
        end

        # An HTML meta tag string containing a CSRF token that is not request-specific.
        # It is not recommended to use this, as it doesn't support request-specific tokens.
        def csrf_metatag
          "<meta name=\"#{csrf_field}\" content=\"#{csrf_unbound_token}\" \/>"
        end

        # Given a form action, return the appropriate path to use for the CSRF token.
        # This makes it easier to generate request-specific tokens without having to
        # worry about the different types of form actions (relative paths, absolute
        # paths, URLs, empty paths).
        def csrf_path(action)
          case action
          when nil, '', /\A[#?]/
            # use current path
            request.path
          when /\A(?:https?:\/)?\//
            # Either full URI or absolute path, extract just the path
            URI.parse(action).path
          else
            # relative path, join to current path
            URI.join(request.url, action).path
          end
        end

        # An HTML hidden input tag string containing the CSRF token, used for inputs
        # with formaction, so the same form can be used to submit to multiple endpoints
        # depending on which button was clicked.  See csrf_token for arguments, but the
        # path argument is required.
        def csrf_formaction_tag(path, *args)
          "<input type=\"hidden\" name=\"#{csrf_options[:formaction_field]}[#{Rack::Utils.escape_html(path)}]\" value=\"#{csrf_token(path, *args)}\" \/>"
        end

        # An action-specific HTML hidden input tag string containing a CSRF token
        # bound to the given stable action identifier.  See csrf_action_token for
        # arguments.
        def csrf_action_tag(action, method='POST')
          "<input type=\"hidden\" name=\"#{csrf_field}\" value=\"#{csrf_action_token(action, method)}\" \/>"
        end

        # An HTML hidden input tag string containing the CSRF token.  See csrf_token for
        # arguments.
        def csrf_tag(path=nil, method=('POST' if path), action: nil)
          "<input type=\"hidden\" name=\"#{csrf_field}\" value=\"#{csrf_token(path, method, :action=>action)}\" \/>"
        end

        # The value of a CSRF token bound to the given stable action identifier.
        # The token works for any trusted route that declares the same action and
        # accepts the same request method, no matter the route's path.  By default,
        # the POST request method is assumed.
        def csrf_action_token(action, method='POST')
          token = SecureRandom.random_bytes(31)
          token << csrf_action_hmac(token, method, action)
          [token].pack("m0")
        end

        # The value of a CSRF token that is not specific to a request or to an
        # action.  Used by csrf_metatag.
        def csrf_unbound_token
          token = SecureRandom.random_bytes(31)
          token << csrf_hmac(token, '', '')
          [token].pack("m0")
        end

        # The value of the csrf token.  For a path specific token, provide a path
        # argument.  By default, it a path is provided, the POST request method will
        # be assumed.  To generate a token for a non-POST request method, pass the
        # method as the second argument.  If the :action keyword is given, an
        # action-specific token is generated instead, using the given stable action
        # identifier (and the path is ignored).  If the current routing branch
        # declared an action with csrf_action, calling this method with no path and
        # no :action keyword generates a token for that declared action.
        def csrf_token(path=nil, method=('POST' if path), action: nil)
          action = @_request.csrf_action if action.nil? && path.nil?
          return csrf_action_token(action, method || 'POST') unless action.nil?

          token = SecureRandom.random_bytes(31)
          token << csrf_hmac(token, method, path)
          [token].pack("m0")
        end

        # Whether request-specific CSRF tokens should be used by default.
        def use_request_specific_csrf_tokens?
          csrf_options[:require_request_specific_tokens]
        end

        # Whether the submitted CSRF token is valid for the request.  True if the
        # request does not require a CSRF token.
        def valid_csrf?(opts=OPTS)
          csrf_invalid_message(opts).nil?
        end

        # Whether the submitted CSRF token is valid for the given stable action
        # identifier.  True if the request does not require a CSRF token.
        def valid_csrf_action?(action, opts=OPTS)
          csrf_invalid_message(opts, action).nil?
        end

        private

        # The request method to use to determine whether to perform a CSRF check.
        # defaults to REQUEST_METHOD in the environment, can be overridden if
        # that isn't the actual request method.
        def csrf_request_method
          @_request.env['REQUEST_METHOD']
        end

        # Returns error message string if the CSRF token is not valid.
        # Returns nil if the CSRF token is valid.  If +action+ is given, the
        # token must be valid for that stable action identifier.  Otherwise, if
        # the :action option is given, or the current routing branch declared an
        # action with csrf_action, the token must be valid for that action.  If
        # no action is available, the legacy request method and path check is
        # used.  An action-specific check never falls back to a path-specific
        # check or to a different action.
        def csrf_invalid_message(opts=OPTS, action=nil)
          opts = opts.empty? ? csrf_options : csrf_options.merge(opts)

          declared_action = @_request.csrf_action
          requested_action = action || opts[:action]

          method = csrf_request_method

          if exempt = opts[:exempt_request_methods]
            return if exempt.include?(method)
          elsif !opts[:check_request_methods].include?(method)
            return
          end

          if declared_action
            declared_action = RouteCsrf.action_identifier(declared_action)

            if requested_action && RouteCsrf.action_identifier(requested_action) != declared_action
              raise RodaError, "CSRF action #{requested_action.inspect} conflicts with action #{declared_action.inspect} declared by the route"
            end

            action = declared_action
          elsif requested_action
            action = RouteCsrf.action_identifier(requested_action)
          end

          path = @_request.path

          unless encoded_token = opts[:token]
            encoded_token = case opts[:check_header]
            when :only
              env[opts[:env_header]]
            when true
              return (csrf_invalid_message(opts.merge(:check_header=>false), action) && csrf_invalid_message(opts.merge(:check_header=>:only), action))
            else
              params = @_request.params
              ((formactions = params[opts[:formaction_field]]).is_a?(Hash) && (formactions[path])) || params[opts[:field]]
            end
          end

          unless encoded_token.is_a?(String)
            return "encoded token is not a string"
          end

          if action.nil? && (rack_csrf_key = opts[:upgrade_from_rack_csrf_key]) && (rack_csrf_value = session[rack_csrf_key]) && csrf_compare(rack_csrf_value, encoded_token)
            # RODA4: Remove :upgrade_from_rack_csrf_key support
            return
          end

          # 31 byte random initialization vector
          # 32 byte HMAC
          # 63 bytes total
          # 84 bytes when base64 encoded
          unless encoded_token.bytesize == 84
            return "encoded token length is not 84"
          end

          begin
            submitted_hmac = Base64_.decode64(encoded_token)
          rescue ArgumentError
            return "encoded token is not valid base64"
          end

          random_data = submitted_hmac.slice!(0...31)

          if action
            if csrf_compare(csrf_action_hmac(random_data, method, action), submitted_hmac)
              return
            end

            return "decoded token is not valid for request method and action"
          end

          if csrf_compare(csrf_hmac(random_data, method, path), submitted_hmac)
            return
          end

          if opts[:require_request_specific_tokens]
            "decoded token is not valid for request method and path"
          else
            unless csrf_compare(csrf_hmac(random_data, '', ''), submitted_hmac)
              "decoded token is not valid for either request method and path or for blank method and path"
            end
          end
        end

        # Helper for getting the plugin options.
        def csrf_options
          self.class.route_csrf_opts
        end

        # Perform a constant-time comparison of the two strings, returning true if they match and false otherwise.
        def csrf_compare(s1, s2)
          Rack::Utils.secure_compare(s1, s2)
        end

        # Return the HMAC-SHA-256 for the secret and the given arguments.
        def csrf_hmac(random_data, method, path)
          OpenSSL::HMAC.digest(OpenSSL::Digest::SHA256.new, csrf_secret, "#{method.to_s.upcase}#{path}#{random_data}")
        end

        # Return the HMAC-SHA-256 for the secret, request method, and stable action
        # identifier.  The null byte prefix domain separates action-specific tokens
        # from path-specific and non-request-specific tokens, so a token for one
        # kind can never validate as another kind, even if an action identifier
        # happens to equal a path.
        def csrf_action_hmac(random_data, method, action)
          action = RouteCsrf.action_identifier(action)
          OpenSSL::HMAC.digest(OpenSSL::Digest::SHA256.new, csrf_secret, "#{method.to_s.upcase}#{ACTION_HMAC_PREFIX}#{action}#{random_data}")
        end

        # If a secret has not already been specified, generate a random 32-byte
        # secret, stored base64 encoded in the session (to handle cases where
        # JSON is used for session serialization).
        def csrf_secret
          key = session[csrf_options[:key]] ||= SecureRandom.base64(32)
          Base64_.decode64(key)
        end
      end
    end

    register_plugin(:route_csrf, RouteCsrf)
  end
end
