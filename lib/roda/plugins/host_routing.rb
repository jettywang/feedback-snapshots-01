# frozen-string-literal: true

#
class Roda
  module RodaPlugins
    # The host_routing plugin adds support for more routing requests based on
    # the requested host.  It also adds predicate methods for checking
    # whether a request was requested with the given host.
    #
    # When loading the plugin, you pass a block, which is used for configuring
    # the plugin.  For example, if you want to treat requests to api.example.com
    # or api2.example.com as api requests, and treat other requests as www
    # requests, you could use:
    #
    #   plugin :host_routing do |hosts|
    #     hosts.to :api, "api.example.com", "api2.example.com"
    #     hosts.default :www
    #   end
    #
    # With this configuration, in your routing tree, you can call the +r.api+ and
    # +r.www+ methods for dispatching to routing blocks only for those types of
    # requests:
    #
    #   route do |r|
    #     r.api do
    #       # requests to api.example.com or api2.example.com
    #     end
    #
    #     r.www do
    #       # requests to other domains
    #     end
    #   end
    #
    # In addition to the routing methods, predicate methods are also added to the
    # request object:
    #
    #   route do |r|
    #     "#{r.api?}-#{r.www?}"
    #   end
    #   # Requests to api.example.com or api2.example.com return "true-false"
    #   # Other requests return "false-true"
    #
    # If the +scope_predicates+ plugin keyword argument is given, predicate methods are also
    # created in route block scope:
    #
    #   plugin :host_routing, scope_predicates: true do |hosts|
    #     hosts.to :api, "api.example.com"
    #     hosts.default :www
    #   end
    #
    #   route do |r|
    #     "#{api?}-#{www?}"
    #   end
    #
    # To handle hosts that match a certain format (such as all subdomains),
    # where the specific host names are not known up front, you can provide a block
    # when calling +hosts.default+. This block is passed the host name, or an empty
    # string if no host name is provided, and is evaluated in route block scope.
    # When using this support, you should also call +hosts.register+
    # to register host types that could be returned by the block.  For example, to
    # handle api subdomains differently:
    #
    #   plugin :host_routing do |hosts|
    #     hosts.to :api, "api.example.com"
    #     hosts.register :api_sub
    #     hosts.default :www do |host|
    #       :api_sub if host.end_with?(".api.example.com")
    #     end
    #   end
    #
    # == Fallback and authorization policy
    #
    # In a deployment with a public site and an administrator subsite, it is often
    # useful to let unknown hostnames fall back to the public default, while
    # requiring administrative host types to be explicitly authorized by the
    # configuration.  The +hosts.fallback+ and +hosts.require_authorization+
    # methods support this:
    #
    #   plugin :host_routing do |hosts|
    #     hosts.to :www, "www.example.com"
    #     hosts.to :admin, "admin.example.com"
    #     hosts.register :admin_alias
    #     hosts.default :www do |host|
    #       :admin_alias if host == "admin-old.example.com"
    #     end
    #     hosts.fallback :www
    #     hosts.require_authorization :admin, :admin_alias
    #   end
    #
    # +hosts.fallback+ declares the host types that may be selected as a fallback
    # for a hostname that is not explicitly configured.  If any fallback types are
    # declared, other host types cannot be selected as a fallback.
    #
    # +hosts.require_authorization+ declares the host types that must be authorized
    # by the configuration.  Without a block, a host type is authorized only if
    # the hostname was explicitly configured with +hosts.to+ (or the equivalent
    # +hosts.fallback+ declaration for fallback types).  With a block, the block
    # is passed the hostname (evaluated in route block scope), and the host type
    # is authorized only if the block returns a truthy value.  A block can be used
    # to retire an alias while keeping the other hosts of the same type available:
    #
    #   hosts.require_authorization(:admin) do |host|
    #     host != "admin-old.example.com"
    #   end
    #
    # Requests for unauthorized hosts receive an empty 403 response before the
    # routing tree is called, so unauthorized requests cannot trigger routing
    # side effects.  Applications that use neither +hosts.fallback+ nor
    # +hosts.require_authorization+ keep the previous behavior.  Once either
    # method is used, a hostname that is not explicitly configured will only
    # use the default host if that host type was declared as a fallback.  You
    # can customize the response using +hosts.unauthorized+:
    #
    #   hosts.unauthorized do |r|
    #     "Host #{r.host.inspect} is not authorized"
    #   end
    #
    # Hosts that were explicitly configured keep their original routing methods
    # and predicates (such as +r.admin?+), so an application's existing host
    # checks continue to work.
    #
    # This plugin uses the +host+ method on the request to get the hostname (this method
    # is defined by Rack). Note that as of Rack 3.2, Rack's default approach to determine
    # the hostname is insecure in many cases, since:
    #
    # * It will use a forwarded header instead of the +host+ header by default if the
    #   request was from a trusted proxy.
    # * Rack trust proxies from any private IP address range by default
    #   (this can be disabled using <tt>Rack::Request.ip_filter=</tt>).
    # * Rack supports both +forwarded+ and <tt>x-forwarded-host</tt> headers, will check
    #   both by default, and the order of checking depends on Rack's configuration
    #   (this can be configured using <tt>Rack::Request.forwarded_priority</tt>).
    # * If the application can be reached via an arbitrary +host+ header, the attacker
    #   has full control over the <tt>Rack::Request#host</tt> value even when forwarded
    #   host usage is disabled.
    #
    # You should configure Rack appropriately for your deployment, not allowing the use
    # of forwarded information unless your deployment is using a reverse proxy, and only
    # allowing the specific forwarded header set by the expected reverse proxy if a
    # reverse proxy is used. Rack 3.3 should include more control in this area,
    # and Rack 4 should ship with more secure defaults in regard to forwarding headers.
    #
    # It is recommended to use the host_authorization plugin to check that the requested
    # host is allowed when using this plugin.
    module HostRouting
      REQUEST_INSTANCE_VARIABLES = [:@_host_routing_host, :@_host_routing_hostname].freeze

      # Setup the host routing support.  The block yields an object used to
      # configure the plugin.  Keyword arguments:
      #
      # +scope_predicates+ :: Setup predicate methods in route block scope
      #                       in addition to request scope.
      def self.configure(app, opts=(no_positional_opts = true; OPTS), scope_predicates: false, **kw, &block)
        RodaPlugins.check_keywords("the host_routing plugin", no_positional_opts, opts, kw)

        hosts, host_hash, default_block, default_host, fallback_hosts, authorization_blocks, unauthorized_block = DSL.new.process(&block)
        app.opts[:host_routing_hash] = host_hash
        app.opts[:host_routing_default_host] = default_host
        app.opts[:host_routing_fallback_hosts] = fallback_hosts
        app.opts[:host_routing_authorization_blocks] = authorization_blocks
        app.opts[:host_routing_policy] = !fallback_hosts.empty? || !authorization_blocks.empty?

        app.send(:define_method, :_host_routing_default, &default_block) if default_block
        app.send(:define_method, :_host_routing_unauthorized, &unauthorized_block) if unauthorized_block

        app.include(PolicyInstanceMethods) if app.opts[:host_routing_policy]

        app::RodaRequest.class_exec do
          hosts.each do |host|
            host_sym = host.to_sym
            define_method(host_sym){|&blk| always(&blk) if _host_routing_host == host}
            alias_method host_sym, host_sym

            meth = :"#{host}?"
            define_method(meth){_host_routing_host == host}
            alias_method meth, meth
          end
        end

        if scope_predicates
          app.class_exec do
            hosts.each do |host|
              meth = :"#{host}?"
              define_method(meth){@_request.send(meth)}
              alias_method meth, meth
            end
          end
        end
      end

      class DSL
        def initialize
          @hosts = []
          @host_hash = {}
          @default_host = nil
          @default_block = nil
          @fallback_hosts = []
          @authorization_blocks = {}
          @unauthorized_block = nil
        end

        # Run the DSL for the given block.
        def process(&block)
          instance_exec(self, &block)

          if !@default_host
            raise RodaError, "must call default method inside host_routing plugin block to set default host"
          end

          @hosts.concat(@host_hash.values)
          @hosts << @default_host
          @hosts.uniq!
          [@hosts.freeze, @host_hash.freeze, @default_block, @default_host, @fallback_hosts.freeze, @authorization_blocks.freeze, @unauthorized_block].freeze
        end

        # Register hosts that can be returned.  This is only needed if
        # calling register with a block, where the block can return
        # a value that doesn't match a host given to +to+ or +default+.
        def register(*hosts)
          @hosts = hosts
        end

        # Treat all given hostnames as routing to the give host.
        def to(host, *hostnames)
          hostnames.each do |hostname|
            @host_hash[hostname.downcase.freeze] = host
          end
        end

        # Register the default hostname.  If a block is provided, it is
        # called with the host if there is no match for one of the hostnames
        # provided to +to+.  If the block returns nil/false, the hostname
        # given to this method is used.
        def default(hostname, &block)
          @default_host = hostname
          @default_block = block
        end

        # Mark the given host types as being allowed as a fallback for a
        # hostname that is not explicitly configured.
        def fallback(*hosts)
          @fallback_hosts.concat(hosts)
          nil
        end

        # Mark the given host types as requiring configuration authorization.
        # If a block is given, it is called with the hostname and evaluated in
        # route block scope.  The host type is only authorized if the block
        # returns a truthy value.
        def require_authorization(*hosts, &block)
          hosts.each do |host|
            @authorization_blocks[host] = block
          end
          nil
        end

        # Set the block used for unauthorized requests.  The block is treated
        # as a routing block and is passed the request object.
        def unauthorized(&block)
          @unauthorized_block = block
        end
      end
      private_constant :DSL

      module ClassMethods
        RodaPlugins.opt_attr_reader(self, :host_routing_hash)
        RodaPlugins.opt_attr_reader(self, :host_routing_default_host)
        RodaPlugins.opt_attr_reader(self, :host_routing_fallback_hosts)
        RodaPlugins.opt_attr_reader(self, :host_routing_authorization_blocks)
        RodaPlugins.opt_attr_reader(self, :host_routing_policy, name: :host_routing_policy?)
      end

      module InstanceMethods
        # Handle case where plugin is used without providing a block to
        # +hosts.default+.  This returns nil, ensuring that the hostname
        # provided to +hosts.default+ will be used.
        def _host_routing_default(_)
          nil
        end

        # Default handler for unauthorized hosts.  Returns an empty 403 response.
        def _host_routing_unauthorized(_)
          @_response.status = 403
          nil
        end
      end

      # Instance methods only included when a fallback or authorization policy
      # is configured, so applications that do not use the policy have no
      # change in dispatch behavior.
      module PolicyInstanceMethods
        private

        # Reject unauthorized hosts before the routing tree runs, so an
        # unauthorized request has no routing side effects.
        def _roda_before_01__host_routing
          return if @_request._host_routing_authorized?

          @_request.on do
            _host_routing_unauthorized(@_request)
          end
        end
      end

      module RequestMethods
        # Whether the request's host type is authorized by the host routing
        # configuration.  This returns true when no authorization policy is
        # configured.
        def _host_routing_authorized?
          return true unless roda_class.host_routing_policy?

          hostname = _host_routing_hostname
          host = _host_routing_host

          if authorization_blocks = roda_class.host_routing_authorization_blocks
            if authorization_blocks.key?(host)
              if block = authorization_blocks[host]
                return !!if block.arity == 0
                  scope.instance_exec(&block)
                else
                  scope.instance_exec(hostname, &block)
                end
              end
              return _host_routing_explicitly_configured?(hostname, host)
            end
          end

          if !roda_class.host_routing_fallback_hosts.empty? &&
             !roda_class.host_routing_fallback_hosts.include?(host)
            return _host_routing_explicitly_configured?(hostname, host)
          end

          true
        end

        private

        # The hostname used for the host routing support, downcased (or an
        # empty string if no hostname was provided).
        def _host_routing_hostname
          @_host_routing_hostname ||= begin
            if host = self.host
              host.downcase
            else
              ""
            end
          end
        end

        # Whether the hostname was explicitly configured for the given host
        # type (using +hosts.to+, or +hosts.fallback+ for the default type).
        def _host_routing_explicitly_configured?(hostname, host)
          if configured = roda_class.host_routing_hash[hostname]
            configured == host
          else
            host == roda_class.host_routing_default_host &&
              roda_class.host_routing_fallback_hosts.include?(host)
          end
        end

        # Cache the host to use in the host routing support, so the processing
        # is only done once per request.
        def _host_routing_host
          @_host_routing_host ||= _get_host_routing_host
        end

        # Determine the host to use for the host routing support.  Tries the
        # following, in order:
        #
        # * An exact match for a hostname given in +hosts.to+
        # * The return value of the +hosts.default+ block, if given
        # * The default value provided in the +hosts.default+ call
        def _get_host_routing_host
          hostname = _host_routing_hostname

          roda_class.host_routing_hash[hostname] ||
            scope._host_routing_default(hostname) ||
            roda_class.host_routing_default_host
        end
      end
    end

    register_plugin(:host_routing, HostRouting)
  end
end
