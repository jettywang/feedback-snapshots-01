# frozen_string_literal: true

# Support for the multi-version mount generated regression: the recording hooks
# the mounted app runs, the deployment builder each manifest declares, and the
# manifest-derived oracle. The oracle never reads what the API answered; it is
# computed from the manifest's own fields, so the trace can contradict it.
module Spec
  module Support
    module MultiVersionMount
      TRACE = 'spec.multi_version_mount.trace'
      USER = 'api-user'
      PASSWORD = 'api-pass'
      VERSIONS = %w[v1 v2].freeze
      FIRST_VERSION = VERSIONS.first
      STRATEGIES = %i[path param header accept_version_header].freeze
      RESOURCES = %i[ping legacy].freeze
      # A stable, git-ignored path: the replay sample survives the run for the
      # pre-launch re-check without being committed.
      REPLAY_DIR = File.expand_path('../../tmp/multi_version_mount', __dir__)
      REPLAY_FILE = File.join(REPLAY_DIR, 'replay.json')

      module_function

      def basic_authorization(user = USER, password = PASSWORD)
        "Basic #{["#{user}:#{password}"].pack('m0')}"
      end

      # Records on the request's own env, so requests never share a trace.
      def record(env, entry)
        (env[TRACE] ||= []) << entry.transform_keys(&:to_s)
      end

      def record_auth(env, layer, user, accepted)
        record(env, kind: 'auth', layer: layer.to_s, user: user.to_s, accepted:)
      end

      def record_handler(env, id)
        endpoint = env[Grape::Env::API_ENDPOINT]
        record(
          env,
          kind: 'handler',
          id:,
          request_method: env['REQUEST_METHOD'],
          route_version: endpoint.route.version,
          env_version: env[Grape::Env::API_VERSION],
          origin: endpoint.route.origin.to_s,
          mount: endpoint.inheritable_setting.mount_paths
        )
      end

      # A leaf service declares only +resources+. Its version and mount are
      # inherited from the deployment scope, so the trace shows whether that
      # inheritance actually reached it.
      def build_service(prefix, resources:)
        Class.new(Grape::API) do
          format :json
          resources.each do |resource|
            resource resource do
              get { MultiVersionMount.record_handler(env, "#{prefix}:#{resource}"); { ok: true } }
              post { MultiVersionMount.record_handler(env, "#{prefix}:#{resource}"); { ok: true } }
            end
          end
        end
      end

      # The deployment a manifest declares. Every version scope mounts a handler
      # at /mid/svc and, beside it, the inherited legacy service; the nested
      # shape reaches both through one intermediate mount instead.
      def build_deployment(manifest, misassociate: false)
        ping_v1 = build_service('ping@v1', resources: [:ping])
        ping_v2 = build_service('ping@v2', resources: [:ping])
        legacy = build_service('legacy', resources: [:legacy])

        leaf = lambda do |version|
          handler = version == 'v1' ? ping_v1 : ping_v2
          handler = ping_v1 if misassociate && version == 'v2'
          handler
        end

        Class.new(Grape::API) do
          format :json
          if manifest[:edge_auth]
            http_basic(realm: 'edge') do |user, password|
              accepted = user == USER && password == PASSWORD
              MultiVersionMount.record_auth(env, :edge, user, accepted)
              accepted
            end
          end
          prefix manifest[:prefix] if manifest[:prefix]

          namespace(manifest[:namespace]) do
            VERSIONS.each do |version|
              options = { using: manifest[:strategy], vendor: 'acme', parameter: 'apiver', cascade: true }
              version(version, **options) do
                # Declared inside the version block, so the layer guards this
                # version's routes only; declaring it in the enclosing scope
                # would reach back into the sibling version's child scope.
                if manifest[:v2_auth] && version == 'v2'
                  http_basic(realm: 'v2') do |user, password|
                    accepted = user == USER && password == PASSWORD
                    MultiVersionMount.record_auth(env, :v2, user, accepted)
                    accepted
                  end
                end

                ping = leaf.call(version)
                mounts = if manifest[:shape] == :nested
                           { MultiVersionMount.build_middle(ping, legacy) => '/mid' }
                         else
                           { ping => '/mid/svc', legacy => '/mid/svc' }
                         end
                mount(mounts)
              end
            end
          end
        end
      end

      # The intermediate mount the nested shape reaches the leaves through.
      def build_middle(ping, legacy)
        Class.new(Grape::API) do
          format :json
          mount({ ping => '/svc', legacy => '/svc' })
        end
      end

      def request_url(manifest, resource, version)
        url = +'/mid/svc'
        url << "/#{manifest[:prefix]}" if manifest[:prefix]
        url << "/#{version}" if manifest[:strategy] == :path && version
        url << "/#{manifest[:namespace]}" if manifest[:namespace]
        url << "/#{resource}"
        url
      end

      def request_headers(manifest, version)
        case manifest[:strategy]
        when :header
          version ? { 'HTTP_ACCEPT' => "application/vnd.acme-#{version}+json" } : {}
        when :accept_version_header
          version ? { 'HTTP_ACCEPT_VERSION' => version } : {}
        else
          {}
        end
      end

      def request_query(manifest, version)
        manifest[:strategy] == :param && version ? "?apiver=#{version}" : ''
      end

      def request_path_and_headers(manifest, resource, version)
        ["#{request_url(manifest, resource, version)}#{request_query(manifest, version)}", request_headers(manifest, version)]
      end

      # The version scopes whose route a strategy tries, in order. This is what
      # runs the auth layers: a route consults them before its versioner can
      # accept or decline it. Path versioning encodes the version in the URL, so
      # the router only offers a declared segment and nothing is tried for an
      # absent or undeclared one; the other strategies match a path first and
      # try its candidates, one per declared version.
      def attempts(manifest, version)
        return [] if manifest[:strategy] == :path && (version.nil? || !VERSIONS.include?(version))
        return [version] if manifest[:strategy] == :path
        return [FIRST_VERSION] if version.nil? || version == FIRST_VERSION

        # A request for the later version, or for an undeclared one, is declined
        # by the first route and offered to the second; both consult their auth.
        VERSIONS
      end

      # Whether any attempted route actually answers. An undeclared version is
      # declined by every route it reaches, so the request ends at the router.
      def answered?(manifest, version)
        return false if version && !VERSIONS.include?(version)

        attempts(manifest, version).any?
      end

      # The version the matched route resolved to, and the version the versioner
      # published on the env. The header versioner records a version even when
      # the caller sent none, because a bare Accept is matched to the first
      # declared media type; the others leave it nil.
      def answering_version(version)
        version || FIRST_VERSION
      end

      def environment_version(manifest, version)
        return version if version
        return FIRST_VERSION if manifest[:strategy] == :header

        nil
      end

      # Each candidate route attempt consults the auth layers declared on it: the
      # edge layer every route inherits, then the version-scoped layer on v2
      # routes. A declined request therefore records every attempt it made.
      def consulted_layers(manifest, version)
        attempts(manifest, version).flat_map do |scope|
          layers = []
          layers << 'edge' if manifest[:edge_auth]
          layers << 'v2' if manifest[:v2_auth] && scope == 'v2'
          layers
        end
      end

      # +resource+ both selects which leaf service answered and, for the
      # inherited route, whether that answer is a version's own handler or the
      # shared one.
      def handler_id(manifest, resource, version)
        return unless answered?(manifest, version)

        return 'legacy:legacy' if resource == :legacy

        "ping@#{answering_version(version)}:ping"
      end

      def expected_origin(manifest, resource)
        origin = +'/mid/svc'
        origin << "/#{manifest[:prefix]}" if manifest[:prefix]
        origin << '/:version' if manifest[:strategy] == :path
        origin << "/#{manifest[:namespace]}" if manifest[:namespace]
        "#{origin}/#{resource}"
      end

      def expected_mount(manifest)
        manifest[:shape] == :nested ? %w[/mid /svc] : %w[/mid/svc]
      end

      def expected_status(manifest, version, method)
        return 404 unless answered?(manifest, version)

        method == 'POST' ? 201 : 200
      end

      # The full manifest-declared outcome for one legal request. When no route
      # answers, only the layers each attempt consulted remain meaningful.
      def expectation(manifest, resource, version, method)
        answered = answered?(manifest, version)
        {
          handler: handler_id(manifest, resource, version),
          route_version: answered ? answering_version(version) : nil,
          env_version: answered ? environment_version(manifest, version) : nil,
          origin: expected_origin(manifest, resource),
          mount: expected_mount(manifest),
          layers: consulted_layers(manifest, version),
          status: expected_status(manifest, version, method)
        }
      end

      # Issues one request and returns what the app recorded, in the same shape
      # as #expectation.
      def observe(app, manifest, resource, version, method, user: USER, password: PASSWORD)
        path, version_headers = request_path_and_headers(manifest, resource, version)
        env = Rack::MockRequest.env_for(path, method: method)
        env[TRACE] = []
        env.merge!(version_headers)
        env['HTTP_AUTHORIZATION'] = basic_authorization(user, password) if user
        status, headers, body = app.call(env)
        response = Rack::MockResponse.new(status, headers, body)
        trace = env[TRACE]
        recorded = trace.find { |entry| entry['kind'] == 'handler' }
        {
          status: response.status,
          content_type: response.headers['content-type'],
          body: response.body,
          trace:,
          handler: recorded && recorded['id'],
          route_version: recorded && recorded['route_version'],
          env_version: recorded && recorded['env_version'],
          origin: recorded && recorded['origin'],
          mount: recorded && recorded['mount'],
          layers: trace.select { |entry| entry['kind'] == 'auth' }.map { |entry| entry['layer'] }
        }
      end

      # Compares an observation with an expectation; each entry names one
      # fact the manifest declared and the app contradicted.
      def mismatch(observed, expected)
        problems = []
        problems << "status #{observed[:status]} != #{expected[:status]}" unless observed[:status] == expected[:status]
        if expected[:handler]
          handlers = observed[:trace].count { |entry| entry['kind'] == 'handler' }
          problems << "handler ran #{handlers} times, expected once" unless handlers == 1
          problems << "handler #{observed[:handler].inspect} != #{expected[:handler].inspect}" unless observed[:handler] == expected[:handler]
          problems << "route_version #{observed[:route_version].inspect} != #{expected[:route_version].inspect}" unless observed[:route_version] == expected[:route_version]
          problems << "env_version #{observed[:env_version].inspect} != #{expected[:env_version].inspect}" unless observed[:env_version] == expected[:env_version]
          problems << "origin #{observed[:origin].inspect} != #{expected[:origin].inspect}" unless observed[:origin] == expected[:origin]
          problems << "mount #{observed[:mount].inspect} != #{expected[:mount].inspect}" unless observed[:mount] == expected[:mount]
          problems << "content-type #{observed[:content_type].inspect} != application/json" unless observed[:content_type] == 'application/json'
        elsif observed[:handler]
          problems << "unexpected handler #{observed[:handler].inspect}"
        end
        problems << "auth #{observed[:layers].inspect} != #{expected[:layers].inspect}" unless observed[:layers] == expected[:layers]
        problems
      end

      # Manifests round-trip through JSON as strings; rebuild the symbol
      # vocabulary the builder reads.
      def normalize_manifest(manifest)
        manifest = manifest.transform_keys(&:to_sym)
        manifest[:strategy] = manifest[:strategy].to_sym
        manifest[:shape] = manifest[:shape].to_sym
        manifest
      end

      def replay_line(manifest, resource, version, method)
        format(
          'plan=%s resource=%s version=%s method=%s',
          manifest.slice(:strategy, :shape, :prefix, :namespace, :v2_auth, :edge_auth).inspect,
          resource, version.inspect, method
        )
      end
    end
  end
end
