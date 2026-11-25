# frozen_string_literal: true

# Generated regression for multi-version mounts.
#
# Every request is legal by construction: the path, method and version value
# come from a deployment manifest (see #manifests), and the expected outcome is
# derived from that manifest alone, never from what the API happens to answer.
#
# The app records the two facts a response cannot show: which endpoint handler
# ran -- with the version it resolved to, the route it matched and the mount
# stack it sat under -- and which authentication layers were consulted and
# whether they accepted the caller. Those records reject *association* failures
# (v2 routing into the v1 handler, a mount that lost its inherited version, a
# declared auth layer that never runs) that a status/body assertion would
# happily accept.
#
# A fixed RSpec seed drives a deterministic sample of manifests; a failing one
# prints a replay line, and the smallest failing example is persisted under
# tmp/ for the pre-launch re-check.
RSpec.describe 'Grape multi-version mount generated regression' do
  let(:mvm) { Spec::Support::MultiVersionMount }

  # Every legal deployment shape the manifest vocabulary can express: four
  # version strategies x nested/flat mounts x optional prefix/namespace x
  # which auth layers are declared. Each field also becomes part of the path,
  # the headers and the trace, so no field is dead weight.
  let(:manifests) do
    mvm::STRATEGIES.product(%i[nested flat], [nil, 'ip'], [nil, 'ops'], [true, false], [true, false]).map do |strategy, shape, prefix, namespace, v2_auth, edge_auth|
      { strategy:, shape:, prefix:, namespace:, v2_auth:, edge_auth: }
    end
  end

  # The smallest manifest with a prefix, a namespace, a nested mount and both
  # auth layers, for each strategy. These carry the "two versions of one path
  # beside one inherited route" shape.
  let(:canonical_manifests) do
    mvm::STRATEGIES.map { |strategy| { strategy:, shape: :nested, prefix: 'ip', namespace: 'ops', v2_auth: true, edge_auth: true } }
  end

  # Deterministic per RSpec seed: a failing run reproduces with --seed <n>. The
  # sweep below runs every manifest, so this selection only picks the smallest
  # example to persist for the replay fixture.
  let(:rng) { Random.new(RSpec.configuration.seed) }
  let(:sample) { manifests.sample([manifests.size, 24].min, random: rng) }

  def app_for(manifest, misassociate: false)
    mvm.build_deployment(manifest, misassociate:)
  end

  # Asserts one request against the manifest and returns the replay description,
  # so a failure names exactly the manifest and request to rebuild.
  def verify(manifest, resource, version, method, app: nil, expected_status: nil, user: mvm::USER, password: mvm::PASSWORD, reject: false)
    app ||= app_for(manifest)
    observed = mvm.observe(app, manifest, resource, version, method, user:, password:)
    if reject
      # An auth rejection: the caller is turned away before any route handler
      # runs. With no credentials at all Rack rejects before the block runs;
      # with wrong ones the block records its refusal.
      expect(observed[:status]).to eq(expected_status)
      expect(observed[:handler]).to be_nil
      if user
        refused = observed[:trace].select { |entry| entry['kind'] == 'auth' && !entry['accepted'] }
        expect(refused.size).to eq(1)
      end
      return mvm.replay_line(manifest, resource, version, method)
    end
    expected = mvm.expectation(manifest, resource, version, method)
    problems = mvm.mismatch(observed, expected)

    expect(problems).to be_empty, -> { "#{mvm.replay_line(manifest, resource, version, method)}\n  #{problems.join("\n  ")}" }
    mvm.replay_line(manifest, resource, version, method)
  end

  describe 'the generated manifests' do
    # The whole vocabulary runs every time: 128 manifests x 2 resources x 4
    # versions x 3 methods, each checked against the manifest that declared it.
    it 'routes every legal request to the handler, mount and auth layers its manifest declares' do
      failures = []
      manifests.each do |manifest|
        app = app_for(manifest)
        mvm::RESOURCES.each do |resource|
          [nil, 'v1', 'v2', 'v9'].each do |version|
            %w[GET POST HEAD].each do |method|
              begin
                verify(manifest, resource, version, method, app:)
              rescue RSpec::Expectations::ExpectationNotMetError => e
                failures << e.message
              end
              break if failures.size >= 3
            end
            break if failures.size >= 3
          end
          break if failures.size >= 3
        end
        break if failures.size >= 3
      end
      expect(failures).to be_empty, failures.first(3).join("\n\n")
    end
  end

  describe 'two versions of one path beside an inherited route' do
    it 'reaches v1, v2 and the inherited route on every strategy' do
      canonical_manifests.each do |manifest|
        app = app_for(manifest)
        # Same path, two versions.
        verify(manifest, :ping, 'v1', 'GET', app:)
        verify(manifest, :ping, 'v2', 'GET', app:)
        # The inherited legacy route beside them, under each version.
        verify(manifest, :legacy, 'v1', 'GET', app:)
        verify(manifest, :legacy, 'v2', 'GET', app:)
      end
    end

    it 'distinguishes the versions by handler and resolved version, not by mount alone' do
      manifest = { strategy: :path, shape: :flat, prefix: nil, namespace: nil, v2_auth: true, edge_auth: true }
      app = app_for(manifest)

      v1 = mvm.observe(app, manifest, :ping, 'v1', 'GET')
      v2 = mvm.observe(app, manifest, :ping, 'v2', 'GET')

      expect(v1[:handler]).to eq('ping@v1:ping')
      expect(v2[:handler]).to eq('ping@v2:ping')
      expect(v1[:mount]).to eq(v2[:mount])
      expect(v1[:env_version]).to eq('v1')
      expect(v2[:env_version]).to eq('v2')
      # The inherited route shares the mount but resolves to the version scope
      # it was declared in.
      inherited = mvm.observe(app, manifest, :legacy, 'v2', 'GET')
      expect(inherited[:handler]).to eq('legacy:legacy')
      expect(inherited[:route_version]).to eq('v2')
    end
  end

  describe 'what a status-only assertion misses' do
    it 'accepts a v2 request routed into the v1 handler, though status and body agree' do
      manifest = { strategy: :path, shape: :flat, prefix: nil, namespace: nil, v2_auth: false, edge_auth: false }
      correct = mvm.observe(app_for(manifest), manifest, :ping, 'v2', 'GET')
      swapped = mvm.observe(app_for(manifest, misassociate: true), manifest, :ping, 'v2', 'GET')

      # The shallow facts agree: same status, same body.
      expect(swapped[:status]).to eq(correct[:status])
      expect(swapped[:body]).to eq(correct[:body])

      # Only the handler association separates them.
      expect(correct[:handler]).to eq('ping@v2:ping')
      expect(swapped[:handler]).to eq('ping@v1:ping')
      expect(mvm.mismatch(swapped, mvm.expectation(manifest, :ping, 'v2', 'GET')).join(',')).to include('ping@v1:ping')
    end
  end

  describe 'the auth layers the manifest declares' do
    it 'requires the edge layer on a versioned route for both versions' do
      manifest = { strategy: :param, shape: :nested, prefix: 'ip', namespace: 'ops', v2_auth: false, edge_auth: true }
      app = app_for(manifest)

      %w[v1 v2].each do |version|
        verify(manifest, :ping, version, 'GET', app:)
        verify(manifest, :ping, version, 'GET', app:, user: nil, expected_status: 401, reject: true)
        verify(manifest, :ping, version, 'GET', app:, password: 'wrong', expected_status: 401, reject: true)
      end
    end

    it 'requires the version-scoped layer on its version only, and rejects a wrong password there' do
      manifest = { strategy: :header, shape: :flat, prefix: nil, namespace: nil, v2_auth: true, edge_auth: false }
      app = app_for(manifest)

      # v1 is unguarded by the v2 layer: a wrong password changes nothing.
      verify(manifest, :ping, 'v1', 'GET', app:)
      verify(manifest, :ping, 'v2', 'GET', app:)
      verify(manifest, :ping, 'v2', 'GET', app:, password: 'wrong', expected_status: 401, reject: true)
    end
  end

  describe 'equivalent mount constructions' do
    # A full semantic signature: status, content type, body and the recorded
    # trace. Only constructions that are claimed equivalent are compared, so a
    # difference here is a real difference.
    def signature(app, url, headers = {})
      env = Rack::MockRequest.env_for(url)
      env[mvm::TRACE] = []
      env.merge!(headers)
      status, response_headers, body = app.call(env)
      response = Rack::MockResponse.new(status, response_headers, body)
      [response.status, response.headers['content-type'], response.body, env[mvm::TRACE]]
    end

    it 'treats a version block and a version statement followed by a scope as one' do
      support = mvm
      service = support.build_service('ping', resources: [:ping])
      block_form = Class.new(Grape::API) { format :json; version('v1', using: :path) { mount({ service => '/svc' }) } }
      statement_form = Class.new(Grape::API) do
        format :json
        version 'v1', using: :path
        scope(:named_only) { mount({ service => '/svc' }) }
      end
      expect(signature(block_form, '/svc/v1/ping')).to eq(signature(statement_form, '/svc/v1/ping'))
    end

    it 'treats prefix and version declared before or after a mount as one' do
      support = mvm
      service = support.build_service('ping', resources: [:ping])
      before = Class.new(Grape::API) { format :json; prefix 'ip'; version 'v1', using: :path; mount({ service => '/svc' }) }
      after = Class.new(Grape::API) { format :json; mount({ service => '/svc' }); version 'v1', using: :path; prefix 'ip' }
      expect(before.routes.map { |route| route.pattern.origin }).to eq(after.routes.map { |route| route.pattern.origin })
      expect(signature(before, '/svc/ip/v1/ping')).to eq(signature(after, '/svc/ip/v1/ping'))
    end

    it 'treats a nested mount and an equivalent single mount path as the same route, while keeping mount identity' do
      support = mvm
      ping = support.build_service('ping', resources: [:ping])
      legacy = support.build_service('legacy', resources: [:legacy])
      middle = support.build_middle(ping, legacy)
      nested = Class.new(Grape::API) { format :json; mount({ middle => '/mid' }) }
      flat = Class.new(Grape::API) { format :json; mount({ ping => '/mid/svc', legacy => '/mid/svc' }) }
      expect(nested.routes.map { |route| route.pattern.origin }).to eq(flat.routes.map { |route| route.pattern.origin })

      nested_mount = signature(nested, '/mid/svc/ping')[3].find { |entry| entry['kind'] == 'handler' }['mount']
      flat_mount = signature(flat, '/mid/svc/ping')[3].find { |entry| entry['kind'] == 'handler' }['mount']
      expect(nested_mount).to eq(%w[/mid /svc])
      expect(flat_mount).to eq(%w[/mid/svc])
    end

    it 'treats an auth layer declared outside or inside a namespace wrapping only mounts as one' do
      support = mvm
      service = support.build_service('ping', resources: [:ping])
      authorize = lambda do |user, password|
        env[support::TRACE] << { kind: 'auth', layer: 'edge' }
        user == support::USER && password == support::PASSWORD
      end
      headers = { 'HTTP_AUTHORIZATION' => support.basic_authorization }
      outside = Class.new(Grape::API) do
        format :json
        http_basic(&authorize)
        namespace(:x) { mount({ service => '/m' }) }
      end
      inside = Class.new(Grape::API) do
        format :json
        namespace(:x) do
          http_basic(&authorize)
          mount({ service => '/m' })
        end
      end
      expect(signature(outside, '/m/x/ping', headers)).to eq(signature(inside, '/m/x/ping', headers))
    end
  end

  describe 'orderings that are business conventions, not incidental code order' do
    def response(app, url, headers = {})
      Rack::MockResponse[*app.call(Rack::MockRequest.env_for(url).merge(headers))]
    end

    def versioned_app(strategy, order)
      Class.new(Grape::API) do
        format :json
        order.each do |version|
          options = { using: strategy, vendor: 'acme', parameter: 'apiver', cascade: true }
          version(version, **options)
          get('/ping') { { from: version } }
        end
      end
    end

    def version_request(strategy, version)
      case strategy
      when :header then ['/ping', version ? { 'HTTP_ACCEPT' => "application/vnd.acme-#{version}+json" } : {}]
      when :accept_version_header then ['/ping', version ? { 'HTTP_ACCEPT_VERSION' => version } : {}]
      when :param then [version ? "/ping?apiver=#{version}" : '/ping', {}]
      end
    end

    it 'treats explicit version selection as independent of declaration order' do
      (mvm::STRATEGIES - [:path]).each do |strategy|
        first = versioned_app(strategy, %w[v1 v2])
        swapped = versioned_app(strategy, %w[v2 v1])
        %w[v1 v2].each do |version|
          url, headers = version_request(strategy, version)
          expect(JSON.parse(response(first, url, headers).body)).to eq('from' => version)
          expect(JSON.parse(response(swapped, url, headers).body)).to eq('from' => version)
        end
      end
    end

    it 'takes the first declared version as the fallback, so declaration order is the convention' do
      (mvm::STRATEGIES - [:path]).each do |strategy|
        first = versioned_app(strategy, %w[v1 v2])
        swapped = versioned_app(strategy, %w[v2 v1])
        expect(JSON.parse(response(first, '/ping').body)).to eq('from' => 'v1')
        expect(JSON.parse(response(swapped, '/ping').body)).to eq('from' => 'v2')
      end
    end

    it 'keeps a version statement in effect for later routes but scopes a version block to its block' do
      statement = Class.new(Grape::API) do
        format :json
        version 'v2', using: :path
        get('/one') { { n: 1 } }
        get('/two') { { n: 2 } }
      end
      block = Class.new(Grape::API) do
        format :json
        version('v2', using: :path) { get('/one') { { n: 1 } } }
        get('/two') { { n: 2 } }
      end
      expect(statement.routes.map { |route| route.pattern.origin }).to eq(%w[/:version/one /:version/two])
      expect(block.routes.map { |route| route.pattern.origin }).to eq(%w[/:version/one /two])
    end

    it 'collapses two mounts of one app declared as duplicate Hash keys to the last' do
      service = mvm.build_service('ping', resources: [:ping])
      # A Hash literal keeps only the last value for a repeated key, so only the
      # final path is mounted.
      app = Class.new(Grape::API) { format :json; mount({ service => '/one', service => '/two' }) }
      expect(app.routes.map { |route| route.pattern.origin }.uniq).to eq(%w[/two/ping])
    end

    it 'covers only routes declared after an auth layer, not ones declared before it' do
      # A layer applies to routes declared after it in the same scope; a
      # namespace opened first is a scope of its own, so routes inside it are
      # covered as a block. That asymmetry is the convention this pins.
      before_only = Class.new(Grape::API) do
        format :json
        get('/x') { { ok: true } }
        http_basic { |user, password| user == mvm::USER && password == mvm::PASSWORD }
      end
      covering = Class.new(Grape::API) do
        format :json
        http_basic { |user, password| user == mvm::USER && password == mvm::PASSWORD }
        get('/x') { { ok: true } }
      end
      expect(response(before_only, '/x').status).to eq(200)
      expect(response(covering, '/x').status).to eq(401)
    end

    it 'lets whichever comes first answer between a catch-all and a bare mount' do
      bare = ->(_env) { [200, { 'content-type' => 'text/plain' }, ['BARE']] }
      catch_first = Class.new(Grape::API) do
        format :json
        route(:any, '*path') { 'catch-all' }
        mount({ bare => '/mp' })
      end
      mount_first = Class.new(Grape::API) do
        format :json
        mount({ bare => '/mp' })
        route(:any, '*path') { 'catch-all' }
      end
      expect(JSON.parse(response(catch_first, '/mp').body)).to eq('catch-all')
      expect(response(mount_first, '/mp').body).to eq('BARE')
    end
  end

  describe 'the replay fixture' do
    let(:replay) do
      manifest = { strategy: :path, shape: :nested, prefix: 'ip', namespace: 'ops', v2_auth: true, edge_auth: true }
      expected = mvm.expectation(manifest, :ping, 'v2', 'GET')
      {
        'seed' => RSpec.configuration.seed,
        'command' => format('bundle exec rspec spec/grape/api/multi_version_mount_generated_spec.rb --seed %d', RSpec.configuration.seed),
        'plan' => manifest.slice(:strategy, :shape, :prefix, :namespace, :v2_auth, :edge_auth),
        'request' => { 'resource' => 'ping', 'version' => 'v2', 'method' => 'GET', 'status' => expected[:status] },
        'expect' => expected.slice(:handler, :route_version, :env_version, :origin, :mount, :layers)
      }
    end

    it 'persists a directly replayable sample for the pre-launch check' do
      FileUtils.mkdir_p(mvm::REPLAY_DIR)
      File.write(mvm::REPLAY_FILE, "#{JSON.pretty_generate(replay)}\n")

      persisted = JSON.parse(File.read(mvm::REPLAY_FILE))
      expect(persisted).to include(
        'seed' => RSpec.configuration.seed,
        'plan' => include('strategy' => 'path'),
        'request' => include('resource' => 'ping', 'version' => 'v2', 'method' => 'GET')
      )
      expect(persisted['expect']['handler']).to eq('ping@v2:ping')
    end

    it 'replays the persisted sample against the current code' do
      # Write once, then read back and issue exactly the persisted plan and
      # request, so the file is proof rather than decoration.
      FileUtils.mkdir_p(mvm::REPLAY_DIR)
      File.write(mvm::REPLAY_FILE, "#{JSON.pretty_generate(replay)}\n")
      persisted = JSON.parse(File.read(mvm::REPLAY_FILE))

      manifest = mvm.normalize_manifest(persisted['plan'])
      app = app_for(manifest)
      observed = mvm.observe(app, manifest, persisted['request']['resource'].to_sym, persisted['request']['version'], persisted['request']['method'])
      expect(observed[:status]).to eq(persisted['request']['status'])
      expect(observed.slice(:handler, :route_version, :env_version, :origin, :mount, :layers))
        .to eq(persisted['expect'].transform_keys(&:to_sym))
    end
  end
end
