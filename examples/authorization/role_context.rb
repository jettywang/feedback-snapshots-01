# frozen_string_literal: true

# Composite identity role context — runnable acceptance example.
#
#   .feedback/bundle-env exec ruby examples/authorization/role_context.rb
#
# A parent Grape API mounts one child API. Two fake authenticators (identity
# sources) approve the same user name "ada"; only the registered `:ledger`
# source may compose the `:admin` role, and only on v1 and on a mount that does
# not ceiling it away. Every authentication and every business block is appended
# to the shared audit log. The script exits non-zero if any decision differs.

$LOAD_PATH.unshift(File.expand_path('../../lib', __dir__))

require 'grape'
require 'rack/mock'

audit = []

Bearer = Class.new do
  def initialize(app, &verifier)
    @app = app
    @verifier = verifier
  end

  def call(env)
    token = env['HTTP_AUTHORIZATION'].to_s[/\ABearer (.+)\z/, 1]
    return @app.call(env) if @verifier.call(token)

    [401, { 'content-type' => 'text/plain' }, ['Unauthorized']]
  end
end

Grape::Middleware::Auth::Strategies.add(:example_bearer, Bearer)

Identity = Grape::Authorization::Identity

authenticate = lambda do |token|
  source, name = token.to_s.split('-', 2)
  case source
  when 'ledger'
    Identity.new(name:, source: :ledger, roles: %i[reader steward])
  when 'desk'
    Identity.new(name:, source: :desk, roles: %i[reader steward])
  end
end

Child = Class.new(Grape::API) do
  version %w[v1 v2], using: :header, vendor: 'feedback', cascade: false
  format :json

  get :widgets, roles: :reader do
    audit << [:business, :read, authorization_context.to_h]
    { widget: true }
  end

  post :publish, roles: :admin do
    audit << [:business, :publish, authorization_context.to_h]
    { published: true }
  end
end

Parent = Class.new(Grape::API) do
  format :json

  identity_source :ledger, management: true
  identity_source :desk
  version_role_map 'v1' => { steward: :admin }, 'v2' => { steward: :auditor }

  auth :example_bearer do |token|
    if token.nil?
      audit << [:authentication, nil, nil, :missing]
      next false
    end

    identity = authenticate.call(token)
    audit << [:authentication, identity&.source, identity&.name, identity ? :approved : :denied]
    authenticate_identity(identity) if identity
    identity
  end

  mount({ Child => '/console' })
  mount({ Child => '/floor' }, authorization: { ceiling: :reader, label: 'floor-kiosk' })
end

request = Rack::MockRequest.new(Parent)
v1 = { 'HTTP_ACCEPT' => 'application/vnd.feedback-v1+json' }
v2 = { 'HTTP_ACCEPT' => 'application/vnd.feedback-v2+json' }
bearer = ->(token) { { 'HTTP_AUTHORIZATION' => "Bearer #{token}" } }

cases = [
  ['ledger read  v1 /console', :get,  '/console/widgets',        bearer.call('ledger-ada').merge(v1), 200],
  ['desk read    v1 /console', :get,  '/console/widgets',        bearer.call('desk-ada').merge(v1),   200],
  ['ledger admin v1 /console', :post, '/console/publish',        bearer.call('ledger-ada').merge(v1), 201],
  ['desk admin   v1 /console', :post, '/console/publish',        bearer.call('desk-ada').merge(v1),   403],
  ['ledger admin v2 /console', :post, '/console/publish',        bearer.call('ledger-ada').merge(v2), 403],
  ['ledger admin v1 /floor',   :post, '/floor/publish',          bearer.call('ledger-ada').merge(v1), 403],
  ['anonymous    v1 /console', :get,  '/console/widgets',        v1,                                  401]
]

failures = []
cases.each do |label, method, path, headers, expected|
  response = request.public_send(method, path, headers)
  mark = response.status == expected ? 'PASS' : 'FAIL'
  puts format('%-28<label>s expected=%<expected>d got=%<got>d %<mark>s',
              label:, expected:, got: response.status, mark:)
  failures << label unless response.status == expected
end

puts "\nAudit trail (#{audit.size} records):"
audit.each { |entry| puts "  #{entry.inspect}" }

abort("\n#{failures.size} case(s) failed: #{failures.join(', ')}") unless failures.empty?

puts "\nAll role-context decisions matched."
