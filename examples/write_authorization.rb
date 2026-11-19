require 'bundler/setup'
require 'flipper'
require 'flipper/adapters/write_authorization'
require 'flipper/instrumenters/memory'

# On-call can turn dangerous things down, but only security can widen a rollout.
policy = Flipper::Adapters::WriteAuthorization::Policy.new(
  on_call: { 'checkout' => %i[add disable clear] },
  security: :all,
)

instrumenter = Flipper::Instrumenters::Memory.new
adapter = Flipper::Adapters::WriteAuthorization.new(
  Flipper::Adapters::Memory.new,
  policy: policy,
  instrumenter: instrumenter,
)
flipper = Flipper.new(adapter)
checkout = flipper[:checkout]
auth = Flipper::Adapters::WriteAuthorization

auth.with_principal(:security) do
  checkout.enable_actor(Flipper::Actor.new('user;1'))
end
puts "security enabled checkout for user;1: #{checkout.enabled?(Flipper::Actor.new('user;1'))}"

auth.with_principal(:on_call) do
  checkout.disable_actor(Flipper::Actor.new('user;1'))
  puts "on-call disabled user;1: #{checkout.enabled?(Flipper::Actor.new('user;1'))}"

  begin
    checkout.enable
  rescue auth::NotAuthorized => error
    puts "on-call enable denied: #{error.message}"
  end
end

auth.with_principal(:security) do
  checkout.enable
end
puts "security enabled checkout for everyone: #{checkout.enabled?}"

denials = instrumenter.events_by_name(auth::DenialInstrumentationName)
puts "denial events: #{denials.map(&:payload).inspect}"
