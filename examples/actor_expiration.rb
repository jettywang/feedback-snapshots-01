require "flipper"

# A common pattern for sensitive feature pilots: each actor is approved
# individually, with an explicit revocation time, while global and group
# gates keep their usual meaning.
#
# Use a clock you control and a reaper you schedule (cron, Sidekiq, etc.).
# Expired grants stop opening the actor gate immediately; the reaper only
# deletes them from storage.
clock = { now: Time.utc(2026, 1, 1, 12, 0, 0) }
storage = Flipper::Adapters::Memory.new
flipper = Flipper::Managed.new(storage, clock: -> { clock[:now] })

alice = Flipper::Actor.new("Employee;1")
bob = Flipper::Actor.new("Employee;2")

# Ordinary gates are unchanged on other features.
flipper.enable :billing_exports
flipper.enable_group :billing_exports, :finance

flipper.enable_actor :billing_v2, alice, expires_in: 60 * 60
flipper.enable_actor :billing_v2, bob, expires_at: clock[:now] + 60 * 60 * 4

puts flipper.enabled?(:billing_v2, alice)   # => true

# At any time, a reviewer can extend one approval without changing who is
# approved.
flipper.extend_actor :billing_v2, bob, expires_in: 60 * 60 * 24

# Move the clock forward and reap. Only grants whose expiration passed are
# removed. A grant extended concurrently is kept.
clock[:now] += 60 * 60
removed = flipper.reap_expired_actors(:billing_v2)
puts removed.inspect                        # => [["billing_v2", "Employee;1"]]

puts flipper.enabled?(:billing_v2, alice)   # => false
puts flipper.enabled?(:billing_v2, bob)     # => true
puts storage.get(flipper[:billing_v2])[:actors].inspect

# If the app needs the stored record rather than its effect, ask directly:
puts flipper.actor_expirations(:billing_v2).inspect
