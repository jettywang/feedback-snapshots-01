require 'bundler/setup'
require 'flipper'
require 'flipper/adapters/failover'

# The primary is the configuration service. The secondary is a local snapshot
# that keeps ordinary flags working while the primary is unreachable.
primary = Flipper::Adapters::Memory.new
secondary = Flipper::Adapters::Memory.new

# Pretend the snapshot was written before payments were turned off.
stale = Flipper.new(secondary)
stale.enable(:search)
stale.enable(:checkout_payments)

adapter = Flipper::Adapters::Failover.new(primary, secondary,
  critical_features: [:checkout_payments, :refunds],
  safe_value: {boolean: false})
flipper = Flipper.new(adapter)

configuration = Flipper.new(primary)
configuration.enable(:search)
configuration.enable(:checkout_payments)
configuration.enable(:refunds)

puts "Primary is healthy:"
puts "  search           => #{flipper.enabled?(:search)}"
puts "  checkout_payments => #{flipper.enabled?(:checkout_payments)}"

# The configuration service goes away.
def disable_primary!(primary)
  primary.define_singleton_method(:get) { |_feature| raise IOError, "primary unavailable" }
  primary.define_singleton_method(:get_multi) { |_features| raise IOError, "primary unavailable" }
  primary.define_singleton_method(:get_all) { |**_kwargs| raise IOError, "primary unavailable" }
  primary.define_singleton_method(:features) { raise IOError, "primary unavailable" }
end
disable_primary!(primary)

puts "\nPrimary is unreachable (snapshot still says payments are on):"
puts "  search            => #{flipper.enabled?(:search)} (ordinary, served from snapshot)"
puts "  checkout_payments => #{flipper.enabled?(:checkout_payments)} (critical, safe value)"
puts "  refunds           => #{flipper.enabled?(:refunds)} (critical, safe value)"

# The primary recovers; its real values win again on the next read.
primary.singleton_class.send(:remove_method, :get)
primary.singleton_class.send(:remove_method, :get_multi)
primary.singleton_class.send(:remove_method, :get_all)
primary.singleton_class.send(:remove_method, :features)

puts "\nPrimary recovered:"
puts "  search            => #{flipper.enabled?(:search)}"
puts "  checkout_payments => #{flipper.enabled?(:checkout_payments)}"
