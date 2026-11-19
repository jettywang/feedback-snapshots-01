require 'flipper'
require 'flipper/audit'

# Wrap the adapter whose writes you want to audit. Reads and writes keep
# hitting the same local adapter.
adapter = Flipper::Adapters::Memory.new
audit = Flipper::Audit.new(adapter)
flipper = Flipper.new(audit)

# Attach only the public id of whoever is operating. Names, emails, and
# other raw person data are not recorded.
Flipper::Audit.with_operator("operator-123") do
  flipper.enable(:search)
  flipper.enable(:search) # repeated; recorded as unchanged
  flipper.enable(:search, Flipper.any(Flipper.property(:plan).eq("pro")))
end

# A broken import is recorded as a failed write and re-raised as usual.
begin
  Flipper::Audit.with_operator("operator-456") do
    flipper.import(Flipper::Exporters::Json::Export.new(contents: "{"))
  end
rescue Flipper::Exporters::Json::InvalidError
  # expected
end

audit.events.each do |event|
  puts [
    event.at.iso8601,
    event.operator_id.inspect,
    event.operation,
    event.feature_name.inspect,
    event.outcome,
    event.reason.inspect,
  ].join(" ")

  event.changes.each do |change|
    puts "  #{change.gate_name}: #{change.from.inspect} -> #{change.to.inspect}"
  end
end

puts "Final state: #{flipper[:search].state.inspect}"
puts "Reconciled: #{audit.reconciled?}"
