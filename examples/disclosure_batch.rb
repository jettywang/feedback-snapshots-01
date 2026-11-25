# frozen_string_literal: true

# Runs a partner download twice with the same order objects referenced from two
# groups in opposite order. Only one occurrence is lowered from detail to
# summary. Prints the public payload and the per-occurrence receipt so the two
# can be compared.
#
#   ruby -Ilib examples/disclosure_batch.rb

require 'grape-entity'

Order = Struct.new(:id, :total, :memo, :note, keyword_init: true)

# One order carries a note through a nested entity. The nested entity is
# rendered with the same disclosure scope as its parent order.
class NoteEntity < Grape::Entity
  expose :code, scope: :summary
  expose :text, scope: :detail
end

class OrderEntity < Grape::Entity
  expose :id, scope: :summary
  expose :total, scope: :summary
  expose :memo, scope: :detail
  expose :note, using: NoteEntity
end

class GroupEntity < Grape::Entity
  expose :name
  expose :orders, using: OrderEntity
end

class BatchEntity < Grape::Entity
  expose :batch_id
  expose :groups, using: GroupEntity
end

order_one = Order.new(id: 1, total: 10, memo: 'first memo')
order_two = Order.new(
  id: 2, total: 20, memo: 'second memo',
  note: { code: 'n-2', text: 'added by a nested entity' }
)

group_a = { name: 'a', orders: [order_one, order_two] }
group_b = { name: 'b', orders: [order_two, order_one] }

def policy(lowered_group_index)
  Grape::Entity::Disclosure::Policy.new(
    levels: %i[summary detail],
    identifier: ->(object) { object.id if object.respond_to?(:id) }
  ) do |object, occurrence, _options|
    next nil unless object.respond_to?(:memo)

    lowered = occurrence.group_path == [:groups, lowered_group_index, :orders] && object.id == 2
    lowered ? :summary : :detail
  end
end

def run(label, batch, lowered_group_index)
  result = BatchEntity.represent_with_receipt(batch, disclosure: policy(lowered_group_index))

  puts "== #{label}"
  puts "payload: #{result.payload.inspect}"
  result.receipt.to_a.each do |entry|
    puts format(
      '  #%<position>d %<path>s mode=%<mode>s id=%<identifier>s fields=%<fields>s',
      position: entry[:position],
      path: entry[:path].inspect,
      mode: entry[:mode],
      identifier: entry[:identifier].inspect,
      fields: entry[:fields].inspect
    )
  end
  puts
end

run('groups a,b (group a first)', { batch_id: 'batch-1', groups: [group_a, group_b] }, 0)
run('groups b,a (group a second)', { batch_id: 'batch-1', groups: [group_b, group_a] }, 1)
