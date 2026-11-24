# frozen_string_literal: true

require "dry-schema"

Dry::Schema.load_extensions(:role_views)

# One compiled base schema: its public validation rules are shared by every role.
profile_schema = Dry::Schema.Params do
  configure { config.validate_keys = true }

  required(:name).filled(:string, min_size?: 2)
  required(:age).filled(:integer, gt?: 0)
  optional(:role).filled(:string)
end

# Roles narrow the writable fields while reusing the base types and rules.
profile_schema.register_role(:admin) { |schema| schema.view(:name, :age, :role) }
profile_schema.register_role(:member) { |schema| schema.view(:name, :age) }

admin = profile_schema.for_role(:admin)
member = profile_schema.for_role(:member)

# Full update: both roles validate every permitted field against the base rules.
puts admin.call(name: "Ada", age: 36, role: "owner").to_h.inspect
# => {:name=>"Ada", :age=>36, :role=>"owner"}

# A member cannot touch a field outside its view.
puts member.call(name: "Ada", age: 36, role: "member").errors.to_h.inspect
# => {:role=>["is not allowed"]}

# Partial update: required keys are relaxed, so an omitted field is allowed while
# the fields that are present still run their base predicates.
puts member.call(name: "Ada").to_h.inspect
# => {:name=>"Ada"}
puts member.call(age: -1).errors.to_h.inspect
# => {:age=>["must be greater than 0"]}

# A caller whose role was never registered is rejected instead of falling back
# to a wider schema.
begin
  profile_schema.for_role(:guest)
rescue Dry::Schema::Extensions::RoleViews::UnknownRoleError => e
  puts e.message
end
# => unknown role :guest. Registered roles: :admin, :member

# The base schema keeps enforcing its original required rules.
puts profile_schema.call(name: "Ada").errors.to_h.inspect
# => {:age=>["is missing"]}
