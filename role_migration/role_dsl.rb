# frozen_string_literal: true

# Role-based declaration layer.
#
# A "role" is a single runtime option key: options[:role]. The DSL below is
# deliberately thin - it does not add a new condition engine. Every role
# declaration compiles to the SAME grape-entity primitives the old view
# conditions use (Hash / Symbol / Block Condition). That is what makes an
# old-vs-new equivalence argument possible at the condition level.
module RoleMigration
  # Compile a role declaration into the exact :if/:unless argument grape-entity
  # already understands.
  #
  #   role_if(:admin)              -> { role: :admin }          # HashCondition
  #   role_if(:admin, :auditor)    -> block (OR over roles)      # BlockCondition
  #   role_if { |obj, opt| ... }   -> block (arbitrary rule)     # BlockCondition
  #   role_unless(:guest)          -> { role: :guest } under :unless
  module RoleDsl
    ROLE_KEY = :role

    def role_if(*roles, &block)
      return RoleMigration::Tracer.block("role_if:#{roles.map(&:inspect).join('|')}", &block) if block_given?

      roles = roles.flatten
      if roles.size == 1
        { ROLE_KEY => roles.first }
      else
        build_or_block(roles, negate: false)
      end
    end

    def role_unless(*roles)
      roles = roles.flatten
      if roles.size == 1
        { ROLE_KEY => roles.first }
      else
        build_or_block(roles, negate: true)
      end
    end

    # A symbol rule on the role option, mirroring the legacy `if: :some_flag`
    # SymbolCondition shape but reading a boolean role capability.
    def role_capability(capability)
      RoleMigration::Tracer.block("role_capability:#{capability}") do |_object, options|
        options[:capabilities]&.include?(capability) == true
      end
    end

    private

    def build_or_block(roles, negate:)
      label = "role_#{negate ? 'unless' : 'if'}:#{roles.map(&:inspect).join('|')}"
      RoleMigration::Tracer.block(label) do |_object, options|
        member = roles.include?(options[RoleDsl::ROLE_KEY])
        negate ? !member : member
      end
    end
  end

  # Static migration classifier. Given a single exposure's compiled condition
  # set and the runtime keys it reads, decide whether it can be rewritten as a
  # pure role declaration without changing visible output.
  #
  # A condition is "role-migratable" only when every condition it depends on can
  # be expressed against options[:role] (or role-derived capabilities) AND it
  # does not rely on a non-role runtime key (view/version/type/object state).
  class MigrationClassifier
    # @param exposure [Grape::Entity::Exposure::Base]
    # @return [Hash] verdict with :status, :reasons, :rewrite
    def self.classify(exposure)
      new(exposure).call
    end

    def initialize(exposure)
      @exposure = exposure
    end

    def call
      reasons = []
      rewrite = []

      @exposure.conditions.each do |condition|
        verdict_for(condition, reasons, rewrite)
      end

      status = reasons.empty? ? :migratable : :blocked
      { field: @exposure.attribute, status: status, reasons: reasons, rewrite: rewrite }
    end

    private

    def verdict_for(condition, reasons, rewrite)
      case condition
      when Grape::Entity::Condition::HashCondition
        hash = condition.cond_hash
        non_role = hash.keys.map(&:to_sym) - [RoleDsl::ROLE_KEY]
        if non_role.empty?
          roles = hash.values
          rewrite << "#{condition.inversed? ? 'role_unless' : 'role_if'}(#{roles.map(&:inspect).join(', ')})"
        else
          reasons << "HashCondition reads non-role key(s) #{non_role.inspect} (e.g. view/version/type)"
          rewrite << "keep #{condition.inversed? ? ':unless' : ':if'} OR first collapse #{non_role.inspect} into role mapping"
        end
      when Grape::Entity::Condition::SymbolCondition
        sym = condition.symbol
        if sym == RoleDsl::ROLE_KEY
          rewrite << 'role_if-style symbol on :role (prefer explicit role hash)'
        else
          reasons << "SymbolCondition reads options[#{sym.inspect}], not the role"
          rewrite << "replace with role_capability(#{sym.inspect}) only if #{sym.inspect} is derivable from role"
        end
      when Grape::Entity::Condition::BlockCondition
        name = RoleMigration::Tracer.block_name(condition.block) || '<anonymous block>'
        if name.to_s.start_with?('role_')
          rewrite << name
        else
          reasons << "BlockCondition `#{name}` may read object state or non-role options"
          rewrite << "inline as role_if { ... } only after proving it depends solely on options[:role]"
        end
      end
    end
  end
end
