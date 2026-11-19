require 'brakeman/util'

# Statically determines whether a file path used in a file access call
# is *proven* to be confined to a managed directory by a guard check
# dominating the use.
#
# Only explainable relationships between a candidate path and a
# directory root are supported:
#
# * Paths built with File.join / File.expand_path / #join / interpolation
#   from a static root (an absolute string literal or Rails.root).
# * Guards of the form `candidate.start_with?(root_prefix)` where the
#   prefix ends on a directory boundary (e.g. a trailing separator), so
#   sibling directories like `uploads_evil` cannot pass the check.
# * Guard clauses (`return ... unless ...`) and branches that reject
#   non-conforming paths before the guarded use.
#
# Anything that cannot be explained statically (runtime-computed roots,
# symlinks resolved via File.realpath, Pathname#cleanpath, etc.) remains
# unknown and is never treated as proof of confinement.
#
# The result of #proof is one of:
#
# * :proven        - a valid guard dominates the use
# * a LostProof    - a guard exists, but the proof was lost (with line/reason)
# * nil            - no relevant guard was found
class Brakeman::PathConfinement
  include Brakeman::Util

  # Location where confinement proof was lost, plus a reason symbol:
  #
  # :boundary    - prefix check does not end on a directory boundary
  # :unrelated   - checked prefix does not match the directory the path
  #                was built from
  # :unknown     - root of the check cannot be verified statically
  # :reassigned  - path variable was reassigned after the check
  # :mutated     - path variable was modified after the check
  # :not_covered - check does not cover this use of the path
  LostProof = Struct.new(:line, :reason)

  # A statically explainable directory root.
  #
  # [base]       :lit (absolute string literal) or :rails_root
  # [segments]   path segments below the base
  # [terminated] true if the path ends on a directory boundary
  Root = Struct.new(:base, :segments, :terminated) do
    def prefix_of? other
      self.base == other.base and
        self.segments.length <= other.segments.length and
        other.segments[0, self.segments.length] == self.segments
    end

    # Two roots are related if one contains the other.
    def related_to? other
      prefix_of?(other) or other.prefix_of?(self)
    end
  end

  Guard = Struct.new(:keys, :valid, :reason, :line, :negated)

  # Methods that modify a string/path in place
  MUTATING_METHODS = [:<<, :concat, :prepend, :replace, :gsub!, :sub!, :insert].freeze

  # Flow-sensitive state while walking a method body
  class Env
    attr_accessor :proven, :values

    def initialize proven = {}, values = {}
      @proven = proven
      @values = values
    end

    def dup
      Env.new(@proven.dup, @values.dup)
    end

    # Keep only what holds in both branch outcomes
    def merge! other
      @proven = @proven.select { |key, _| other.proven.key? key }
      @values = @values.select { |key, value| other.values[key] == value }
      self
    end

    def adopt! other
      @proven = other.proven
      @values = other.values
      self
    end
  end

  # [src]       method definition sexp (:defn or :defs)
  # [use_call]  the file access call sexp inside +src+
  # [candidate] the path expression passed to +use_call+
  def initialize src, use_call, candidate
    @src = src
    @use_call = use_call
    @candidate = candidate
    @guards_seen = {} # key => line of first guard-like check
    @lost = {}        # key => LostProof
    @done = false
    @result = nil
  end

  def proof
    process @src, Env.new
    @result
  end

  private

  def process exp, env
    return if @done
    return unless sexp? exp

    case exp.node_type
    when :lasgn
      process_assignment exp, env
    when :if
      process_if exp, env
    when :and
      process_and exp, env
    when :or
      process_or exp, env
    when :call
      process_call exp, env
    when :iter, :while, :until, :for, :case, :rescue
      # Branches/loops: effects do not propagate outward
      process_all exp, env.dup
    else
      process_all exp, env
    end
  end

  def process_all exp, env
    exp.each do |e|
      process e, env if e.is_a? Sexp
    end
  end

  def process_assignment exp, env
    value = exp[2]

    # Right-hand side is evaluated first
    process value, env if sexp? value

    var = exp[1]
    return unless var.is_a? Symbol

    old_value = env.values[var]

    if proof_or_guard_for? env, var, old_value
      record_lost var, old_value, exp.line, :reassigned
    end

    env.proven.delete var
    env.proven.delete old_value if old_value
    env.values[var] = value
  end

  def process_if exp, env
    condition = exp.condition
    then_clause = exp.then_clause
    else_clause = exp.else_clause

    guard = guard_info condition, env

    process condition, env

    if guard
      record_guard guard

      protected_clause = guard.negated ? else_clause : then_clause
      rejected_clause = guard.negated ? then_clause : else_clause

      if empty_clause? protected_clause and rejecting? rejected_clause
        # Guard clause: `return/raise unless path.start_with?(...)`
        process rejected_clause, env.dup

        if guard.valid
          guard.keys.each { |key| env.proven[key] = guard.line }
        end

        return
      end

      protected_env = env.dup

      if guard.valid
        guard.keys.each { |key| protected_env.proven[key] = guard.line }
      end

      process protected_clause, protected_env

      rejected_env = env.dup
      process rejected_clause, rejected_env

      if rejecting? rejected_clause
        env.adopt! protected_env
      elsif rejecting? protected_clause
        env.adopt! rejected_env
      else
        env.adopt! protected_env.merge!(rejected_env)
      end
    else
      then_env = env.dup
      process then_clause, then_env

      else_env = env.dup
      process else_clause, else_env

      env.adopt! then_env.merge!(else_env)
    end
  end

  def process_and exp, env
    lhs, rhs = exp[1], exp[2]
    guard = guard_info lhs, env

    process lhs, env

    if guard
      record_guard guard

      rhs_env = env.dup

      if guard.valid
        guard.keys.each { |key| rhs_env.proven[key] = guard.line }
      end

      process rhs, rhs_env
    else
      process rhs, env.dup
    end
  end

  def process_or exp, env
    lhs, rhs = exp[1], exp[2]
    guard = guard_info lhs, env

    process lhs, env

    if guard
      record_guard guard

      process rhs, env.dup

      # `path.start_with?(ok) || return` proves confinement afterwards
      if guard.valid and rejecting? rhs
        guard.keys.each { |key| env.proven[key] = guard.line }
      end
    else
      process rhs, env.dup
    end
  end

  def process_call exp, env
    if use_call? exp
      evaluate_use env
      return
    end

    check_mutation exp, env

    process exp.target, env if sexp? exp.target

    exp.args.each do |arg|
      process arg, env if arg.is_a? Sexp
    end
  end

  def use_call? exp
    exp.equal? @use_call or
      (exp.line == @use_call.line and exp.method == @use_call.method)
  end

  def evaluate_use env
    keys = keys_for @candidate, env

    if keys.any? { |key| env.proven.key? key }
      @result = :proven
    else
      keys.each do |key|
        if lost = @lost[key]
          @result = lost
          break
        end
      end

      if @result.nil?
        guard_line = nil

        keys.each do |key|
          if line = @guards_seen[key]
            guard_line = line
            break
          end
        end

        @result = LostProof.new(guard_line, :not_covered) if guard_line
      end
    end

    @done = true
  end

  # In-place modification of a tracked path (e.g. `path << params[:x]`)
  def check_mutation exp, env
    return unless MUTATING_METHODS.include? exp.method

    target = exp.target
    return unless sexp? target

    vars = []
    vars << target.value if target.node_type == :lvar

    env.values.each do |var, value|
      vars << var if value == target
    end

    vars.each do |var|
      old_value = env.values[var]

      if proof_or_guard_for? env, var, old_value
        record_lost var, old_value, exp.line, :mutated
      end

      env.proven.delete var
      env.proven.delete old_value if old_value

      # The variable now holds the mutated expression
      env.values[var] = exp
    end
  end

  def proof_or_guard_for? env, var, value
    env.proven.key?(var) or
      @guards_seen.key?(var) or
      (value and (env.proven.key?(value) or @guards_seen.key?(value)))
  end

  def record_lost var, value, line, reason
    lost = LostProof.new(line, reason)
    @lost[var] ||= lost
    @lost[value] ||= lost if value
  end

  def record_guard guard
    guard.keys.each do |key|
      @guards_seen[key] ||= guard.line
      @lost[key] ||= LostProof.new(guard.line, guard.reason) unless guard.valid
    end
  end

  # All identities a path expression may be known by: itself and any
  # local variable currently holding it.
  def keys_for exp, env
    keys = [exp]
    keys << exp.value if exp.node_type == :lvar

    env.values.each do |var, value|
      keys << var if value == exp
    end

    keys
  end

  # Matches `path.start_with?(prefix)` (optionally negated) and checks
  # whether the prefix is a verifiable directory boundary for the path.
  def guard_info condition, env
    return nil unless call? condition

    negated = false
    check = condition

    while call? check and check.method == :! and check.num_args == 0
      negated = !negated
      check = check.target
    end

    return nil unless call? check
    return nil unless check.method == :start_with? or check.method == :begin_with?
    return nil unless check.num_args == 1

    checked = check.target
    return nil unless sexp? checked

    keys = keys_for checked, env
    prefix_root = static_root check.first_arg, env

    valid = false
    reason = nil

    if prefix_root.nil?
      reason = :unknown
    elsif not prefix_root.terminated
      reason = :boundary
    else
      construction = construction_root checked, env

      if construction.nil?
        reason = :unknown
      elsif not prefix_root.related_to? construction
        reason = :unrelated
      else
        valid = true
      end
    end

    Guard.new keys, valid, reason, condition.line, negated
  end

  # Root the candidate path was built from, if statically explainable.
  def construction_root exp, env
    root_of exp, env, allow_tail: true
  end

  # A fully static directory root, or nil if any part is not
  # statically explainable.
  def static_root exp, env
    root_of exp, env, allow_tail: false
  end

  def root_of exp, env, allow_tail:, seen: {}
    return nil unless sexp? exp

    case exp.node_type
    when :str
      string_root exp.value
    when :lvar
      var = exp.value
      value = env.values[var]

      if value and not seen[var]
        root_of value, env, allow_tail: allow_tail, seen: seen.merge(var => true)
      end
    when :call
      root_of_call exp, env, allow_tail, seen
    when :dstr
      root_of_dstr exp, env, allow_tail, seen
    end
  end

  def root_of_call exp, env, allow_tail, seen
    case exp.method
    when :join
      if const_file? exp.target
        # File.join(root, ...)
        base = root_of exp.first_arg, env, allow_tail: allow_tail, seen: seen
        extend_with_args base, exp.args[1..] || [], env, allow_tail, seen
      else
        # root.join(...)
        base = root_of exp.target, env, allow_tail: allow_tail, seen: seen
        extend_with_args base, exp.args, env, allow_tail, seen
      end
    when :expand_path
      return nil unless const_file? exp.target and exp.num_args == 1

      root = root_of exp.first_arg, env, allow_tail: allow_tail, seen: seen

      # File.expand_path strips any trailing separator
      root && Root.new(root.base, root.segments, false)
    when :+
      return nil unless exp.num_args == 1 and string? exp.first_arg

      root = root_of exp.target, env, allow_tail: allow_tail, seen: seen
      root && extend_with_literal(root, exp.first_arg.value)
    when :to_s
      root_of exp.target, env, allow_tail: allow_tail, seen: seen
    when :root
      if exp.target == s(:const, :Rails) and exp.num_args == 0
        Root.new(:rails_root, [], false)
      end
    end
  end

  def root_of_dstr exp, env, allow_tail, seen
    base = nil

    exp.each_with_index do |part, index|
      if part.is_a? String
        # Leading literal of the interpolation
        next if part.empty?

        base = string_root part
        return nil if base.nil?
        next
      end

      next if index == 0

      case part.node_type
      when :str
        literal = part.value
        next if literal.empty? and base.nil?

        if base.nil?
          base = string_root literal
          return nil if base.nil?
        else
          base = extend_with_literal base, literal
        end
      when :evstr
        inner = part.value

        if base.nil?
          base = root_of inner, env, allow_tail: allow_tail, seen: seen
          return nil if base.nil?
        elsif allow_tail
          # Remainder is not statically known
          return base
        else
          return nil
        end
      else
        return nil
      end
    end

    base
  end

  def extend_with_args base, args, env, allow_tail, seen
    return nil if base.nil?

    args.each do |arg|
      if string? arg
        base = extend_with_literal base, arg.value
      elsif allow_tail
        # Remaining arguments are the uncontrolled tail of the path
        return base
      else
        return nil
      end
    end

    base
  end

  def extend_with_literal base, literal
    segments = literal.split("/").reject(&:empty?)
    terminated = literal.empty? || literal.end_with?("/")

    Root.new(base.base, base.segments + segments, terminated)
  end

  def string_root string
    return nil unless string.start_with? "/"

    Root.new(:lit, string.split("/").reject(&:empty?), string.end_with?("/"))
  end

  def const_file? exp
    exp == s(:const, :File)
  end

  def empty_clause? exp
    exp.nil? or
      (sexp?(exp) and (exp.node_type == :block or exp.node_type == :rlist) and exp.empty?)
  end

  # Statements that definitely do not fall through
  def rejecting? exp
    return false unless sexp? exp

    case exp.node_type
    when :return
      true
    when :call
      (exp.target.nil? or exp.target == s(:const, :Kernel)) and
        [:raise, :fail].include? exp.method
    when :block, :rlist
      rejecting? exp.last
    else
      false
    end
  end
end
