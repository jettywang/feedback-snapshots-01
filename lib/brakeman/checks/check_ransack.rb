require 'brakeman/checks/base_check'
require 'brakeman/processors/output_processor'
require 'set'

class Brakeman::CheckRansack < Brakeman::BaseCheck
  Brakeman::Checks.add self

  @description = "Checks for dangerous use of the Ransack library"

  # Result of evaluating an allow-list method. A finite result is a
  # statically proven set of attribute/association names. Unrestricted
  # means the method demonstrably exposes every name. Unknown means it
  # could not be proven finite, but not necessarily that it exposes all.
  AllowList = Struct.new(:status, :reason, :names) do
    def finite?
      status == :finite
    end

    def unrestricted?
      status == :unrestricted
    end

    def unknown?
      status == :unknown
    end
  end

  def run_check
    return unless version_between? "0.0.0", "3.99", tracker.config.gem_version(:ransack)
    check_ransack_calls
  end

  def check_ransack_calls
    tracker.find_call(method: :ransack, nested: true).each do |result|
      next unless original? result

      call = result[:call]
      arg = call.first_arg

      class_name = result[:chain].first

      capability = search_capability class_name

      next if capability[:available]

      if input = has_immediate_user_input?(arg)
        definite = capability[:definite]

        confidence = if tracker.find_class(class_name).nil? or !model_class?(class_name)
                       :low
                     elsif definite
                       if result[:location][:file].relative.include? 'admin'
                         :medium
                       else
                         :high
                       end
                     else
                       :medium
                     end

        reason_text = capability[:reasons].join('; ')

        message = msg('Unrestricted search using ', msg_code('ransack'), ' library called with ', msg_input(input), '. ', reason_text, '. Limit search by defining finite ', msg_code('ransackable_attributes'), ' and ', msg_code('ransackable_associations'), ' methods in class or upgrade Ransack to version 4.0.0 or newer')

        warn result: result,
          warning_type: 'Missing Authorization',
          warning_code: :ransack_search,
          message: message,
          user_input: input,
          confidence: confidence,
          cwe_id: [862],
          link: 'https://positive.security/blog/ransack-data-exfiltration'
      end
    end
  end

  def analyze_allow_list class_name, method_name, kind
    @allow_list_cache ||= {}
    key = [class_name, method_name, kind]

    if @allow_list_cache.key? key
      @allow_list_cache[key]
    else
      @allow_list_cache[key] = AllowListAnalyzer.new(self, class_name, method_name, kind).analyze
    end
  end

  ASSOCIATION_TYPES = [:has_many, :has_one, :belongs_to, :has_and_belongs_to_many]

  # Associations extend searchable attributes to the associated models.
  # A finite association list is only sufficient if the models it exposes
  # also have finite allow lists.
  def search_capability class_name, seen = Set.new
    attributes = analyze_allow_list class_name, :ransackable_attributes, :attributes
    associations = analyze_allow_list class_name, :ransackable_associations, :associations

    capability = {
      attributes: attributes,
      associations: associations,
      available: false,
      definite: attributes.unrestricted? || associations.unrestricted?,
      reasons: [attributes, associations].reject(&:finite?).map(&:reason).uniq
    }

    unless attributes.finite? and associations.finite?
      return capability
    end

    if seen.include?(class_name)
      capability[:available] = true
      return capability
    end

    seen = seen + [class_name]

    unless associations.names.empty?
      association_classes = association_class_map class_name

      associations.names.each do |association_name|
        target = resolve_association_class association_name, association_classes
        name = association_name.to_s

        unless target
          capability[:reasons] << "association #{name} could not be resolved to a model, so related searches cannot be proven finite"
          return capability
        end

        related = search_capability target, seen

        unless related[:available]
          if related[:definite]
            capability[:definite] = true
            capability[:reasons] << "association #{name} (#{target}) exposes a related model with unrestricted search: #{related[:reasons].join('; ')}"
          else
            capability[:reasons] << "association #{name} (#{target}) cannot be proven finite: #{related[:reasons].join('; ')}"
          end

          return capability
        end
      end
    end

    capability[:available] = true
    capability
  end

  def association_class_map class_name
    model = tracker.models[class_name]
    return {} unless model

    map = {}

    ASSOCIATION_TYPES.each do |type|
      args = model.associations[type] or next

      args.slice_before { |arg| symbol? arg }.each do |group|
        name = group.first
        next unless symbol? name

        explicit = association_class_name group
        map[name.value] = explicit
      end
    end

    map
  end

  def association_class_name args
    args.each do |arg|
      next unless hash? arg

      arg.sexp_body.each_slice(2) do |key, value|
        if symbol? key and key.value == :class_name and (string? value or symbol? value)
          return value.value.to_s
        end
      end
    end

    nil
  end

  def resolve_association_class association_name, association_classes
    explicit = association_classes[association_name.to_sym]
    return explicit.to_sym if explicit and model_class?(explicit)

    if explicit
      return explicit.to_sym if explicit.include?('::')
      return camelize(explicit).to_sym
    end

    name = association_name.to_s
    singular = singular_association_name(name)

    candidates = [
      singular,
      name,
      singular.sub(/a\z/, 'um'),
      singular.sub(/a\z/, 'on')
    ]

    candidates.uniq.each do |candidate|
      class_name = camelize(candidate).to_sym
      return class_name if model_class?(class_name)
    end

    nil
  end

  def singular_association_name name
    if name.end_with? 'ies'
      name.sub(/ies\z/, 'y')
    elsif name =~ /(s|x|z|ch|sh)es\z/
      name.sub(/es\z/, '')
    elsif name.end_with? 's'
      name[0..-2]
    else
      name
    end
  end

  def model_class? name
    model = tracker.models[name]
    model and model.ancestor? :"ActiveRecord::Base"
  end

  # Evaluates the effective allow-list method for a model in a small,
  # deliberately conservative subset of Ruby.
  class AllowListAnalyzer
    include Brakeman::Util

    MAX_DEPTH = 12

    ATTRIBUTE_FALLBACKS = Set[:column_names,
                              :attribute_names,
                              :authorizable_ransackable_attributes]
    ASSOCIATION_FALLBACKS = Set[:reflect_on_all_associations,
                                :authorizable_ransackable_associations]
    ALL_FALLBACKS = Set[:all, :_all]

    ARRAY_MUTATION_METHODS = Set[:<<, :push, :append, :concat, :prepend]

    Context = Struct.new(:receiver_class, :owner_class, :method_info, :seen, :depth, :exits)

    def initialize check, class_name, method_name, kind
      @check = check
      @tracker = check.tracker
      @class_name = class_name
      @method_name = method_name
      @kind = kind
      @format_cache = {}
    end

    def analyze
      unless @class_name.is_a? Symbol
        return unknown("the search target class could not be determined")
      end
      unless @tracker.find_class(@class_name) and @check.model_class?(@class_name)
        return unknown("the search target class could not be determined")
      end

      method = @tracker.find_method(@method_name, @class_name, :class)

      unless method
        # Without a method Ransack falls back to every column/association.
        return unrestricted("#{@method_name} is not defined, so all #{@kind} are searchable")
      end

      context = Context.new(@class_name, method.owner.name, method, Set.new, 0, [])
      value = analyze_method method, context
      result = allow_list_from value

      if result.unknown?
        result.reason = "#{@method_name} #{result.reason}" unless result.reason.start_with?(@method_name.to_s)
        result.reason = "#{result.reason}, so it cannot be proven finite"
      end

      if result.unrestricted? and !result.reason.start_with?(@method_name.to_s) and
         !result.reason.start_with?("the ")
        result.reason = "#{@method_name} #{result.reason}"
      end

      result
    end

    private

    def analyze_method method_info, context
      return unknown("#{@method_name} could not be analyzed (recursion limit)") if context.depth > MAX_DEPTH

      key = [method_info.owner.name, method_info.name]
      return unknown("#{method_info.name} is recursive") if context.seen.include? key

      seen = context.seen + [key]
      method_context = Context.new(@class_name,
                                   method_info.owner.name,
                                   method_info,
                                   seen,
                                   context.depth + 1,
                                   [])

      env = {}
      implicit = evaluate_sequence(method_info.src.body, env, method_context)

      # Explicit returns anywhere in the control flow are alternative paths.
      values = method_context.exits + [implicit]
      combine(values, "some branches", method_context)
    end

    # Evaluate statements in order so early returns see assignments made
    # before them. Every explicit return is a possible capability path,
    # while the fall-through value covers the path where no return is taken.
    def evaluate_sequence statements, env, context
      last = unknown("the method has no return value")

      statements.each do |statement|
        last = evaluate(statement, env, context)

        # Once a branch or statement unconditionally returns, later
        # statements in this sequence are unreachable.
        break if terminates? statement
      end

      last
    end

    def terminates? exp
      return false unless sexp? exp

      case exp.node_type
      when :return
        true
      when :block, :rlist, :scope, :begin
        exp.sexp_body.any? { |e| terminates? e }
      when :if
        then_clause = exp.then_clause
        else_clause = exp.else_clause

        !then_clause.nil? and !else_clause.nil? and
          terminates?(then_clause) and terminates?(else_clause)
      when :case
        branches = []
        exp.each_sexp do |e|
          branches << e if node_type? e, :when
        end

        else_clause = exp.last
        !else_clause.nil? and sexp? else_clause and
          (branches.all? { |branch| terminates_sequence?(branch[2..-1]) }) and
          terminates?(else_clause)
      else
        false
      end
    end

    def terminates_sequence? statements
      statements.any? { |statement| terminates? statement }
    end

    def evaluate exp, env, context
      return unknown("the return value is missing") if exp.nil?

      case exp.node_type
      when :lasgn
        value = evaluate(exp.rhs, env, context)
        env[exp.lhs] = value
        value
      when :op_asgn_or
        left = env.fetch(exp.lhs) { unknown("the local variable #{exp.lhs} has no proven finite value") }
        right = evaluate(exp.rhs, env, context)
        value = combine([left, right], "some branches", context)
        env[exp.lhs] = value
        value
      when :if
        evaluate_if exp, env, context
      when :case
        evaluate_case exp, env, context
      when :return
        value = exp.value ? evaluate(exp.value, env, context) : finite(Sexp.new(:array))
        context.exits << value
        value
      when :block, :rlist, :scope
        evaluate_sequence exp, env, context
      when :begin
        evaluate_sequence exp.sexp_body, env, context
      when :masgn
        evaluate exp.rhs.last, env, context
      when :rescue
        evaluate_rescue exp, env, context
      when :or, :and
        left = evaluate(exp.lhs, env, context)
        right = evaluate(exp.rhs, env, context)
        combine([left, right], "some branches", context)
      when :zsuper, :super
        evaluate_super context
      else
        evaluate_expression exp, env, context
      end
    end

    def evaluate_expression exp, env, context
      return unknown("the return value is missing") if exp.nil?

      case exp.node_type
      when :array
        evaluate_array exp, env, context
      when :hash
        unknown("the allow list is a Hash, not a finite list")
      when :splat
        if request_value? exp[1]
          unrestricted("the allow list is built from request input #{format_exp(exp[1])}")
        else
          evaluate exp[1], env, context
        end
      when :lvar
        env.fetch(exp.value) do
          unknown("the local variable #{format_exp(exp)} has no proven finite value")
        end
      when :lit, :str
        if all_symbol? exp
          unrestricted("#{@method_name} allows all #{@kind} via #{format_exp(exp)}")
        else
          unknown("the expression #{format_exp(exp)} is not an allow list")
        end
      when :nil, :false
        unknown("the method returns nil instead of an allow list")
      when :true
        unknown("the expression #{format_exp(exp)} is not a finite allow list")
      when :const, :colon2, :colon3
        evaluate_constant exp, context
      when :dstr, :dsym
        if request_value? exp
          unrestricted("the allow list is built from request input #{format_exp(exp)}")
        else
          unknown("the allow list contains dynamic string values #{format_exp(exp)}")
        end
      when :zsuper, :super
        evaluate_super context
      when :call, :safe_call, :attrasgn, :safe_attrasgn
        evaluate_call exp, env, context
      when :iter
        evaluate_call exp.block_call, env, context
      else
        unknown("the expression #{format_exp(exp)} could not be evaluated")
      end
    end

    def evaluate_array exp, env, context
      names = Set.new

      exp.each_sexp do |element|
        case element.node_type
        when :lit, :str
          return unrestricted("#{@method_name} allows all #{@kind} via #{format_exp(element)}") if all_symbol? element
          names << normalize_name(element)
        when :splat
          return unrestricted("the allow list is built from request input #{format_exp(element[1])}") if request_value? element[1]
          value = evaluate(element[1], env, context)
          case value.status
          when :finite
            names.merge value.names
          when :unrestricted
            return unrestricted(value.reason)
          else
            return unknown(value.reason)
          end
        else
          value = evaluate(element, env, context)

          if value.unrestricted?
            return unrestricted(value.reason)
          elsif request_value? element
            return unrestricted("the allow list is built from request input #{format_exp(element)}")
          else
            return unknown("the allow list contains a dynamic value #{format_exp(element)}")
          end
        end
      end

      finite exp, names
    end

    def evaluate_if exp, env, context
      condition = exp.condition

      if known_truthy? condition
        return evaluate_branch exp.then_clause, env, context
      elsif known_falsey? condition
        return evaluate_branch exp.else_clause, env, context
      end

      then_env = env.dup
      else_env = env.dup
      then_value = evaluate_branch exp.then_clause, then_env, context
      else_value = evaluate_branch exp.else_clause, else_env, context

      merge_branch_env env, then_env, else_env
      branch_value = combine([then_value, else_value], "some branches", context)
      annotate_branch branch_value, "conditional"
    end

    def evaluate_case exp, env, context
      values = []
      branch_envs = []

      exp.each_sexp do |branch|
        next unless node_type? branch, :when

        branch_env = env.dup
        values << evaluate_sequence(branch[2..-1], branch_env, context)
        branch_envs << branch_env
      end

      if sexp? exp.last
        else_env = env.dup
        values << evaluate_sequence([exp.last], else_env, context)
        branch_envs << else_env
      else
        # Without an else, an unmatched case returns nil. Include the
        # original environment as that fall-through path.
        values << unknown("a case branch has no matching else")
        branch_envs << env.dup
      end

      unless branch_envs.empty?
        merged = branch_envs.shift
        branch_envs.each { |branch_env| merged = merge_envs(merged, branch_env) }
        env.replace merged
      end

      annotate_branch combine(values, "some branches", context), "case"
    end

    def annotate_branch value, branch_kind
      if value.unrestricted? or value.unknown?
        value.reason = "#{value.reason} (#{branch_kind} branch)"
      end

      value
    end

    def evaluate_branch exp, env, context
      if exp.nil?
        unknown("a branch returns nil instead of an allow list")
      elsif node_type? exp, :block, :rlist
        evaluate_sequence exp, env, context
      else
        evaluate exp, env, context
      end
    end

    def merge_branch_env env, then_env, else_env
      env.replace merge_envs(then_env, else_env)
    end

    # A local assigned in only one branch is not guaranteed after the branch.
    def merge_envs left, right
      merged = {}

      left.each do |name, value|
        if right.key? name
          combined = combine_values value, right[name]
          merged[name] = combined
        end
      end

      merged
    end

    def combine_values left, right
      combine([left, right], "some branches", nil)
    end

    def evaluate_rescue exp, env, context
      values = []

      exp.each_sexp do |part|
        if node_type? part, :resbody
          branch_env = env.dup
          values << evaluate_sequence(part[2..-1], branch_env, context)
        else
          values << evaluate(part, env, context)
        end
      end

      combine(values, "some branches", context)
    end

    def evaluate_call exp, env, context
      target = exp.target
      method = exp.method
      args = exp.args

      # Fallbacks which expose every possible name.
      if all_fallback_call? exp
        return unrestricted("#{@method_name} allows all #{@kind} via #{format_exp(exp)}")
      end

      if [:send, :public_send, :__send__].include?(method) and args.length >= 1 and literal_name?(args.first)
        forwarded = Sexp.new(:call, target, args.first.value.to_sym)
        forwarded.push(*args[1..-1]) if args.length > 1
        return evaluate_call forwarded, env, context
      end

      case method
      when :freeze
        value = evaluate target, env, context
        return value
      when :+, :|
        return evaluate_union target, args.first, env, context
      when :&
        return evaluate_intersection target, args.first, env, context
      when :-
        return evaluate_difference target, args.first, env, context
      when :[]
        return evaluate_bracket_call exp, env, context
      when :new
        if node_type? target, :const and [:Set, :Array].include?(target.value)
          return evaluate_set_args exp, env, context
        end
      when *ARRAY_MUTATION_METHODS
        return evaluate_mutation exp, env, context
      when :map, :collect
        return evaluate_map exp, env, context
      when :select, :filter, :reject, :uniq, :compact, :sort, :sort_by,
           :reverse, :flatten, :take, :first, :last, :only, :except,
           :without, :to_a, :to_set, :dup, :clone, :all
        # These can only preserve or narrow the target's names.
        return evaluate(target, env, context) unless args.empty?
      end

      # A call to a local helper which statically returns a list.
      if target.nil? and args.empty?
        if helper_method = find_helper_method(method, context)
          return analyze_method helper_method, context
        end
      end

      unknown("the allow list uses an unknown expression #{format_exp(exp)}")
    end

    def evaluate_union left_exp, right_exp, env, context
      return unrestricted("the allow list is built from request input #{format_exp(right_exp)}") if request_value? right_exp
      return unrestricted("the allow list is built from request input #{format_exp(left_exp)}") if request_value? left_exp

      left = evaluate left_exp, env, context
      right = right_exp ? evaluate(right_exp, env, context) : unknown("the other side of the union is missing")

      if left.unrestricted? or right.unrestricted?
        unrestricted((left.unrestricted? ? left.reason : right.reason))
      elsif left.unknown? or right.unknown?
        unknown((left.unknown? ? left.reason : right.reason))
      else
        finite nil, left.names | right.names
      end
    end

    def evaluate_intersection left_exp, right_exp, env, context
      left = evaluate left_exp, env, context
      right = right_exp ? evaluate(right_exp, env, context) : unknown("the other side of the intersection is missing")

      if left.finite? and right.finite?
        finite nil, left.names & right.names
      elsif left.finite?
        finite nil, left.names
      elsif right.finite?
        finite nil, right.names
      else
        unknown("the intersection cannot be proven finite")
      end
    end

    def evaluate_difference left_exp, right_exp, env, context
      left = evaluate left_exp, env, context

      if left.finite?
        right = right_exp ? evaluate(right_exp, env, context) : unknown("the other side of the subtraction is missing")
        names = right.finite? ? left.names - right.names : left.names
        finite nil, names
      elsif left.unrestricted?
        unrestricted(left.reason)
      else
        unknown(left.reason)
      end
    end

    def evaluate_bracket_call exp, env, context
      target = exp.target

      if node_type? target, :const and [:Set, :Array].include?(target.value)
        evaluate_set_args exp, env, context
      else
        unknown("the expression #{format_exp(exp)} could not be evaluated")
      end
    end

    def evaluate_set_args exp, env, context
      names = Set.new

      exp.each_arg do |arg|
        if array? arg
          value = evaluate_array(arg, env, context)

          if value.finite?
            names.merge value.names
          elsif value.unrestricted?
            return unrestricted(value.reason)
          else
            return unknown(value.reason)
          end
        elsif literal_name? arg
          # A name may itself be a String/Symbol literal.
          return unrestricted("the collection allows all #{@kind}") if all_symbol? arg
          names << normalize_name(arg)
        else
          value = evaluate(arg, env, context)
          case value.status
          when :finite
            names.merge value.names
          when :unrestricted
            return unrestricted(value.reason)
          else
            return unknown(value.reason)
          end
        end
      end

      finite nil, names
    end

    def evaluate_mutation exp, env, context
      target = exp.target
      current = evaluate target, env, context

      exp.args.each do |arg|
        if request_value? arg
          return unrestricted("the allow list is built from request input #{format_exp(arg)}")
        end
      end

      additions = exp.args.map { |arg| evaluate(arg, env, context) }
      additions.each do |addition|
        if addition.unrestricted?
          return unrestricted(addition.reason)
        elsif addition.unknown?
          current = unknown(addition.reason)
          break
        elsif current.finite?
          current = finite(nil, current.names | addition.names)
        end
      end

      if name = base_lvar(target)
        env[name] = current
      end

      current
    end

    def evaluate_map exp, env, context
      target = evaluate exp.target, env, context
      return target unless target.finite?

      if block_pass = exp.args.first
        if node_type? block_pass, :block_pass and literal_name?(block_pass[1]) and
           [:to_sym, :to_s, :to_str, :name, :freeze].include?(block_pass[1].value.to_sym)
          return target
        end
      end

      unless simple_mapping?(exp)
        return unknown("the mapped allow list could contain dynamic values")
      end

      target
    end

    def simple_mapping? exp
      return false unless node_type? exp, :iter

      block_body = exp.block

      if node_type? block_body, :block, :rlist
        block_body = block_body.last
      end

      return true if block_body.nil?

      if node_type? block_body, :lvar
        true
      elsif call? block_body
        method = block_body.method
        target = block_body.target
        [:to_sym, :to_s, :to_str, :name, :freeze].include?(method) and
          node_type? target, :lvar
      else
        false
      end
    end

    def evaluate_constant exp, context
      constants = @tracker.constants.find_all(exp)
      return unknown("the constant #{format_exp(exp)} is not known") unless constants

      constants = constants.select { |constant| constant_context? constant, context }
      return unknown("the constant #{format_exp(exp)} is not known in this class") if constants.empty?

      # A reopened class can assign the same constant multiple times. Use the
      # last assignment as the effective value, mirroring Ruby load order.
      constant = constants.last

      if constant.value.nil?
        unknown("the constant #{format_exp(exp)} has no known value")
      else
        value_context = context.dup
        value_context.owner_class = constant_context_name(constant) || context.owner_class
        evaluate constant.value, {}, value_context
      end
    end

    def constant_context? constant, context
      scope = constant_context_name(constant)
      return true if scope.nil? # top-level constant
      return true if scope == context.owner_class
      return true if ancestor?(context.owner_class, scope)

      module_included?(context.owner_class, scope)
    end

    def constant_context_name constant
      ctx = constant.context
      return nil unless ctx

      scope = ctx[:class] || ctx[:module]
      scope.respond_to?(:name) ? scope.name : scope
    end

    def ancestor? child, parent
      seen = Set.new
      current = @tracker.find_class(child)

      while current and !seen.include? current.name
        return true if current.name == parent
        seen << current.name
        current = @tracker.find_class(current.parent)
      end

      false
    end

    def module_included? child, parent
      seen = Set.new
      queue = [child]

      until queue.empty?
        name = queue.shift
        next if seen.include? name
        seen << name

        collection = @tracker.find_class(name)
        next unless collection

        collection.includes.each do |included|
          return true if included == parent
          queue << included
        end

        queue << collection.parent if collection.parent
      end

      false
    end

    def evaluate_super context
      parent_name = @tracker.find_class(context.owner_class)&.parent

      unless parent_name and (parent_method = find_parent_class_method(parent_name, @method_name))
        return unrestricted("#{@method_name} calls `super`, but no finite parent allow list exists, so all #{@kind} are searchable")
      end

      parent_context = Context.new(@class_name,
                                   parent_method.owner.name,
                                   parent_method,
                                   context.seen,
                                   context.depth + 1,
                                   [])
      result = analyze_method parent_method, parent_context

      if result.unrestricted?
        result.reason = "#{result.reason} (inherited from #{parent_method.owner.name})"
      end

      result
    end

    def find_parent_class_method class_name, method_name
      seen = Set.new
      current = @tracker.find_class(class_name)

      while current and !seen.include? current.name
        if method = current.get_class_method(method_name)
          return method
        end

        seen << current.name
        current = @tracker.find_class(current.parent)
      end

      nil
    end

    def find_helper_method method_name, context
      @tracker.find_method(method_name, context.receiver_class, :class)
    end

    def all_symbol? exp
      node_type? exp, :lit, :str and [:all, :"_all"].include?(exp.value)
    end

    def all_fallback_call? exp
      method = exp.method
      target = exp.target

      return false unless method

      fallbacks = case @kind
                  when :attributes
                    ATTRIBUTE_FALLBACKS
                  when :associations
                    ASSOCIATION_FALLBACKS
                  else
                    Set.new
                  end

      # Methods like `column_names` or `reflect_on_all_associations` are
      # only fallbacks when called without a target, since a target could
      # have a narrower/method-local meaning.
      return true if target.nil? and fallbacks.include? method

      # `_all` is only Ransack's magic all-names result.
      ALL_FALLBACKS.include? method and (target.nil? or node_type? target, :const, :colon2, :colon3, :self)
    end

    def known_truthy? exp
      node_type? exp, :true
    end

    def known_falsey? exp
      exp.nil? or node_type? exp, :false, :nil
    end

    def combine values, description, context
      values = values.compact
      return finite(nil, Set.new) if values.empty?

      unrestricted = values.find(&:unrestricted?)
      if unrestricted
        AllowList.new(:unrestricted, unrestricted.reason, nil)
      else
        unknown = values.find(&:unknown?)
        if unknown
          AllowList.new(:unknown, unknown.reason, nil)
        else
          names = values.inject(Set.new) { |all, value| all | value.names }
          finite nil, names
        end
      end
    end

    def finite exp = nil, names = Set.new
      AllowList.new(:finite, nil, names)
    end

    def unrestricted reason
      AllowList.new(:unrestricted, reason, nil)
    end

    def unknown reason
      AllowList.new(:unknown, reason, nil)
    end

    def allow_list_from value
      AllowList.new(value.status, value.reason, value.names)
    end

    def normalize_name exp
      value = exp.value
      value.is_a?(Symbol) ? value.to_s : value.to_s
    end

    def literal_name? exp
      sexp? exp and [:lit, :str].include? exp.node_type
    end

    def base_lvar exp
      while sexp? exp
        case exp.node_type
        when :lvar
          return exp.value
        when :call, :safe_call, :attrasgn, :safe_attrasgn
          exp = exp.target
        else
          return nil
        end
      end

      nil
    end

    def format_exp exp
      return '' unless sexp? exp

      @format_cache[exp] ||= begin
        formatted = Brakeman::OutputProcessor.new.format(exp).gsub(/\s+/, ' ')
        formatted.length > 80 ? "#{formatted[0, 77]}..." : formatted
      rescue
        exp.inspect
      end
    end
  end
end
