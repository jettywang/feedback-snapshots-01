require 'brakeman/checks/base_check'

# This check looks for dynamic regular expressions (a regexp literal with an
# interpolation, such as +/#{user_input}/+) that incorporate user input.
#
# Two distinct questions are answered separately for every finding:
#
#   1. Can the pattern itself be injected?  An attacker who controls an
#      unescaped interpolation can supply regexp metacharacters and therefore
#      change the meaning of the pattern.  Wrapping the input in
#      +Regexp.escape+ (or +Regexp.quote+) removes this capability, but it does
#      not make matching cheap.
#
#   2. Is the cost of actually running a match effectively bounded?  Escaping
#      metacharacters does not bound backtracking or the size of the input that
#      is scanned, so on its own it does not address denial of service.  The
#      only safeguards recognized here are a length check on the very value
#      that reaches the regexp, or a call-level timeout that wraps the actual
#      match.  A global +Regexp.timeout=+ is deliberately not treated as proof
#      for an individual call site.
#
# The analysis is intentionally conservative and explainable. It only
# recognizes the specific, visible safeguards below and makes no claim about
# the intrinsic (worst-case) complexity of any particular pattern.
class Brakeman::CheckRegexDoS < Brakeman::BaseCheck
  Brakeman::Checks.add self

  ESCAPE_METHODS = [:escape, :quote].freeze
  LENGTH_METHODS = [:length, :size, :bytesize].freeze
  LENGTH_COMPARISONS = [:>, :>=].freeze
  TIMEOUT_METHODS = [:timeout].freeze

  @description = "Searches regexes including user input"

  #Process calls
  def run_check
    Brakeman.debug "Finding dynamic regexes"
    calls = tracker.find_call :method => [:brakeman_regex_interp]

    Brakeman.debug "Processing dynamic regexes"
    calls.each do |call|
      process_result call
    end
  end

  #Warns about a dynamic regexp that incorporates user input
  def process_result result
    return unless original? result

    call = result[:call]
    method_context = enclosing_method(result)

    component_result = tainted_component(call)
    return unless component_result

    match, component, confidence = component_result

    injectable = !escaped?(component)
    length_bounded = length_guarded?(component, method_context)
    timeout_bounded = call_level_timeout?(call, method_context)
    cost_bounded = length_bounded || timeout_bounded

    # The cost axis is the denial-of-service concern. When a visible, local
    # bound caps the match, there is no unbounded-cost finding to report; the
    # separate injectability question is only relevant while cost is unbound.
    return if cost_bounded

    warn :result => result,
      :warning_type => "Denial of Service",
      :warning_code => :regex_dos,
      :message => build_message(match, injectable, length_bounded, timeout_bounded),
      :confidence => confidence,
      :user_input => match,
      :cwe_id => [20, 185]
  end

  private

  # Returns [Match, tainted_component_sexp, confidence] for the first
  # interpolation component of the regexp that carries user input, otherwise
  # nil. Confidence mirrors the depth at which the input is found: direct
  # params/cookies/request are high, model attributes are medium, and input
  # reached indirectly is weak.
  def tainted_component call
    call.sexp_body.each do |component|
      next unless sexp? component

      if match = has_immediate_user_input?(component)
        return [match, component, :high]
      elsif immediate_model = has_immediate_model?(component)
        return [Match.new(:model, immediate_model), component, :medium]
      elsif match = include_user_input?(component)
        return [match, component, :weak]
      end
    end

    nil
  end

  # True when the user-controlled value is wrapped directly in
  # Regexp.escape/Regexp.quote. This only speaks to injectability; the
  # resulting literal text can still be long and expensive to scan.
  def escaped? component
    nested = component
    nested = nested.value if node_type?(nested, :evstr)

    escape_call?(nested)
  end

  def escape_call? exp
    call?(exp) and
      regexp_constant?(exp.target) and
      ESCAPE_METHODS.include?(exp.method)
  end

  # Matches a bare +Regexp+ constant. A namespaced constant such as
  # +Rack::Utils+ is represented as a multi-item +:colon2+ node and must not be
  # read with +Sexp#value+, which only accepts single-item nodes.
  def regexp_constant? exp
    node_type?(exp, :const) && exp.value == :Regexp
  end

  # Matches a bare +Timeout+ constant only.
  def timeout_constant? exp
    node_type?(exp, :const) && exp.value == :Timeout
  end

  # True when the enclosing method contains a length/size comparison that
  # guards the exact value reaching the regexp. The comparison must reference
  # the same expression that is interpolated, so a check on a different
  # variable or a reassigned value is not reused as proof. When the value is
  # wrapped in Regexp.escape, the length check naturally sits on the raw input
  # (the argument to escape), so that argument is compared instead.
  def length_guarded? component, method_context
    return false unless method_context

    guarded_value = component
    guarded_value = guarded_value.value if node_type?(guarded_value, :evstr)

    if escape_call?(guarded_value)
      guarded_value = guarded_value.first_arg
    end

    found = false

    walk method_context do |node|
      next unless call? node
      next unless LENGTH_COMPARISONS.include?(node.method)
      next unless integer?(node.first_arg)

      length_call = node.target
      next unless call?(length_call) && LENGTH_METHODS.include?(length_call.method)

      if length_call.target == guarded_value
        found = true
        break
      end
    end

    found
  end

  # True when the actual regexp match is wrapped in a call-level timeout. Only
  # +Timeout.timeout+ blocks that lexically enclose this regexp are accepted.
  # A process-wide +Regexp.timeout=+ assignment is deliberately ignored: it is
  # configured away from the call site and is not treated as proof for this
  # particular match.
  def call_level_timeout? call, method_context
    return false unless method_context

    timeout_block_wraps?(method_context, call)
  end

  # Walk the enclosing scope and check whether the regexp call sits inside a
  # +Timeout.timeout+ block. A timeout elsewhere in the same method (for
  # example, around an unrelated call) does not wrap this regexp.
  def timeout_block_wraps? node, regexp_call
    return false unless node.is_a? Sexp

    if node_type?(node, :iter)
      block_call = node.block_call

      if call?(block_call) &&
         TIMEOUT_METHODS.include?(block_call.method) &&
         timeout_constant?(block_call.target) &&
         contains?(node.block, regexp_call)
        return true
      end
    end

    node.each_sexp do |child|
      return true if timeout_block_wraps?(child, regexp_call)
    end

    false
  end

  # Structural containment check over the enclosing scope's sexp tree.
  def contains? node, target
    return false unless node.is_a? Sexp
    return true if node == target

    node.each_sexp do |child|
      return true if contains?(child, target)
    end

    false
  end

  # Depth-first traversal of every sexp node in a tree. +Sexp#each_sexp+ only
  # visits direct children, so this recursion is needed to search whole scopes.
  def walk node, &block
    return unless node.is_a? Sexp

    yield node

    node.each_sexp do |child|
      walk child, &block
    end
  end

  # Resolve the body of the method (or template block) that contains the
  # regexp. Length checks and timeout wrappers are only meaningful within this
  # local scope. Returns nil when the surrounding scope cannot be resolved.
  def enclosing_method result
    location = result[:location]

    if location[:type] == :template
      template = location[:template]
      return template.respond_to?(:src) ? template.src : nil
    end

    klass = tracker.find_class(location[:class])
    return nil unless klass

    method_info = klass.get_method(location[:method])
    method_info && method_info.src
  end

  def build_message match, injectable, length_bounded, timeout_bounded
    # A warning is only emitted while matching cost is unbounded, so the
    # message always states which cost safeguard is missing. The injectability
    # axis is described separately instead of being conflated with cost.
    message = msg(msg_input(match), " used in regular expression")

    if injectable
      message << msg(". Input is not escaped with ", msg_code("Regexp.escape"),
                     ", so the pattern itself can be injected")
    else
      message << msg(" (escaped with ", msg_code("Regexp.escape"),
                     ", so it cannot be injected, but escaping does not limit matching cost)")
    end

    missing = []
    missing << "a length check on the matched value" unless length_bounded
    missing << "a call-level timeout wrapping the match" unless timeout_bounded

    message << msg(". Matching cost is not bounded by #{missing.join(" or ")}")
    message
  end
end
