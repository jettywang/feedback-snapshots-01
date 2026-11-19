require 'brakeman/checks/base_check'

#Reports request data flowing into response header names or values without a
#provable removal (or rejection) of CR/LF characters.
#
#Response splitting is possible when attacker-controlled data containing
#carriage return/line feed characters is written to a response header.
#
#Tracks data into the response header hash via:
#
#  response.headers["X-Header"] = value
#  headers["X-Header"] = value
#  response.set_header("X-Header", value)
#  response.headers.merge!("X-Header" => value)
#
#including through local/instance variable aliases of the header hash.
#Header names and header values are checked separately.
class Brakeman::CheckResponseHeaderSplitting < Brakeman::BaseCheck
  Brakeman::Checks.add self

  @description = "Checks request data used in response headers for response splitting (CR/LF injection)"

  #Methods that remove CR and LF characters from a string.
  NEWLINE_FILTERS = Set[:gsub, :gsub!, :sub, :sub!, :tr, :tr!, :tr_s, :tr_s!, :delete, :delete!].freeze

  #Methods which cannot reintroduce CR/LF characters after filtering.
  SAFE_STRING_METHODS = Set[:to_s, :to_str, :upcase, :downcase, :titleize, :titlecase,
    :strip, :lstrip, :rstrip, :chomp, :chop, :reverse, :squeeze, :squeeze!,
    :encode, :force_encoding, :dup, :freeze, :itself, :to_query].freeze

  #Methods which halt execution of the current action when invoked.
  HALT_METHODS = Set[:raise, :fail, :return, :throw, :head, :redirect_to, :redirect_back,
    :redirect_back_or_to, :render].freeze

  def run_check
    @guarded_taint = {}

    tracker.find_call(:methods => [:[]=, :set_header, :merge!, :update], :nested => true).each do |result|
      process_result result
    end
  end

  def process_result result
    call = result[:call]

    case call.method
    when :[]=
      process_assignment result, call.target, call.first_arg, call.second_arg
    when :set_header
      process_set_header result, call
    when :merge!, :update
      process_merge result, call
    end
  end

  def process_assignment result, target, header_name, header_value
    return unless header_hash? target

    check_header_component result, header_name, :name
    check_header_component result, header_value, :value
  end

  def process_set_header result, call
    return unless response_target? call.target

    check_header_component result, call.first_arg, :name
    check_header_component result, call.second_arg, :value
  end

  def process_merge result, call
    return unless header_hash? call.target
    return unless hash? call.first_arg

    hash_iterate(call.first_arg) do |header_name, header_value|
      check_header_component result, header_name, :name
      check_header_component result, header_value, :value
    end
  end

  def check_header_component result, exp, component
    return unless sexp? exp
    return unless match = header_user_input?(exp)
    return if sanitized_expression? exp
    return if rejected_before_assignment? result, exp

    warn :result => result,
      :warning_type => "Response Splitting",
      :warning_code => :response_header_splitting,
      :message => msg(
        "Request parameter used in response header ",
        msg_lit(component.to_s),
        " without removing CR/LF characters"
      ),
      :code => result[:call],
      :user_input => match,
      :confidence => :weak,
      :cwe_id => [113]
  end

  #Finds request-controlled data reaching the expression. The default
  #BaseCheck matcher does not flag `request.env[...]` when it is nested, so
  #request header access is recognized explicitly here.
  def header_user_input? exp
    if match = include_user_input?(exp)
      match
    elsif request_value? exp
      Match.new(:request, exp)
    end
  end

  #Returns true when CR and LF characters are provably removed from the
  #expression before it reaches the header assignment.
  #
  #Sanitizing a different variable does not make an expression safe, so each
  #expression is examined on its own merits.
  def sanitized_expression? exp
    return false unless sexp? exp

    case exp.node_type
    when :str, :lit, :true, :false, :nil
      true
    when :dstr
      exp.each_sexp do |e|
        next unless sexp? e

        if node_type? e, :evstr
          return false unless sanitized_expression?(e.value)
        end
      end

      true
    when :if, :or
      branches_safe?(exp)
    when :call
      call_is_sanitized? exp
    when :array
      exp.all? { |e| !sexp?(e) or sanitized_expression?(e) }
    else
      false
    end
  end

  def branches_safe? exp
    if node_type? exp, :if
      (!sexp?(exp.then_clause) or sanitized_expression?(exp.then_clause)) and
        (!sexp?(exp.else_clause) or sanitized_expression?(exp.else_clause))
    else
      sanitized_expression?(exp.lhs) and sanitized_expression?(exp.rhs)
    end
  end

  def call_is_sanitized? call
    return false unless call? call

    method = call.method

    if NEWLINE_FILTERS.include? method
      newline_filter_chain_safe? call
    elsif method == :split
      false
    elsif method == :join
      split_join_safe? call
    elsif SAFE_STRING_METHODS.include? method
      target = call.target
      return true unless sexp?(target)
      sanitized_expression?(target)
    else
      false
    end
  end

  #Walk a chain of string filters from the outermost call down to the
  #original (possibly tainted) value. The chain is safe when every step
  #leaves no CR/LF: a single filter may remove both characters, or several
  #filters may combine to remove them (e.g. `gsub("\r", "").gsub("\n", "")`).
  def newline_filter_chain_safe? call
    removal = Set.new
    node = call

    while call?(node) and NEWLINE_FILTERS.include?(node.method)
      #For gsub/sub the second argument is the replacement string and must
      #not reintroduce CR/LF. Single-argument filters (delete/tr) take the
      #character set itself, so there is no replacement to check.
      if replacement_filter?(node.method)
        return false unless newline_free_literal?(node.last_arg)
      end

      step = filter_removal(node)
      return false if step.nil?

      removal.merge(step)

      if removal.include?(:cr) and removal.include?(:lf) and
          sanitized_input?(node.target)
        return true
      end

      node = node.target
    end

    false
  end

  def replacement_filter? method
    [:gsub, :gsub!, :sub, :sub!].include? method
  end

  #Characters removed by a single filter call. Returns nil when the filter
  #cannot be proven to remove at least one of CR/LF.
  def filter_removal call
    pattern = call.first_arg

    if string? pattern
      character_removal(pattern)
    elsif regexp_literal? pattern
      regexp_removal(pattern)
    end
  end

  def character_removal pattern
    return nil unless string? pattern

    removed = Set.new
    removed << :cr if pattern.value.include?("\r".freeze)
    removed << :lf if pattern.value.include?("\n".freeze)
    removed
  end

  def regexp_removal pattern
    return nil unless regexp_literal? pattern

    source = pattern.value.source
    removed = Set.new

    if source.include?("\\R".freeze) or source.include?("\\s".freeze) or
        source == ".*" or source == ".+"
      return Set[:cr, :lf]
    end

    removed << :cr if source.include?("\\r".freeze) or source.include?("\r".freeze)
    removed << :lf if source.include?("\\n".freeze) or source.include?("\n".freeze)
    removed
  end

  #`split` followed by `join` removes the separator strings, which is safe
  #as long as the split covers CR/LF.
  def split_join_safe? join_call
    target = join_call.target
    return false unless call? target and target.method == :split

    split_pattern = target.first_arg
    return false unless regexp_literal?(split_pattern) and regexp_covers_cr_and_lf?(split_pattern)
    return false unless newline_free_literal?(join_call.first_arg)

    split_target = target.target
    sanitized_input?(split_target)
  end

  #The expression feeding a filter may be tainted, but any methods wrapped
  #around it must be unable to reintroduce CR/LF characters.
  def sanitized_input? exp
    return true unless sexp? exp
    return true if request_value? exp

    if call? exp
      method = exp.method

      if method == :split
        return false
      elsif NEWLINE_FILTERS.include? method
        return newline_filter_chain_safe? exp
      elsif SAFE_STRING_METHODS.include? method
        return (!sexp?(exp.target) or sanitized_input?(exp.target))
      end
    end

    false
  end

  #String filters are safe when the literal argument contains both CR and LF.
  def covers_cr_and_lf? exp
    string?(exp) and exp.value.include?("\r".freeze) and exp.value.include?("\n".freeze)
  end

  def regexp_literal? exp
    node_type? exp, :lit and exp.value.is_a? Regexp
  end

  #Regexp filters are safe when the pattern matches CR, LF, any whitespace,
  #or any character at all.
  def regexp_covers_cr_and_lf? regexp_exp
    return false unless regexp_literal? regexp_exp

    source = regexp_exp.value.source

    source.include?("\\R".freeze) or
      source.include?("\\s".freeze) or
      (source.include?("\\r".freeze) and source.include?("\\n".freeze)) or
      (source.include?("\r".freeze) and source.include?("\n".freeze)) or
      source == ".*" or source == ".+"
  end

  #Replacement strings and join separators must not contain CR/LF.
  def newline_free_literal? exp
    return true if exp.nil?
    return true unless string? exp

    !exp.value.include?("\r".freeze) and !exp.value.include?("\n".freeze)
  end

  #Looks for a guard that rejects the request (raises, returns, renders an
  #error, etc.) when the tainted value contains CR/LF before the header
  #assignment is reached.
  def rejected_before_assignment? result, exp
    taint = tainted_base(exp)
    return false unless taint

    @guarded_taint ||= {}
    key = [result[:location][:file], result[:location][:method], taint, result[:call].line]
    return @guarded_taint[key] if @guarded_taint.key? key

    guarded = rejection_guard?(result, taint)
    @guarded_taint[key] = guarded
    guarded
  end

  #Find the request value whose taint reaches the expression. Comparing
  #against this exact expression (rather than any tainted variable) ensures
  #guards for other variables are not treated as protection.
  def tainted_base exp
    if match = has_immediate_user_input?(exp)
      match.match
    end
  end

  def rejection_guard? result, taint
    method_src = enclosing_method result
    return false unless method_src

    guarded = false

    method_src.each_sexp do |node|
      next unless node_type? node, :if

      condition = node.condition
      negated = negated_condition?(condition)
      condition = unwrap_negation(condition)

      next unless newline_test?(condition, taint)

      if explicit_reject_guard?(node, negated) or
          implicit_branch_guard?(node, negated, result[:call])
        guarded = true
      end
    end

    guarded
  end

  #A guard whose offending branch explicitly halts request processing.
  #
  #  raise "bad" if value =~ /[\r\n]/        #halt in then
  #  raise "bad" unless value !~ /[\r\n]/    #halt in else
  def explicit_reject_guard? node, negated
    halt_branch = negated ? node.else_clause : node.then_clause
    halting_branch? halt_branch
  end

  #The header assignment is itself inside a branch that is unreachable when
  #the value contains CR/LF, either because the test was negated:
  #
  #  if !(value =~ /[\r\n]/)
  #    response.headers["X"] = value
  #  end
  #
  #or the code used `unless`, which places the body in the else clause:
  #
  #  unless value.match?(/[\r\n]/)
  #    response.headers["X"] = value
  #  end
  def implicit_branch_guard? node, negated, sink
    branch = if negated or node.then_clause.nil?
               node.else_clause
             else
               node.then_clause
             end

    contains_call?(branch, sink)
  end

  def contains_call? exp, target_call
    return false unless sexp? exp
    return true if exp == target_call

    found = false
    exp.each_sexp do |node|
      found = true if node == target_call
    end
    found
  end

  #Negation is parsed either as a `:not` node or a call to `!`.
  def negated_condition? exp
    node_type?(exp, :not) or
      (node_type?(exp, :call) and exp.method == :! and sexp?(exp.target))
  end

  def unwrap_negation exp
    if node_type? exp, :not
      exp[1]
    elsif node_type?(exp, :call) and exp.method == :! and sexp?(exp.target)
      exp.target
    else
      exp
    end
  end

  def enclosing_method result
    location = result[:location]
    class_name = location[:class]
    method_name = location[:method]
    return unless class_name and method_name

    method_info = tracker.find_method(method_name, class_name)
    method_info&.src
  end

  #Matches checks such as:
  #
  #  value =~ /[\r\n]/
  #  value.match?(/[\r\n]/)
  #  value.include?("\r\n")
  def newline_test? condition, taint
    newline_test_coverage(condition, taint) == Set[:cr, :lf]
  end

  #Returns the set of newline characters (:cr, :lf) proven to be detected by
  #the condition for the given tainted value.
  def newline_test_coverage condition, taint
    return Set.new unless sexp? condition

    if condition.node_type == :match3
      #s(:match3, regexp, value) for `value =~ regexp`
      condition[2] == taint ? regexp_coverage(condition[1]) : Set.new
    elsif call? condition
      target = condition.target

      case condition.method
      when :=~, :match, :match?
        sexp?(target) and target == taint ? regexp_coverage(condition.first_arg) : Set.new
      when :include?, :exclude?
        if sexp?(target) and target == taint and string?(condition.first_arg)
          string_coverage(condition.first_arg)
        else
          Set.new
        end
      else
        Set.new
      end
    elsif condition.node_type == :or
      #Either branch matching is enough, so their coverage is combined.
      newline_test_coverage(condition.lhs, taint) |
        newline_test_coverage(condition.rhs, taint)
    elsif condition.node_type == :and
      #Both branches hold, so only coverage guaranteed by each one counts.
      newline_test_coverage(condition.lhs, taint) &
        newline_test_coverage(condition.rhs, taint)
    else
      Set.new
    end
  end

  def regexp_coverage pattern
    return Set.new unless regexp_literal? pattern

    source = pattern.value.source

    if source.include?("\\R".freeze) or source.include?("\\s".freeze) or
        source == ".*" or source == ".+"
      return Set[:cr, :lf]
    end

    coverage = Set.new
    coverage << :cr if source.include?("\\r".freeze) or source.include?("\r".freeze)
    coverage << :lf if source.include?("\\n".freeze) or source.include?("\n".freeze)
    coverage
  end

  def string_coverage pattern
    coverage = Set.new
    coverage << :cr if pattern.value.include?("\r".freeze)
    coverage << :lf if pattern.value.include?("\n".freeze)
    coverage
  end

  #A branch halts request processing when it raises, returns, or explicitly
  #responds (head/render/redirect), including `head(...) and return` style
  #guards.
  def halting_branch? exp
    return false unless sexp? exp

    case exp.node_type
    when :call
      HALT_METHODS.include?(exp.method) or
        (call?(exp.target) and HALT_METHODS.include?(exp.target.method))
    when :return
      true
    when :and, :or
      halting_branch?(exp.lhs) or halting_branch?(exp.rhs)
    when :if
      halting_branch?(exp.then_clause) or
        (sexp?(exp.else_clause) and halting_branch?(exp.else_clause))
    when :block
      exp.each_sexp.any? { |e| halting_branch? e }
    else
      false
    end
  end

  #Only the actual response header hash is a sink. Request headers and
  #arbitrary user hashes are not treated as response headers, and matching is
  #structural rather than by generalizing over same-named methods.
  def header_hash? exp
    return false unless sexp? exp
    return false unless call? exp
    return false unless exp.method == :headers

    target = exp.target
    target.nil? or response_target? target
  end

  #Matches `response` (including an aliased call resolved back to it), but
  #not other objects that happen to expose a same-named method.
  def response_target? exp
    sexp?(exp) and call?(exp) and exp.method == :response
  end
end
