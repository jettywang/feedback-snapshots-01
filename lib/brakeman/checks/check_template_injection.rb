require 'brakeman/checks/base_check'
require 'brakeman/processors/lib/find_return_value'

# Checks for dynamic template *source code* being compiled by a known template
# engine and then executed.
#
# This is not a text search for +ERB.new+. It distinguishes the template source
# (the first argument, which is compiled as code) from template variables
# (binding/+result_with_hash+ arguments, which are merely data), tracks the
# aliases of the compiled object to determine whether it is ever executed, and
# follows helper methods that compile or render the template.
class Brakeman::CheckTemplateInjection < Brakeman::BaseCheck
  Brakeman::Checks.add self

  @description = "Searches for execution of user input used as dynamic template source"

  # Known template engines and the methods that compile template *source*
  # into an executable template object. Namespaced engines are indexed by
  # Brakeman using their fully-qualified target symbol (e.g. +:"Haml::Engine"+).
  TEMPLATE_FACTORIES = {
    :ERB => [:new],
    :Erubi => [:new],
    :Erubis => [:new],
    :"Haml::Engine" => [:new, :compile],
    :"Slim::Template" => [:new, :compile],
  }.freeze

  # Methods that execute a previously compiled template object.
  EXECUTION_METHODS = [:result, :result_with_hash, :result_with_binding, :render].freeze

  # Methods that only produce HTML-escaped text. Escaping data for HTML output
  # does not make a string safe to use as template *language* source, so these
  # are never treated as sanitizers for the template source.
  HTML_ESCAPE_METHODS = [:html_escape, :h, :escape_once, :encode_html_entities].freeze

  #Limit on how many helper methods are resolved while following the flow of
  #the template source / compiled object. Factories whose flow cannot be
  #resolved stay uncovered instead of being reported on speculation.
  MAX_HELPER_DEPTH = 3

  #Process calls
  def run_check
    Brakeman.debug "Finding dynamic template compilation calls"

    factory_calls.each do |result|
      process_compilation result
    end
  end

  private

  def factory_calls
    calls = []

    TEMPLATE_FACTORIES.each do |engine, methods|
      tracker.find_call(:target => engine, :method => methods, :nested => true).each do |result|
        calls << result
      end
    end

    calls
  end

  def process_compilation result
    return unless original? result

    call = result[:call]
    template_source = call.first_arg

    #Constant template source is not controllable by the request, so it is
    #never a template injection issue regardless of how it is executed.
    return if safe_source? template_source

    input = tainted_source? result, template_source, 0

    #No request-derived data reaches the template source. Unknown/dynamic
    #factories stay uncovered instead of being reported on speculation.
    return unless input

    if executed? result, call
      warn_about result, input, true
    else
      #The object is constructed from request-controlled source but no
      #execution of it is observable, so report at lower confidence.
      warn_about result, input, false
    end
  end

  #Returns a user-input Match when +source+ can be influenced by the request,
  #following helper method parameters when the source is a method argument.
  def tainted_source? result, source, depth
    return false if depth > MAX_HELPER_DEPTH
    return false unless sexp? source

    if input = include_user_input?(source)
      return input
    end

    #HTML escaping only neutralizes HTML metacharacters for output; it does not
    #make the value safe to interpret as template language source. Look through
    #the escaping wrapper to the underlying request value.
    if html_escape_call?(source) and (inner = source.first_arg) and sexp?(inner)
      return tainted_source?(result, inner, depth)
    end

    #The source is a method parameter. Resolve the enclosing helper and check
    #what its callers pass in that argument position.
    if source.node_type == :lvar or source.node_type == :arg
      method_def = method_definition(result)

      if method_def and position = argument_position(method_def, source)
        return taint_from_callers(result, method_def, position, depth)
      end
    end

    false
  end

  def html_escape_call? exp
    call?(exp) and HTML_ESCAPE_METHODS.include?(exp.method)
  end

  #Finds a tainted value passed to +method_def+ in the given argument position
  #across every known call site.
  def taint_from_callers result, method_def, position, depth
    method_name = method_def.src.method_name

    tracker.find_call(:method => method_name, :nested => true).each do |caller_result|
      next if caller_result[:location] == result[:location]

      argument = caller_result[:call].args[position]
      next unless sexp? argument

      if input = tainted_source?(caller_result, argument, depth + 1)
        return input
      end
    end

    false
  end

  def method_definition result
    location = result[:location]
    return nil unless location[:class] and location[:method]

    resolve_method location[:method], location[:class]
  end

  #Resolves a method whether it is an instance method or a class method.
  def resolve_method method_name, class_name
    tracker.find_method(method_name, class_name, :instance) ||
      tracker.find_method(method_name, class_name, :class)
  end

  def argument_position method_def, variable
    args = method_def.src.formal_args
    return nil unless args

    args.sexp_body.each_with_index do |arg, index|
      #Ordinary arguments are plain symbols; keyword/optional arguments are
      #represented as nested assignment Sexps.
      arg_name =
        if arg.is_a? Symbol
          arg
        elsif sexp?(arg) and arg.respond_to?(:lhs)
          arg.lhs
        end

      return index if arg_name == variable.value
    end

    nil
  end

  #A template source is only considered safe when it is provably a constant
  #string or another pure literal. HTML escaping of user data is explicitly
  #not treated as making the source safe.
  def safe_source? exp
    return true unless sexp? exp

    case exp.node_type
    when :str
      true
    when :lit
      #A symbol or numeric literal is harmless as template source, but other
      #:+lit+ objects cannot be assumed safe.
      exp[1].is_a?(Symbol) or exp[1].is_a?(Numeric)
    when :dstr
      exp.all? { |part| safe_dstr_part? part }
    else
      false
    end
  end

  def safe_dstr_part? part
    return true if part.is_a? String
    return false unless sexp? part

    case part.node_type
    when :str
      true
    when :evstr
      value = part.value
      sexp?(value) and value.node_type == :lit and (value[1].is_a?(Symbol) or value[1].is_a?(Numeric))
    else
      false
    end
  end

  #Determines whether the compiled object is ever executed. Returns true when
  #an execution call is observed directly, through a provable alias, or after
  #the object flows back from a helper method; false when it is only built.
  def executed? result, factory_call
    #1. Direct chain in the same expression: ERB.new(...).result
    full = result[:full_call] && result[:full_call][:call]
    if call?(full) and EXECUTION_METHODS.include?(full.method) and full.target == factory_call
      return true
    end

    #2. A provable alias of the compiled object (local/instance/global/class
    #variable) is passed to an execution method in the same method body.
    method_src = enclosing_method_src result
    if method_src and find_execution_of(method_src, factory_call)
      return true
    end

    #3. The compiled object is returned by a helper; look for a caller that
    #executes that helper's result (up to MAX_HELPER_DEPTH layers deep).
    if method_src and helper_name = returned_by_helper?(result, method_src)
      return true if helper_result_executed?(result, helper_name, 0)
    end

    false
  end

  def enclosing_method_src result
    method = method_definition result
    method && method.src
  end

  #Searches a method body for an execution method invoked on an expression the
  #alias processor can prove is the same compiled object.
  def find_execution_of method_src, factory_call
    @execution_matches ||= {}
    key = [method_src.object_id, factory_call]
    return @execution_matches[key] if @execution_matches.key?(key)

    processor = Brakeman::AliasProcessor.new tracker
    resolved = processor.process_safely method_src.deep_clone

    found = nil
    each_call(resolved) do |call|
      if EXECUTION_METHODS.include?(call.method) and call.target == factory_call
        found = call
        break
      end
    end

    @execution_matches[key] = found
  end

  #Walks every call Sexp in a tree.
  def each_call exp, &block
    return unless sexp? exp

    yield exp if call? exp

    exp.each do |child|
      each_call child, &block if sexp? child
    end
  end

  #Returns the helper method name when the factory result is the (explicit or
  #implicit) return value of the enclosing method.
  def returned_by_helper? result, method_src
    return_value = Brakeman::FindReturnValue.return_value method_src.deep_clone

    if references_call?(return_value, result[:call])
      method_src.method_name
    end
  end

  def references_call? exp, target_call
    return false unless sexp? exp

    if call? exp and exp == target_call
      return true
    end

    exp.each do |child|
      return true if sexp?(child) and references_call?(child, target_call)
    end

    false
  end

  #Looks for callers of +helper_name+ that execute its result, recursing
  #through another helper layer when that helper itself returns its result.
  def helper_result_executed? result, helper_name, depth
    return false if depth >= MAX_HELPER_DEPTH

    tracker.find_call(:method => helper_name, :nested => true).any? do |caller_result|
      next false if caller_result[:location] == result[:location]

      caller_call = caller_result[:call]
      full = caller_result[:full_call] && caller_result[:full_call][:call]

      #The helper's return value is executed directly: compile(x).result
      if call?(full) and EXECUTION_METHODS.include?(full.method) and full.target == caller_call
        next true
      end

      #The helper's result is stored in a provable alias that is then executed.
      caller_src = enclosing_method_src caller_result
      if caller_src and find_execution_of(caller_src, caller_call)
        next true
      end

      #The helper's result is passed as an argument to another method. If that
      #receiving method executes the corresponding parameter (or returns it for
      #a caller to execute), follow the object one more layer.
      if passed_to_executing_helper?(caller_result, caller_call, depth)
        next true
      end

      #Another helper layer: the helper result itself is returned again, so the
      #compiled object keeps flowing upward toward an execution call.
      if caller_src and next_helper = returned_by_helper?(caller_result, caller_src)
        next true if helper_result_executed?(caller_result, next_helper, depth + 1)
      end

      false
    end
  end

  #Handles +renderer(compile(x))+ where the compiled object is handed to a
  #helper that executes the matching parameter.
  def passed_to_executing_helper? caller_result, helper_call, depth
    parent = caller_result[:parent]
    return false unless parent and call?(parent[:call])

    receiver_call = parent[:call]
    position = receiver_call.args.index(helper_call)
    return false unless position

    receiver_def = resolve_method(receiver_call.method, caller_result[:location][:class])
    return false unless receiver_def

    parameter_name = formal_arg_name(receiver_def, position)
    return false unless parameter_name

    parameter_variable = Sexp.new(:lvar, parameter_name)

    #The receiving method executes the parameter directly, e.g. +t.result+.
    if find_execution_of(receiver_def.src, parameter_variable)
      return true
    end

    #Or it returns that parameter, so continue following the object upward.
    return_value = Brakeman::FindReturnValue.return_value receiver_def.src.deep_clone
    if references_call?(return_value, parameter_variable)
      return helper_result_executed?(
        { :location => caller_result[:location].merge(:method => receiver_call.method) },
        receiver_call.method,
        depth + 1
      )
    end

    false
  end

  def formal_arg_name method_def, position
    arg = method_def.src.formal_args.sexp_body[position]

    if arg.is_a? Symbol
      arg
    elsif sexp?(arg) and arg.respond_to?(:lhs)
      arg.lhs
    end
  end

  def warn_about result, input, executed
    confidence = executed ? :high : :medium

    message =
      if executed
        msg(msg_input(input), " used as dynamic template source and executed")
      else
        msg(msg_input(input), " used as dynamic template source, but no execution of the compiled template was found")
      end

    warn :result => result,
      :warning_type => "Template Injection",
      :warning_code => :erb_template_injection,
      :message => message,
      :user_input => input,
      :confidence => confidence,
      :cwe_id => [1336]
  end
end
