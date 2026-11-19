require 'brakeman/checks/base_check'

# JSONP responses wrap an encoded JSON payload in a caller-controlled
# callback expression: `callback(payload)`. Correctly encoding the JSON
# body does not make the response safe, because the callback name is emitted
# verbatim as executable JavaScript.
#
# This check follows the actual callback expression through the render
# `:callback` option, merged option hashes, and helper method return values.
# A callback is only trusted when it is a fixed name or is provably drawn
# from a finite set of literal names. Arbitrary user text - including input
# that only had a few characters filtered, or that is concatenated back into
# a larger string - is reported.
class Brakeman::CheckJSONPCallback < Brakeman::BaseCheck
  Brakeman::Checks.add self

  @description = "Checks JSONP render calls for an unsafe callback name"

  # Methods that do not change the set of values an expression can take.
  # Unlike filters such as +gsub+, these cannot be used to launder input.
  PRESERVING_METHODS = Set[:freeze, :dup, :to_str, :to_sym].freeze

  def run_check
    tracker.find_call(:target => nil, :method => :render).each do |result|
      check_render result
    end
  end

  def check_render result
    return unless original? result

    call = result[:call]
    return unless node_type? call, :render

    options = json_render_options call
    return unless options

    callback = hash_access(options, :callback)
    return unless callback and sexp? callback

    callback = resolve_callback callback, result

    return if provably_safe_callback? callback

    input = callback_input callback

    warn :result => result,
      :warning_type => "Cross-Site Scripting",
      :warning_code => :jsonp_callback,
      :message => msg("JSONP callback is not a fixed or allowlisted name (", msg_input(input), ")"),
      :user_input => input,
      :code => callback,
      :link_path => "jsonp_callback",
      :confidence => confidence_for(input),
      :cwe_id => [79]
  end

  # Returns the options hash for a JSON-producing render, or nil when the
  # render is not a JSON render.
  #
  # Handles both `render json: x, callback: cb` (render type `:json`) and a
  # positional options hash such as `render some_hash.merge(json: x, ...)`,
  # which the parser leaves as render type `:action` with the hash in the
  # value slot.
  def json_render_options call
    return call[3] if call.render_type == :json

    candidate = call[2]

    return candidate if hash?(candidate) and hash_access(candidate, :json)

    nil
  end

  # Follow helper method calls down to the expression they return so the
  # classification is based on the real callback rather than the method name.
  def resolve_callback callback, result
    visited = Set.new

    while bare_method_call? callback
      method_name = callback.method
      break if visited.include? method_name

      found = tracker.find_method(method_name, result[:location][:class])
      break unless found

      visited << method_name
      return_value = Brakeman::FindReturnValue.return_value found.src
      return callback unless sexp? return_value

      callback = return_value
    end

    callback
  end

  def bare_method_call? exp
    return false unless call? exp and exp.args.empty?

    exp.target.nil? or node_type?(exp.target, :self)
  end

  # A callback is provably safe when every value it can evaluate to is a
  # fixed literal name or a member of a finite literal collection.
  def provably_safe_callback? exp
    return true if safe_literal? exp

    case exp.node_type
    when :str, :lit
      true
    when :true, :false, :nil
      true
    when :array
      exp.length > 1 and exp.all? { |e| sexp?(e) && provably_safe_callback?(e) }
    when :dstr
      safe_interpolation? exp
    when :or
      provably_safe_callback?(exp.lhs) and provably_safe_callback?(exp.rhs)
    when :if
      (!sexp?(exp.then_clause) || provably_safe_callback?(exp.then_clause)) and
        (!sexp?(exp.else_clause) || provably_safe_callback?(exp.else_clause))
    when :call
      provably_safe_call? exp
    else
      false
    end
  end

  # An interpolated string is safe when every interpolated expression is
  # itself provably constrained. The literal segments of a `:dstr` are just
  # strings and cannot introduce taint.
  def safe_interpolation? exp
    exp.each_sexp do |segment|
      next unless node_type? segment, :evstr

      value = segment.value
      return false unless sexp?(value) and provably_safe_callback?(value)
    end

    true
  end

  def provably_safe_call? exp
    method = exp.method

    if PRESERVING_METHODS.include? method
      target = exp.target
      return sexp?(target) && provably_safe_callback?(target)
    end

    finite_collection_method?(method, exp.target)
  end

  # `[:a, :b].sample`, `NAMES.first`, and friends only ever yield one of the
  # literal members of the underlying collection.
  def finite_collection_method? method, target
    return false unless [:sample, :first, :last, :min, :max, :shift].include? method
    return false unless literal_array? target

    target.sexp_body.all? { |e| provably_safe_callback? e }
  end

  def literal_array? exp
    node_type? exp, :array and exp.length > 1
  end

  # Identify the untrusted source that actually reaches the callback so the
  # warning points at the callback source instead of the JSON payload.
  def callback_input callback
    if match = has_immediate_user_input?(callback)
      match
    elsif match = include_user_input?(callback)
      match
    elsif model = has_immediate_model?(callback)
      Match.new(:model, model)
    else
      Match.new(:generic, callback)
    end
  end

  def confidence_for input
    if input.type == :params or input.type == :cookies or input.type == :request
      :high
    else
      :medium
    end
  end
end
