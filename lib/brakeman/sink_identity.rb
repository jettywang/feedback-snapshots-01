require 'set'
require 'brakeman/util'

# Builds a stable description of the dangerous expression (the "sink") for a
# warning.  The description deliberately ignores whitespace, line numbers and
# the concrete value of user-input sources: the same sink reached through two
# render paths or two data-flow paths must keep one identity.  Call targets,
# method names, literals and non-source arguments are retained, so two
# genuinely different sinks remain different.
module Brakeman::SinkIdentity
  extend Brakeman::Util

  SOURCE_NODE_TYPES = Set.new([:params, :cookies, :session])

  # Struct-free evidence entry used by Warning#evidence.  A Hash-like object
  # keeps JSON output straightforward while still allowing `e.type`/`e.code`.
  Evidence = Struct.new(:type, :code, :line, keyword_init: true) do
    def to_h
      { :type => type.to_s, :code => code, :line => line }
    end

    def == other
      other.respond_to?(:to_h) && to_h == other.to_h
    end
    alias eql? ==

    def hash
      to_h.hash
    end
  end

  class << self
    # Returns the source type when +exp+ itself is a direct user-input access.
    # We intentionally do not walk nested calls here: callers use this to stop
    # descending so `params[:a] + params[:b]` yields two evidence entries
    # instead of one opaque expression.
    def source_type exp
      return unless exp.is_a? Sexp

      if SOURCE_NODE_TYPES.include? exp.node_type
        return exp.node_type
      end

      return unless call? exp

      target = exp.target

      if params_target? target
        :params
      elsif cookies_target? target
        :cookies
      elsif target == SESSION
        :session
      elsif request_headers? exp
        :request
      end
    end

    def params_target? target
      source_target?(target, :params)
    end

    def cookies_target? target
      source_target?(target, :cookies)
    end

    def source_target? target, type = nil
      return false unless target.is_a? Sexp

      case target.node_type
      when :params
        type.nil? || type == :params
      when :cookies
        type.nil? || type == :cookies
      when :call, :safe_call
        if type == :params
          ALL_PARAMETERS.include?(target)
        elsif type == :cookies
          ALL_COOKIES.include?(target)
        else
          ALL_PARAMETERS.include?(target) || ALL_COOKIES.include?(target)
        end
      else
        false
      end
    end

    # Collect every direct source in +exp+.  Nested transformations such as
    # `params[:a].to_s` are walked so the evidence is the source access rather
    # than the whole chain.
    def collect_sources exp, list = []
      return list unless exp.is_a? Sexp

      if type = source_type(exp)
        list << [type, exp]
        return list
      end

      exp.each do |child|
        collect_sources child, list
      end

      list
    end

    # Canonical, line-independent representation of an expression.
    def normalize exp
      case exp
      when Sexp
        if type = source_type(exp)
          # Two render paths may resolve the same `@user` to different
          # parameters.  To keep one identity for that sink, only the source
          # kind is significant here, not the concrete key.  Distinct calls are
          # separated by scope/line/occurrence instead.
          [:source, type]
        else
          normalize_sexp exp
        end
      when Array
        [:array_data, *exp.map { |e| normalize(e) }]
      when Symbol, String, Numeric, NilClass, TrueClass, FalseClass
        exp
      when Regexp
        [:regexp, exp.source, exp.options]
      else
        exp.class.name
      end
    end

    def signature exp
      return "" if exp.nil?

      normalize(exp).inspect
    end

    # Like #signature, but retains concrete source keys.  Used to tell two
    # real calls on the same line apart; never used for cross-path identity.
    def exact_signature exp
      return "" if exp.nil?

      exact_normalize(exp).inspect
    end

    def format_code exp
      return nil if exp.nil?

      Brakeman::OutputProcessor.new.format(exp).gsub(/(\t|\r|\n)+/, " ")
    rescue StandardError
      begin
        exp.inspect.gsub(/(\t|\r|\n)+/, " ")
      rescue StandardError
        exp.to_s
      end
    end

    private

    def exact_normalize exp
      case exp
      when Sexp
        [exp.node_type, *exp.map { |e| exact_normalize(e) }]
      when Array
        [:array_data, *exp.map { |e| exact_normalize(e) }]
      when Symbol, String, Numeric, NilClass, TrueClass, FalseClass
        exp
      when Regexp
        [:regexp, exp.source, exp.options]
      else
        exp.class.name
      end
    end

    def normalize_sexp exp
      case exp.node_type
      when :ivar, :lvar, :gvar, :cvar
        [:variable, exp.node_type]
      when :const, :colon3
        [:const, exp.value]
      when :colon2
        [:colon2, normalize(exp.lhs), exp.rhs]
      when :lit, :str, :sym
        [exp.node_type, exp.value]
      else
        [exp.node_type, *exp.map { |e| normalize(e) }]
      end
    end
  end
end
