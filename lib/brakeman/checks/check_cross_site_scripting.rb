require 'brakeman/checks/base_check'
require 'brakeman/processors/lib/find_call'
require 'brakeman/processors/lib/processor_helper'
require 'brakeman/util'
require 'brakeman/template_context'
require 'set'

#This check looks for unescaped output in templates which contains
#parameters or model attributes.
#
#For example:
#
# <%= User.find(:id).name %>
# <%= params[:id] %>
class Brakeman::CheckCrossSiteScripting < Brakeman::BaseCheck
  Brakeman::Checks.add self

  @description = "Checks for unescaped output in views"

  #Model methods which are known to be harmless
  IGNORE_MODEL_METHODS = Set[:average, :count, :maximum, :minimum, :sum, :id]

  MODEL_METHODS = Set[:all, :find, :first, :last, :new]

  IGNORE_LIKE = /^link_to_|(_path|_tag|_url)$/

  # Methods that escape HTML characters in a plain String. They are enough
  # to keep a value inside a quoted JavaScript string, but not enough in
  # expression position.
  HTML_ESCAPE_METHODS = Set[:escapeHTML, :escape_once, :h, :html_escape,
                            :html_escape_without_haml_xss, :u, :url_encode]

  # Methods that return an HTML-safe buffer (sanitized or otherwise). They
  # bypass the template engine's escaping.
  HTML_SAFE_METHODS = Set[:raw, :html_safe, :html_safe!, :sanitize,
                          :strip_tags, :content_tag, :tag, :link_to, :safe_join]

  HAML_HELPERS = Sexp.new(:colon2, Sexp.new(:const, :Haml), :Helpers)

  XML_HELPER = Sexp.new(:colon2, Sexp.new(:const, :Erubis), :XmlHelper)

  URI = Sexp.new(:const, :URI)

  CGI = Sexp.new(:const, :CGI)

  FORM_BUILDER = Sexp.new(:call, Sexp.new(:const, :FormBuilder), :new)

  def initialize *args
    super
    @matched = @mark = false
  end

  #Run check
  def run_check
    setup

    tracker.each_template do |name, template|
      Brakeman.debug "Checking #{name} for XSS"

      @current_template = template

      template.each_output do |out|
        context = out.respond_to?(:output_context) ? out.output_context : nil

        if script_context? context
          # For script contexts, evaluate HTML escaping and JavaScript
          # escaping separately instead of reusing the HTML output rules.
          check_script_output out, context
        else
          unless check_for_immediate_xss out
            @matched = false
            @mark = false
            process out
          end
        end
      end
    end
  end

  def script_context? context
    Brakeman::TemplateContext.script? context
  end

  # Analysis of a value being emitted into a script context.
  #
  # +chain+ records the conversions applied between the user input and the
  # actual output location, for example [:helper(foo), :html_safe, :to_json].
  ScriptAnalysis = Struct.new(:input, :chain, :js_escaped, :html_safe,
                              :html_escaped, :json, :unknown, :engine_escaped)

  # Check an output expression whose surrounding template text places it in
  # a script (not HTML) context.
  def check_script_output out, context
    return if duplicate? out

    analysis = analyze_script_value out.value

    # Some template engines unwrap j/raw/html_safe before recording the
    # output value. Merge the conversions observed at the insertion point.
    apply_output_flags analysis, out

    # Whether the template engine HTML-escaped this value for us. This is
    # what makes ordinary output safe in an HTML node or a quoted string but
    # not in a JavaScript expression.
    analysis.engine_escaped = out.node_type == :escaped_output

    unless analysis.input
      return
    end

    return if script_safe? analysis, context

    add_result out

    message = script_warning_message(analysis, context)

    warn :template => @current_template,
      :warning_type => "Cross-Site Scripting",
      :warning_code => :cross_site_scripting,
      :message => message,
      :code => out.value,
      :user_input => analysis.input,
      :confidence => script_confidence(analysis),
      :link_path => "cross_site_scripting",
      :cwe_id => [79]
  end

  def apply_output_flags analysis, out
    flags = out.respond_to?(:output_flags) ? out.output_flags : nil
    return unless flags and flags.any?

    analysis.js_escaped ||= flags.include? :js_escaped
    analysis.html_safe ||= flags.include? :html_safe
    analysis.html_escaped ||= flags.include? :html_escaped
    analysis.json ||= flags.include? :json
  end

  def content_tag_method? method
    method == :content_tag or method == :tag or method == :link_to or method == :safe_join
  end

  def script_confidence analysis
    # An unresolved call could return a plain String (escaped by the
    # template engine) or a SafeBuffer, so only report it at medium when it
    # appears in the conversion chain.
    if analysis.unknown and analysis.chain.any?
      :medium
    else
      :high
    end
  end

  def script_warning_message analysis, context
    context_name = case context
                   when Brakeman::TemplateContext::SCRIPT_STRING
                     "JavaScript string"
                   when Brakeman::TemplateContext::SCRIPT_TEMPLATE
                     "JavaScript template literal"
                   when Brakeman::TemplateContext::SCRIPT_EXPRESSION
                     "JavaScript expression"
                   when Brakeman::TemplateContext::JSON, Brakeman::TemplateContext::JSON_STRING
                     "JSON data"
                   else
                     "script context"
                   end

    message = msg("Unescaped ", msg_input(script_input_type(analysis.input)),
                  " in ", context_name)

    details = script_warning_details(analysis, context)
    message << msg_plain(" (#{details})") unless details.empty?

    message
  end

  # Describe the conversion chain from input to output so a finding points to
  # the actual transformation that was insufficient.
  def script_warning_details analysis, context
    details = []

    if analysis.chain.any?
      chain = analysis.chain.map(&:to_s).join(" -> ")
      details << "via #{chain}"
    end

    if analysis.chain.include?(:escape_javascript) and
       (context == Brakeman::TemplateContext::SCRIPT_EXPRESSION or
        context == Brakeman::TemplateContext::SCRIPT_TEMPLATE)
      details << "`escape_javascript` only escapes JavaScript string contents"
    elsif context == Brakeman::TemplateContext::SCRIPT_TEMPLATE
      details << "template literals require escaping backticks and `${`"
    elsif analysis.html_safe and not analysis.json
      details << "HTML-safe output is not JavaScript-safe"
    end

    details.join("; ")
  end

  # The script check reports the value itself, not a @matched Match, so
  # derive the same user-input wording used by the HTML check.
  def script_input_type input
    if params?(input)
      Match.new(:params, input)
    elsif cookies?(input)
      Match.new(:cookies, input)
    elsif request_headers?(input)
      Match.new(:request, input)
    else
      Match.new(:model, input)
    end
  end

  # Decide whether the value is safe at the insertion point.
  #
  # The template engine HTML-escapes ordinary output. Inside an HTML node or
  # a quoted JavaScript string, that is enough to keep the value from
  # changing the surrounding markup or ending the string. Inside a
  # JavaScript expression it is not enough: characters such as `;`, `(` and
  # letters are untouched by HTML escaping, so attacker-controlled text is
  # still JavaScript source.
  #
  # Values marked HTML-safe (`raw`, `html_safe`, helpers returning SafeBuffer,
  # and `j`, whose result is a SafeBuffer) bypass the engine's escaping, so
  # only their own conversions count.
  def script_safe? analysis, context
    outer = outer_conversion analysis
    json_ok = analysis.json and json_escaped?

    case context
    when Brakeman::TemplateContext::SCRIPT_STRING
      # Inside a quoted JavaScript string the value must not be able to end
      # the string. j escapes quotes, HTML-escaping helpers encode them, and
      # JSON serialization escapes them too. Engine escaping covers ordinary
      # output. HTML-safe output without any of those can end the string.
      return true if outer == :escape_javascript
      return true if analysis.html_escaped
      return true if HTML_ESCAPE_METHODS.include? outer
      return true if json_ok
      return true if plain_engine_escaped? analysis

      false

    when Brakeman::TemplateContext::SCRIPT_TEMPLATE
      # Template literals also require escaping backticks and `${`. None of
      # the conversions tracked here do that.
      false

    when Brakeman::TemplateContext::SCRIPT_EXPRESSION
      # Engine-escaped text and j-escaped string contents are still
      # JavaScript source here. Serialized JSON is data and inert when its
      # HTML entities are escaped. j must not be the outermost call because
      # it turns JSON into string contents.
      json_ok and outer != :escape_javascript

    when Brakeman::TemplateContext::JSON
      # JSON value position. Serialized JSON is inert; j-escaped values are
      # string data. Engine-escaped plain output cannot close the script
      # element, although it may not be valid JSON.
      return true if json_ok and outer != :escape_javascript
      return true if outer == :escape_javascript
      return true if plain_engine_escaped? analysis

      false

    when Brakeman::TemplateContext::JSON_STRING
      return true if json_ok and outer != :escape_javascript
      return true if outer == :escape_javascript
      return true if HTML_ESCAPE_METHODS.include? outer
      return true if plain_engine_escaped? analysis

      false

    else
      # The template does not determine the context. Do not claim the value
      # is safe, but do not guess at a warning either.
      true
    end
  end

  # The outermost conversion that applies to the emitted value. The chain is
  # ordered from the output expression inwards. Helper markers are not
  # conversions; the conversion inside the helper is the outermost one from
  # the caller's perspective. Marking a value HTML-safe does not change
  # characters, although it does stop the engine escaping it.
  def outer_conversion analysis
    analysis.chain.find do |step|
      name = step.to_s
      !(name.start_with?("helper(") or name.start_with?("opaque_helper(") or
        name.start_with?("unknown(") or
        name == "html_safe")
    end
  end

  # Ordinary output that the template engine itself HTML-escaped and that
  # nothing marked HTML-safe afterwards.
  def plain_engine_escaped? analysis
    analysis.engine_escaped and not analysis.html_safe and not analysis.unknown
  end

  # Whether to_json output is HTML-entity escaped. Computed in #setup from
  # the same configuration used for the existing to_json handling.
  def json_escaped?
    @json_escaped
  end

  # Walk the output expression and record the conversions applied to the
  # value: j/escape_javascript, raw/html_safe, to_json, HTML escaping, and
  # helper return values.
  def analyze_script_value exp, seen = Set.new, depth = 0
    analysis = ScriptAnalysis.new(nil, [], false, false, false, false, false, false)

    analyze_script_expression exp, analysis, seen, depth

    unless analysis.input
      analysis.input = find_script_input(exp)
    end

    analysis.input = analysis.input.match if analysis.input.is_a? Match
    analysis
  end

  # Find request/model input even when wrapped in calls whose meaning is not
  # known, e.g. j(params[:x]) or a helper that simply returns its argument.
  def find_script_input exp, depth = 0
    return unless sexp? exp
    return if depth > 12

    input = has_immediate_user_input?(exp)
    input ||= has_immediate_model?(exp) unless tracker.options[:ignore_model_output]
    return input if input

    case exp.node_type
    when :call, :safe_call
      found = find_script_input(exp.target, depth + 1)
      return found if found

      exp.each_arg do |arg|
        found = find_script_input(arg, depth + 1)
        return found if found
      end
      nil
    when :dstr, :evstr, :if, :or, :and
      exp.each do |child|
        next unless sexp?(child)
        found = find_script_input(child, depth + 1)
        return found if found
      end
      nil
    else
      nil
    end
  end

  def analyze_script_expression exp, analysis, seen, depth
    return unless sexp? exp
    return if depth > 8

    case exp.node_type
    when :call, :safe_call
      method = exp.method
      target = exp.target

      if method == :j or method == :escape_javascript
        analysis.chain << :escape_javascript
        analysis.js_escaped = true
        analyze_script_expression exp.first_arg, analysis, seen, depth + 1
      elsif method == :raw
        analysis.chain << :raw
        analysis.html_safe = true
        analyze_script_expression exp.first_arg, analysis, seen, depth + 1
      elsif method == :html_safe or method == :html_safe!
        analysis.chain << :html_safe
        analysis.html_safe = true
        analyze_script_expression target, analysis, seen, depth + 1
      elsif method == :to_json or method == :encode
        analysis.chain << :to_json
        analysis.json = true
        analyze_script_expression target, analysis, seen, depth + 1
      elsif HTML_ESCAPE_METHODS.include? method
        analysis.chain << method
        analysis.html_escaped = true
        analyze_script_expression(target || exp.first_arg, analysis, seen, depth + 1)
      elsif method == :to_s or method == :strip or method == :freeze
        analyze_script_expression target, analysis, seen, depth + 1
      elsif content_tag_method? method
        analysis.chain << method
        analysis.html_escaped = true
        analysis.html_safe = true
      elsif HTML_SAFE_METHODS.include? method
        analysis.chain << method
        analysis.html_safe = true
      elsif helper = find_helper_method(method) and not seen.include?(method)
        seen = seen.dup.add(method)
        value = helper_return_value(helper, exp)

        analysis.chain << :"helper(#{method})"

        unless sexp? value and analyze_helper_value(value, analysis, seen, depth + 1)
          analysis.chain << :"opaque_helper(#{method})"
          analysis.unknown = true
        end
      elsif request_value? exp or model_name?(target) or
            (not tracker.options[:ignore_model_output] and has_immediate_model?(exp))
        # The value itself, i.e. a request value or model attribute. Escaping
        # is applied by the template engine unless a later conversion marks it
        # HTML-safe.
      elsif method == :[] or method == :fetch
        # Indexing a hash does not transform the value.
        analyze_script_expression target, analysis, seen, depth + 1
      else
        # Unknown call. It may sanitize, but it may also return the value
        # unchanged or as a SafeBuffer, so remember the uncertainty.
        analysis.unknown = true
        analysis.chain << :"unknown(#{method})" if method
      end
    when :dstr, :evstr, :if, :or, :and
      exp.each { |part| analyze_script_expression part, analysis, seen, depth + 1 if sexp?(part) }
    else
      # Literal or otherwise non-call value. It has no conversions of its own.
    end
  end

  # Analyze the return value of a helper. Returns false if the helper's
  # return value cannot be determined from the template or helper source.
  def analyze_helper_value value, analysis, seen, depth
    if value.nil?
      return false
    elsif sexp? value and value.node_type == :ignore
      return false
    else
      analyze_script_expression value, analysis, seen, depth
      true
    end
  end

  def find_helper_method name
    @helper_cache ||= {}

    return @helper_cache[name] if @helper_cache.key? name

    found = nil
    tracker.libs.each do |_set_name, collection|
      if method = collection.get_method(name)
        found = method
        break
      end
    end

    @helper_cache[name] = found
  end

  def helper_return_value helper, call
    value = Brakeman::FindReturnValue.return_value(helper.src.body_list)

    formal = helper.src.formal_args
    actual = call.args

    substitutions = {}
    formal.each_with_index do |arg, index|
      next if index == 0
      substitutions[arg] = actual[index - 1] if arg.is_a? Symbol and sexp?(actual[index - 1])
    end

    substitute_args value, substitutions
  end

  def substitute_args exp, substitutions
    return exp unless sexp?(exp)

    if exp.node_type == :lvar and substitutions.key?(exp.value)
      substitutions[exp.value].deep_clone(exp.line)
    else
      exp = exp.deep_clone
      exp.map! do |child|
        sexp?(child) ? substitute_args(child, substitutions) : child
      end
      exp
    end
  end

  def check_for_immediate_xss exp
    return :duplicate if duplicate? exp

    if exp.node_type == :output
      out = exp.value
    end

    if raw_call? exp
      out = exp.value.first_arg
    elsif html_safe_call? exp
      out = exp.value.target
    end

    return if call? out and ignore_call? out.target, out.method

    if input = has_immediate_user_input?(out)
      add_result exp

      message = msg("Unescaped ", msg_input(input))

      warn :template => @current_template,
        :warning_type => "Cross-Site Scripting",
        :warning_code => :cross_site_scripting,
        :message => message,
        :code => input.match,
        :confidence => :high,
        :cwe_id => [79]

    elsif not tracker.options[:ignore_model_output] and match = has_immediate_model?(out)
      method = if call? match
                 match.method
               else
                 nil
               end

      unless IGNORE_MODEL_METHODS.include? method
        add_result exp

        if likely_model_attribute? match
          confidence = :high
        else
          confidence = :medium
        end

        message = "Unescaped model attribute"
        link_path = "cross_site_scripting"
        warning_code = :cross_site_scripting

        if node_type?(out, :call, :safe_call, :attrasgn, :safe_attrasgn) && out.method == :to_json
          message += " in JSON hash"
          link_path += "_to_json"
          warning_code = :xss_to_json
        end

        warn :template => @current_template,
          :warning_type => "Cross-Site Scripting",
          :warning_code => warning_code,
          :message => message,
          :code => match,
          :confidence => confidence,
          :link_path => link_path,
          :cwe_id => [79]
      end

    else
      false
    end
  end

  #Call already involves a model, but might not be acting on a record
  def likely_model_attribute? exp
    return false unless call? exp

    method = exp.method

    if MODEL_METHODS.include? method or method.to_s.start_with? "find_by_"
      true
    else
      likely_model_attribute? exp.target
    end
  end

  #Process an output Sexp
  def process_output exp
    process exp.value.dup
  end

  #Look for calls to raw()
  #Otherwise, ignore
  def process_escaped_output exp
    unless check_for_immediate_xss exp
      if not duplicate? exp
        if raw_call? exp
          process exp.value.first_arg
        elsif html_safe_call? exp
          process exp.value.target
        end
      end
    end
    exp
  end

  #Check a call for user input
  #
  #
  #Since we want to report an entire call and not just part of one, use @mark
  #to mark when a call is started. Any dangerous values inside will then
  #report the entire call chain.
  def process_call exp
    if @mark
      actually_process_call exp
    else
      @mark = true
      actually_process_call exp
      message = nil

      if @matched
        unless @matched.type and tracker.options[:ignore_model_output]
          message = msg("Unescaped ", msg_input(@matched))
        end

        if message and not duplicate? exp
          add_result exp

          link_path = "cross_site_scripting"
          warning_code = :cross_site_scripting

          if @known_dangerous.include? exp.method
            confidence = :high
            if exp.method == :to_json
              message << msg_plain(" in JSON hash")
              link_path += "_to_json"
              warning_code = :xss_to_json
            end
          else
            confidence = :weak
          end

          warn :template => @current_template,
            :warning_type => "Cross-Site Scripting",
            :warning_code => warning_code,
            :message => message,
            :code => exp,
            :user_input => @matched,
            :confidence => confidence,
            :link_path => link_path,
            :cwe_id => [79]
        end
      end

      @mark = @matched = false
    end

    exp
  end

  def actually_process_call exp
    return if @matched
    target = exp.target
    if sexp? target
      target = process target
    end

    method = exp.method

    #Ignore safe items
    if ignore_call? target, method
      @matched = false
    elsif sexp? target and model_name? target[1] #TODO: use method call?
      @matched = Match.new(:model, exp)
    elsif cookies? exp
      @matched = Match.new(:cookies, exp)
    elsif @inspect_arguments and params? exp
      @matched = Match.new(:params, exp)
    elsif @inspect_arguments
      process_call_args exp
    end
  end

  #Note that params have been found
  def process_params exp
    @matched = Match.new(:params, exp)
    exp
  end

  #Note that cookies have been found
  def process_cookies exp
    @matched = Match.new(:cookies, exp)
    exp
  end

  #Ignore calls to render
  def process_render exp
    exp
  end

  #Process as default
  def process_dstr exp
    process_default exp
  end

  #Process as default
  def process_format exp
    process_default exp
  end

  #Ignore output HTML escaped via HAML
  def process_format_escaped exp
    exp
  end

  #Ignore condition in if Sexp
  def process_if exp
    process exp.then_clause if sexp? exp.then_clause
    process exp.else_clause if sexp? exp.else_clause
    exp
  end

  def process_case exp
    #Ignore user input in case value
    #TODO: also ignore when values

    current = 2
    while current < exp.length
      process exp[current] if exp[current]
      current += 1
    end

    exp
  end

  def setup
    @ignore_methods = Set[:==, :!=, :button_to, :check_box, :content_tag, :escapeHTML, :escape_once,
                           :field_field, :fields_for, :form_for, :h, :hidden_field,
                           :hidden_field, :hidden_field_tag, :image_tag, :label,
                           :link_to, :mail_to, :radio_button, :select,
                           :submit_tag, :text_area, :text_field,
                           :text_field_tag, :url_encode, :u, :url_for,
                           :will_paginate].merge tracker.options[:safe_methods]

    @models = tracker.models.keys
    @inspect_arguments = tracker.options[:check_arguments]

    @known_dangerous = Set[:truncate, :concat]

    if version_between? "2.0.0", "3.0.5"
      @known_dangerous << :auto_link
    elsif version_between? "3.0.6", "3.0.99"
      @ignore_methods << :auto_link
    end

    if version_between? "2.0.0", "2.3.14" or tracker.config.gem_version(:'rails-html-sanitizer') == '1.0.2'
      @known_dangerous << :strip_tags
    end

    if tracker.config.has_gem? :'rails-html-sanitizer' and
       version_between? "1.0.0", "1.0.2", tracker.config.gem_version(:'rails-html-sanitizer')

      @known_dangerous << :sanitize
    end

    json_escape_on = false
    initializers = tracker.find_call(target: :ActiveSupport, method: :escape_html_entities_in_json=)
    initializers.each {|result| json_escape_on = true?(result[:call].first_arg) }

    if tracker.config.escape_html_entities_in_json?
      json_escape_on = true
    elsif version_between? "4.0.0", "9.9.9"
      json_escape_on = true
    end

    if !json_escape_on or version_between? "0.0.0", "2.0.99"
      @known_dangerous << :to_json
      @json_escaped = false
      Brakeman.debug("Automatic to_json escaping not enabled, consider to_json dangerous")
    else
      @safe_input_attributes << :to_json
      @json_escaped = true
      Brakeman.debug("Automatic to_json escaping is enabled.")
    end
  end

  def raw_call? exp
    exp.value.node_type == :call and exp.value.method == :raw
  end

  def html_safe_call? exp
    call? exp.value and exp.value.method == :html_safe
  end

  def ignore_call? target, method
    ignored_method?(target, method) or
    safe_input_attribute?(target, method) or
    ignored_model_method?(target, method) or
    form_builder_method?(target, method) or
    haml_escaped?(target, method) or
    boolean_method?(method) or
    cgi_escaped?(target, method) or
    xml_escaped?(target, method)
  end

  def ignored_model_method? target, method
    ((@matched and @matched.type == :model) or
       model_name? target) and
       IGNORE_MODEL_METHODS.include? method
  end

  def ignored_method? target, method
    @ignore_methods.include? method or method.to_s =~ IGNORE_LIKE
  end

  def cgi_escaped? target, method
    method == :escape and
    (target == URI or target == CGI)
  end

  def haml_escaped? target, method
    method == :html_escape and target == HAML_HELPERS
  end

  def xml_escaped? target, method
    method == :escape_xml and target == XML_HELPER
  end

  def form_builder_method? target, method
    target == FORM_BUILDER and @ignore_methods.include? method
  end

  def safe_input_attribute? target, method
    target and always_safe_method? method
  end
end
