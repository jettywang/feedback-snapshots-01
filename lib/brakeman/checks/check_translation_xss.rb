require 'set'
require 'brakeman/checks/base_check'
require 'brakeman/locale_store'

# Statically analyzes output produced through Rails translation helpers
# (+t+/+translate+ in views and +I18n.t+) for cross-site scripting.
#
# Unlike CheckTranslateBug / CheckI18nXSS (which flag framework versions), this
# check never executes translation code. It connects four pieces of static
# information:
#
#   1. The locale key passed at the call site.
#   2. The key's capability as declared in config/locales/*.yml: a plain text
#      key is escaped on output, an "_html"/".html" key is emitted as trusted
#      HTML.
#   3. The fallback/default chain (+:default+, possibly an array) which can
#      switch the effective capability, including call-level string defaults.
#   4. The interpolation arguments and the output context (<%= %> vs raw()),
#      tracking whether user-controlled data reaches a placeholder.
#
# Trusted translation *text* does not imply trusted *interpolation*: the fixed
# strings in locale files are treated as trusted, but a tainted value bound to
# a placeholder inside an HTML key is rendered without escaping. A fallback that
# lands on a different capability cannot reuse the conclusion from the primary
# key, so every leg of the chain is evaluated separately.
class Brakeman::CheckTranslationXSS < Brakeman::BaseCheck
  Brakeman::Checks.add self

  @description = "Checks translation output for XSS via HTML keys, fallback/default chains, dynamic keys, and unescaped interpolation"

  RESERVED_OPTION_KEYS = Set[:default, :scope, :count, :separator, :raise, :exception_object]

  I18N_CONST = s(:const, :I18n)

  def run_check
    @locale_store = Brakeman::LocaleStore.new(@app_tree)
    @reported = Set[]

    # A view parsed directly and again via a controller render produces two
    # Template objects backed by the same file. Key dedup on the file so the
    # identical call site is only analyzed once.
    @seen_files = Set[]

    tracker.each_template do |_name, template|
      @current_template = template
      file_key = template.file&.relative
      next if file_key and @seen_files.include? file_key
      @seen_files << file_key if file_key

      template.each_output do |output|
        inspect_output output
      end
    end
  end

  private

  # Walk one output expression. ERB wraps every <%= %> in an escaped output, so
  # the node type alone does not indicate raw rendering; an explicit raw() or
  # html_safe wrapper is the unescape marker we look for. Translation calls may
  # be the whole output or nested inside such a wrapper.
  def inspect_output(output)
    return unless output.node_type == :output or output.node_type == :escaped_output

    @output_escaping = :normal
    call = output.value

    if raw_wrapper?(call)
      @output_escaping = :raw
      call = call.first_arg
    elsif html_safe_wrapper?(call)
      @output_escaping = :raw
      call = call.target
    end

    find_translation_calls(call).each do |translation_call|
      analyze_call translation_call
    end
  end

  def raw_wrapper?(exp)
    call?(exp) and exp.method == :raw and exp.target.nil?
  end

  def html_safe_wrapper?(exp)
    call?(exp) and exp.method == :html_safe
  end

  # Collect translation calls anywhere in the expression, including nested
  # ones, without descending into unrelated method bodies.
  def find_translation_calls(exp)
    calls = []
    return calls unless sexp? exp

    calls << exp if translation_call? exp

    exp.each_sexp do |child|
      calls.concat find_translation_calls(child)
    end

    calls
  end

  def translation_call? exp
    call?(exp) and
      [:t, :translate].include?(exp.method) and
      (exp.target.nil? or exp.target == I18N_CONST)
  end

  # --- Per call-site analysis -------------------------------------------------

  def analyze_call(call)
    key_arg = call.first_arg
    options = call.second_arg
    interpolation = extract_interpolation(options)

    # Dynamic / unknown key: the effective capability cannot be resolved, so the
    # safe assumption is that an HTML-capable key may be selected at runtime.
    unless static_key?(key_arg)
      warn_dynamic_key(call, key_arg, interpolation)
      return
    end

    primary_key = normalize_key(key_arg)
    chain = capability_chain(primary_key, options)

    analyze_chain(call, primary_key, chain, interpolation)
  end

  def static_key?(exp)
    string?(exp) or symbol?(exp)
  end

  def normalize_key(exp)
    string?(exp) ? exp.value : exp.value.to_s
  end

  # Build the ordered list of capabilities the call can resolve to.
  #
  # Each leg is a Hash:
  #   { kind: :locale_key | :call_default, key:, capability:, defined:, source: }
  #
  # The primary key comes first. Every +:default+ entry is appended in order so
  # that a capability switch later in the chain is evaluated on its own merits.
  def capability_chain(primary_key, options)
    chain = [{
      kind: :locale_key,
      key: primary_key,
      capability: capability_of_key(primary_key),
      defined: !@locale_store[primary_key].nil?,
      source: :primary
    }]

    default_entries(options).each do |entry|
      chain.concat default_leg(entry)
    end

    chain
  end

  def default_entries(options)
    return [] unless hash? options

    default = hash_access(options, :default)
    return [] if default.nil? or false? default

    array?(default) ? default.sexp_body : [default]
  end

  # Translate one +:default+ value into zero or more capability legs.
  #
  # A symbol default names another locale key and inherits that key's
  # capability. A string default is inline text content (escaped text), even
  # when the primary key is an HTML key. A hash is a pluralization default.
  def default_leg(entry)
    if symbol?(entry)
      key = normalize_key(entry)
      [{
        kind: :locale_key,
        key: key,
        capability: capability_of_key(key),
        defined: !@locale_store[key].nil?,
        source: :default
      }]
    elsif string?(entry) or string_interp?(entry) or hash?(entry)
      # Inline string (or pluralization hash) default: literal text content,
      # always escaped text capability regardless of the primary key's name.
      [{
        kind: :call_default,
        key: nil,
        capability: :text,
        defined: true,
        source: :default,
        value: entry
      }]
    else
      # Non-literal default (another call etc.): capability unknown.
      [{
        kind: :call_default,
        key: nil,
        capability: :unknown,
        defined: false,
        source: :default,
        value: entry
      }]
    end
  end

  # Capability of a locale key based on its name and parsed definition.
  # HTML semantics follow the key name; anything else is escaped text.
  def capability_of_key(key)
    Brakeman::LocaleStore.html_semantic_key?(key) ? :html : :text
  end

  # --- Interpolation ----------------------------------------------------------

  # Returns { placeholder_name => value_exp } for the non-reserved options.
  def extract_interpolation(options)
    interpolation = {}
    return interpolation unless hash? options

    key = nil
    options.each_sexp do |node|
      if node.node_type == :lit and node.value.is_a? Symbol
        key = node.value
      elsif key
        interpolation[key] = node unless RESERVED_OPTION_KEYS.include? key
        key = nil
      end
    end

    interpolation
  end

  def taint_match(exp)
    has_immediate_user_input?(exp) ||
      (!tracker.options[:ignore_model_output] && has_immediate_model?(exp))
  end

  def tainted?(exp)
    !!taint_match(exp)
  end

  def tainted_interpolation(interpolation)
    interpolation.select { |_name, value| tainted? value }
  end

  # Evaluate the full chain for one call, emitting distinct, explained warnings.
  def analyze_chain(call, primary_key, chain, interpolation)
    html_legs = chain.select { |leg| leg[:capability] == :html }
    unknown_legs = chain.select { |leg| leg[:capability] == :unknown }
    tainted = tainted_interpolation(interpolation)

    # 1. HTML-capable legs: interpolation values are emitted unescaped.
    html_legs.each do |leg|
      warn_html_leg(call, leg, tainted)
    end

    # 2. A later leg changing capability relative to the primary key means the
    #    "safe text" conclusion cannot be reused; explain the switch.
    warn_on_capability_switch(call, primary_key, chain, tainted)

    # 3. Completely unresolved key: neither the primary key nor any fallback is
    #    defined in a locale file, and there is no usable inline default. The
    #    output capability then genuinely cannot be determined.
    resolvable = chain.any? { |leg| leg[:defined] }
    if !resolvable and unknown_legs.empty?
      warn_unresolved(call, primary_key, tainted)
    end

    # 4. Unknown-capability defaults (dynamic default expression).
    unknown_legs.each do |leg|
      warn_unknown_default(call, leg, tainted)
    end

    # 5. Plain text output wrapped in raw()/html_safe still bypasses escaping.
    if @output_escaping == :raw and html_legs.empty?
      warn_raw_text(call, primary_key, tainted)
    end
  end

  # --- Warning builders -------------------------------------------------------

  def warn_html_leg(call, leg, tainted)
    if tainted.empty?
      # Trusted HTML text with no tainted interpolation: explain that this call
      # is HTML-capable, but its fixed translation and safe values are trusted.
      emit call, :translation_xss_html_key, :weak, leg,
           msg("HTML translation key ", msg_code(leg[:key].inspect),
               " is rendered without escaping; its fixed text is trusted and no tainted interpolation reaches it (",
               msg_plain(leg_location(leg)), ")")
      return
    end

    tainted.each do |name, value|
      match = taint_match(value)
      emit call, :translation_xss_html_key, :high, leg,
           msg("Unescaped interpolation ", msg_code("%{#{name}}"),
               " from ", msg_input(match), " in HTML translation key ",
               msg_code(leg[:key].inspect), " (", msg_plain(leg_location(leg)), ")"),
           match, name
    end
  end

  # Highlight when a fallback/default resolves to a different capability than
  # the primary key. This is the "cannot reuse the old conclusion" case.
  def warn_on_capability_switch(call, primary_key, chain, tainted)
    primary = chain.first
    return if primary.nil? or tainted.empty?

    chain.each_with_index do |leg, index|
      next if index.zero?
      next unless leg[:capability] == :html and primary[:capability] != :html

      tainted.each do |name, value|
        match = taint_match(value)
        emit call, :translation_xss_default, :high, leg,
             msg("Fallback ", msg_code(leg_label(leg)),
                 " switches ", msg_code(primary_key.inspect),
                 " from ", msg_plain(primary[:capability].to_s),
                 " to HTML capability; interpolation ", msg_code("%{#{name}}"),
                 " from ", msg_input(match), " is no longer escaped (",
                 msg_plain(leg_location(leg)), ")"),
             match, name
      end
    end
  end

  def warn_unresolved(call, primary_key, tainted)
    return if tainted.empty? and @output_escaping != :raw

    emit call, :translation_xss_dynamic_key, :medium,
         { kind: :locale_key, key: primary_key, capability: :unknown, source: :primary },
         msg("Translation key ", msg_code(primary_key.inspect),
             " is not defined in any locale and has no inline default; its output capability is unknown"),
         tainted.values.map { |v| taint_match(v) }.compact.first
  end

  def warn_unknown_default(call, leg, tainted)
    return if tainted.empty?

    tainted.each do |name, value|
      match = taint_match(value)
      emit call, :translation_xss_default, :medium, leg,
           msg("Dynamic default for this translation call has unknown capability; interpolation ",
               msg_code("%{#{name}}"), " from ", msg_input(match),
               " may be rendered unescaped"),
           match, name
    end
  end

  def warn_dynamic_key(call, key_arg, interpolation)
    tainted = tainted_interpolation(interpolation)

    emit call, :translation_xss_dynamic_key, :medium,
         { kind: :dynamic, key: nil, capability: :unknown, source: :primary },
         msg("Dynamic translation key ", msg_code(format_output(key_arg)),
             " cannot be resolved statically; an HTML-capable key may be selected at runtime"),
         tainted.values.map { |v| taint_match(v) }.compact.first
  end

  def warn_raw_text(call, primary_key, tainted)
    return if tainted.empty?

    tainted.each do |name, value|
      match = taint_match(value)
      emit call, :translation_xss_raw_output, :high,
           { kind: :locale_key, key: primary_key, capability: :text, source: :primary },
           msg("Plain-text translation ", msg_code(primary_key.inspect),
               " is passed through ", msg_code("raw"), "; interpolation ",
               msg_code("%{#{name}}"), " from ", msg_input(match),
               " bypasses HTML escaping"),
           match, name
    end
  end

  # --- Shared plumbing --------------------------------------------------------

  def leg_label(leg)
    leg[:key] ? leg[:key].inspect : "call-site default"
  end

  def leg_location(leg)
    return "call-site default" unless leg[:key]

    entry = @locale_store[leg[:key]]
    if entry && (location = entry.locations.values.first)
      "#{location[:file].relative}:#{location[:line]}"
    else
      "key not found in locale files"
    end
  end

  # Dedup on (call line, warning code, leg key, placeholder) so the same
  # call site cannot emit the identical warning more than once.
  def emit(call, code, confidence, leg, message, user_input = nil, placeholder = nil)
    fingerprint = [call.line, code, leg[:key], placeholder, @current_template.name]
    return if @reported.include? fingerprint
    @reported << fingerprint

    warn template: @current_template,
      warning_type: "Cross-Site Scripting",
      warning_code: code,
      message: message,
      confidence: confidence,
      code: call,
      user_input: user_input,
      cwe_id: [79],
      link_path: "translation_xss"
  end

  def hash_access(hash_exp, key)
    hash_exp.each_sexp.each_slice(2) do |k, v|
      return v if k.is_a?(Sexp) and k.node_type == :lit and k.value == key
    end
    nil
  end
end
