require 'brakeman/checks/base_check'

class Brakeman::CheckDeserialize < Brakeman::BaseCheck
  Brakeman::Checks.add self

  @description = "Checks for unsafe deserialization of objects"

  def run_check
    check_yaml
    check_csv
    check_marshal
    check_oj
  end

  def check_yaml
    check_methods :YAML, :load_documents, :load_stream, :parse_documents, :parse_stream

    # Check for safe_yaml gem use with YAML.load(..., safe: true)
    if uses_safe_yaml?
      tracker.find_call(target: :YAML, method: :load).each do |result|
        call = result[:call]
        options = call.second_arg

        if hash? options and true? hash_access(options, :safe)
          next
        else
          check_deserialize result, :YAML
        end
      end
    else
      check_methods :YAML, :load
    end

    check_safe_load
  end

  # Classes that only deserialize to plain data values,
  # not application objects
  SAFE_LOAD_PLAIN_CLASSES = %w[
    Array
    BigDecimal
    Date
    DateTime
    FalseClass
    Float
    Hash
    Integer
    NilClass
    Range
    Regexp
    String
    Symbol
    Time
    TrueClass
  ].freeze

  # Methods that may modify a permitted class list after assignment
  SAFE_LOAD_LIST_MUTATIONS = [
    :<<,
    :concat,
    :fill,
    :insert,
    :prepend,
    :push,
    :replace,
    :unshift,
  ].freeze

  # YAML.safe_load is only safe for untrusted input if the permitted
  # classes are limited to plain data. Check the permitted_classes,
  # permitted_symbols, and aliases options instead of trusting the
  # method name.
  def check_safe_load
    tracker.find_call(target: :YAML, method: :safe_load).each do |result|
      next unless original? result

      call = result[:call]
      arg = call.first_arg

      if input = has_immediate_user_input?(arg)
        confidence = :high
      elsif input = include_user_input?(arg)
        confidence = :medium
      else
        next
      end

      check_safe_load_options result, input, confidence
    end
  end

  def check_safe_load_options result, input, confidence
    call = result[:call]
    options = call.second_arg

    permitted_classes = nil
    aliases = nil

    if options.nil? or node_type? options, :nil
      # No options, only plain data is permitted
    elsif hash? options
      # Note: permitted_symbols only controls which symbols are
      # allowed, it cannot permit deserialization of objects
      permitted_classes = hash_access(options, :permitted_classes)
      aliases = hash_access(options, :aliases)
    elsif array? options
      # Legacy positional arguments:
      # YAML.safe_load(yaml, permitted_classes, permitted_symbols, aliases)
      permitted_classes = options
      aliases = call[6]
    else
      warn_safe_load result, input, lower_confidence(confidence),
        "options cannot be determined statically"
      return
    end

    resolution = resolve_permitted_classes permitted_classes, [], result[:file]

    case resolution[:status]
    when :none, :plain
      if true? aliases
        warn_safe_load result, input, :low,
          "allows YAML aliases with ", msg_code("aliases: true")
      end
    when :objects
      detail = ["permits deserialization of ",
        msg_code(resolution[:classes].join(", ")),
        " objects"]

      unless resolution[:sources].empty?
        detail += [" via ", msg_code(resolution[:sources].join(" -> "))]
      end

      warn_safe_load result, input, confidence, *detail
    when :unknown
      warn_safe_load result, input, lower_confidence(confidence),
        "permitted classes cannot be determined statically ",
        msg_plain("(#{resolution[:evidence]})")
    end
  end

  # Statically resolve a permitted_classes value to find out what can
  # actually be deserialized. Follows constants and records where the
  # class list came from. Never instantiates anything.
  def resolve_permitted_classes exp, sources = [], file = nil
    if exp.nil? or node_type? exp, :nil
      return { status: :none, sources: sources }
    end

    if array? exp
      if exp.sexp_body.empty?
        return modified_or(file, exp, { status: :none, sources: sources })
      end

      object_classes = []
      unknown_elements = []

      exp.sexp_body.each do |element|
        if constant? element
          name = class_name(element).to_s

          unless SAFE_LOAD_PLAIN_CLASSES.include? name
            object_classes << name
          end
        else
          unknown_elements << element
        end
      end

      if not unknown_elements.empty?
        unknown = unknown_elements.map { |e| Brakeman::OutputProcessor.new.process(e) rescue "dynamic value" }

        return {
          status: :unknown,
          sources: sources,
          evidence: "#{unknown.join(', ')} in permitted class list is not a known class",
        }
      elsif not object_classes.empty?
        return { status: :objects, classes: object_classes, sources: sources }
      else
        return modified_or(file, exp, { status: :plain, sources: sources })
      end
    elsif constant? exp
      name = class_name(exp).to_s
      sources = sources + [name]

      key = mutation_key(exp)

      if constant_mutations.key? key
        return {
          status: :unknown,
          sources: sources,
          evidence: mutation_evidence(name, constant_mutations[key]),
        }
      end

      if value = tracker.constants[exp]
        resolve_permitted_classes value, sources, file
      else
        return {
          status: :unknown,
          sources: sources,
          evidence: "value of #{name} is unknown",
        }
      end
    else
      description = Brakeman::OutputProcessor.new.process(exp) rescue "dynamic value"

      {
        status: :unknown,
        sources: sources,
        evidence: "permitted classes come from #{description}",
      }
    end
  end

  # If the given plain class list was inlined from a constant assignment
  # that is modified somewhere else, the resolved value cannot be
  # trusted. Report it as unknown instead.
  def modified_or file, array_exp, resolution
    if name = modified_source_constant(array_exp, file)
      mutations = constant_mutations[name]

      return {
        status: :unknown,
        sources: [name],
        evidence: mutation_evidence(name, mutations),
      }
    end

    resolution
  end

  # Find the constant a class list was inlined from (based on the
  # original line of the list) and check if that constant is modified
  # somewhere after its assignment
  def modified_source_constant array_exp, file
    line = array_exp.original_line
    return nil unless line

    tracker.constants.each do |const|
      next unless const.line == line
      next unless array? const.value
      next if file and const.file and const.file.to_s != file.to_s

      name = mutation_key(const.name)

      if constant_mutations.key? name
        return name
      end
    end

    nil
  end

  # Unqualified constant name used to match mutation calls against
  # constants, since mutations may use a qualified name (A::B::C)
  def mutation_key exp
    class_name(exp).to_s.split("::").last
  end

  # All mutation calls (<<, push, etc.) on constants, indexed by
  # unqualified constant name
  def constant_mutations
    @constant_mutations ||= begin
      mutations = Hash.new { |hash, key| hash[key] = [] }

      tracker.find_call(methods: SAFE_LOAD_LIST_MUTATIONS).each do |result|
        target = result[:call].target

        if constant? target
          mutations[mutation_key(target)] << result[:call]
        end
      end

      mutations
    end
  end

  def mutation_evidence name, mutations
    added = mutations.filter_map do |call|
      arg = call.first_arg
      class_name(arg).to_s if constant? arg
    end

    if added.empty?
      "#{name} is modified after assignment"
    else
      "#{name} is modified after assignment (adds #{added.uniq.join(', ')})"
    end
  end

  def warn_safe_load result, input, confidence, *detail
    message = msg(msg_code("YAML.safe_load"), " called with ", msg_input(input), " ", *detail)

    warn :result => result,
      :warning_type => "Remote Code Execution",
      :warning_code => :unsafe_deserialize,
      :message => message,
      :user_input => input,
      :confidence => confidence,
      :link_path => "unsafe_deserialization",
      :cwe_id => [502]
  end

  def lower_confidence confidence
    case confidence
    when :high
      :medium
    else
      :low
    end
  end

  def check_csv
    check_methods :CSV, :load
  end

  def check_marshal
    check_methods :Marshal, :load, :restore
  end

  def check_oj
    check_methods :Oj, :object_load # Always unsafe, regardless of mode

    unsafe_mode = :object
    safe_default = oj_safe_default?

    tracker.find_call(:target => :Oj, :method => :load).each do |result|
      call = result[:call]
      options = call.second_arg

      if options and hash? options and mode = hash_access(options, :mode)
        if symbol? mode and mode.value == unsafe_mode
          check_deserialize result, :Oj
        end
      elsif not safe_default
        check_deserialize result, :Oj
      end
    end
  end

  def check_methods target, *methods
    tracker.find_call(:target => target, :methods => methods ).each do |result|
      check_deserialize result, target
    end
  end

  def check_deserialize result, target, arg = nil
    return unless original? result

    arg ||= result[:call].first_arg
    method = result[:call].method

    if input = has_immediate_user_input?(arg)
      confidence = :high
    elsif input = include_user_input?(arg)
      confidence = :medium
    elsif target == :Marshal
      confidence = :low
      message = msg("Use of ", msg_code("#{target}.#{method}"), " may be dangerous")
    end

    if confidence
      message ||= msg(msg_code("#{target}.#{method}"), " called with ", msg_input(input))

      warn :result => result,
        :warning_type => "Remote Code Execution",
        :warning_code => :unsafe_deserialize,
        :message => message,
        :user_input => input,
        :confidence => confidence,
        :link_path => "unsafe_deserialization",
        :cwe_id => [502]
    end
  end

  private

  def oj_safe_default?
    safe_default = false

    if tracker.find_call(target: :Oj, method: :mimic_JSON).any?
      safe_default = true
    elsif result = tracker.find_call(target: :Oj, method: :default_options=).first
      options = result[:call].first_arg

      if oj_safe_mode? options
        safe_default = true
      end
    end

    safe_default
  end

  def oj_safe_mode? options
    if hash? options and mode = hash_access(options, :mode)
      if symbol? mode and mode != :object
        return true
      end
    end

    false
  end

  def uses_safe_yaml?
    tracker.config.has_gem? :safe_yaml
  end
end
