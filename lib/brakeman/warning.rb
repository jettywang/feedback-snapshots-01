require 'json'
require 'digest/sha2'
require 'brakeman/warning_codes'
require 'brakeman/messages'
require 'brakeman/sink_identity'

#The Warning class stores information about warnings
class Brakeman::Warning
  attr_reader :called_from, :check, :class, :confidence, :controller, :cwe_id,
    :line, :method, :model, :template, :user_input, :user_input_type,
    :warning_code, :warning_set, :warning_type, :evidence, :sink_expression,
    :render_paths, :discovery_scope

  attr_accessor :occurrence, :template_site_ordinal

  attr_accessor :code, :context, :file, :message

  TEXT_CONFIDENCE = {
    0 => "High",
    1 => "Medium",
    2 => "Weak",
  }

  CONFIDENCE = {
    :high => 0,
    :med => 1,
    :medium => 1,
    :low => 2,
    :weak => 2,
  }

  OPTIONS = {
    :called_from => :@called_from,
    :check => :@check,
    :class => :@class,
    :code => :@code,
    :controller => :@controller,
    :cwe_id => :@cwe_id,
    :file => :@file,
    :gem_info => :@gem_info,
    :line => :@line,
    :link => :@link,
    :link_path => :@link_path,
    :message => :@message,
    :method => :@method,
    :model => :@model,
    :template => :@template,
    :user_input => :@user_input,
    :warning_set => :@warning_set,
    :warning_type => :@warning_type,
    :sink => :@sink_expression,
    :evidence => :@given_evidence,
    :discovery_scope => :@discovery_scope,
    :template_site_ordinal => :@template_site_ordinal,
  }

  attr_writer :collision_suffix

  #+options[:result]+ can be a result from Tracker#find_call. Otherwise, it can be +nil+.
  def initialize options = {}
    @view_name = nil

    OPTIONS.each do |key, var|
      self.instance_variable_set(var, options[key])
    end

    self.confidence = options[:confidence]

    result = options[:result]
    if result
      @code ||= result[:call]
      @file ||= result[:location][:file]

      if result[:location][:type] == :template #template result
        @template ||= result[:location][:template]
      else
        @class ||= result[:location][:class]
        @method ||= result[:location][:method]
      end
    end

    if @method.to_s =~ /^fake_filter\d+/
      @method = :before_filter
    end

    if @user_input.is_a? Brakeman::BaseCheck::Match
      @user_input_type = @user_input.type
      @user_input = @user_input.match
    elsif @user_input == false
      @user_input = nil
    end

    if not @line
      if @user_input and @user_input.respond_to? :line
        @line = @user_input.line
      elsif @code and @code.respond_to? :line
        @line = @code.line
      end
    end

    if @gem_info
      if @gem_info.is_a? Hash
        @line ||= @gem_info[:line]
        @file ||= @gem_info[:file]
      else
        # Fallback behavior returns just a string for the file name
        @file ||= @gem_info
      end
    end

    unless @warning_set
      if self.model
        @warning_set = :model
        @file ||= self.model.file
      elsif self.template
        @warning_set = :template
        @called_from = self.template.render_path
        @file ||= self.template.file
      elsif self.controller
        @warning_set = :controller
      else
        @warning_set = :warning
      end
    end

    if options[:warning_code]
      @warning_code = Brakeman::WarningCodes.code options[:warning_code]
    else
      @warning_code = nil
    end

    Brakeman.debug("Warning created without warning code: #{options[:warning_code]}") unless @warning_code

    if options[:message].is_a? String
      @message = Brakeman::Messages::Message.new(options[:message])
    end

    @render_paths = []
    @render_paths << @called_from if @called_from
    @occurrence = 0
    @sink_expression ||= result && result[:call]
    @sink_expression ||= @code

    @evidence = build_evidence(@given_evidence)

    @format_message = nil
    @row = nil
  end

  def hash
    sink_instance_key.hash
  end

  def eql? other_warning
    other_warning.is_a?(Brakeman::Warning) &&
      sink_instance_key == other_warning.sink_instance_key
  end

  def confidence= conf
    @confidence = case conf
                  when Integer
                    conf
                  when Symbol
                    CONFIDENCE[conf]
                  else
                    raise "Could not set confidence to `#{conf}`"
                  end

    raise "Could not set confidence to `#{conf}`" unless @confidence
    raise "Invalid confidence: `#{@confidence}`" unless TEXT_CONFIDENCE[@confidence]
  end

  #Returns name of a view, including where it was rendered from
  def view_name(include_renderer = true)
    if called_from and include_renderer
      @view_name = "#{template.name} (#{called_from.last})"
    else
      @view_name = template.name
    end
  end

  #Return String of the code output from the OutputProcessor and
  #stripped of newlines and tabs.
  def format_code strip = true
    format_ruby self.code, strip
  end

  #Return String of the user input formatted and
  #stripped of newlines and tabs.
  def format_user_input strip = true
    format_ruby self.user_input, strip
  end

  def format_with_user_input strip = true, &block
    if self.user_input
      formatted = Brakeman::OutputProcessor.new.format(code, self.user_input, &block)
      formatted = formatted.gsub(/(\t|\r|\n)+/, " ") if strip
      formatted
    else
      format_code
    end
  end

  #Return formatted warning message
  def format_message
    return @format_message if @format_message

    @format_message = self.message.to_s.dup

    if self.line
      @format_message << " near line #{self.line}"
    end

    if self.code
      @format_message << ": #{format_code}"
    end

    @format_message
  end

  def link
    return @link if @link

    if @link_path
      if @link_path.start_with? "http"
        @link = @link_path
      else
        @link = "https://brakemanscanner.org/docs/warning_types/#{@link_path}"
      end
    else
      warning_path = self.warning_type.to_s.downcase.gsub(/\s+/, '_') + "/"
      @link = "https://brakemanscanner.org/docs/warning_types/#{warning_path}"
    end

    @link
  end

  #Generates a hash suitable for inserting into a table
  def to_row type = :warning
    @row = { "Confidence" => TEXT_CONFIDENCE[self.confidence],
      "Warning Type" => self.warning_type.to_s,
      "CWE ID" => self.cwe_id,
      "Message" => self.message }

    case type
    when :template
      @row["Template"] = self.view_name.to_s
    when :model
      @row["Model"] = self.model.name.to_s
    when :controller
      @row["Controller"] = self.controller.to_s
    when :warning
      @row["Class"] = self.class.to_s
      @row["Method"] = self.method.to_s
    end

    @row
  end

  def to_s
   output =  "(#{TEXT_CONFIDENCE[self.confidence]}) #{self.warning_type} - #{self.message}"
   output << " near line #{self.line}" if self.line
   output << " in #{self.file.relative}" if self.file
   output << ": #{self.format_code}" if self.code

   output
  end

  # Stable, path-independent identity for the warning's rule + source location
  # + sink expression.  It deliberately excludes line numbers, confidence and
  # evidence so formatting-only changes do not create a new finding.
  def sink_identity_key
    [@warning_code, self.file && self.file.relative, scope_key, Brakeman::SinkIdentity.signature(@sink_expression)]
  end

  # A single physical occurrence of a sink.  Line and the exact source keys are
  # included so two real calls on one line (or two different sources nested in
  # one statement) stay distinct.  These are never used to merge discoveries
  # from different propagation paths.
  def sink_instance_key
    key = sink_identity_key + [@line, Brakeman::SinkIdentity.exact_signature(@sink_expression)]
    key << @template_site_ordinal if warning_set == :template
    key
  end

  # Identity used to decide whether a warning merely moved lines.  Everything
  # except the line number must match: a changed source or sink structure is a
  # semantic change, not a formatting move.
  def sink_move_key
    sink_identity_key + [Brakeman::SinkIdentity.exact_signature(@sink_expression)]
  end

  # Physical sink inside a template: rule + template file + line + ordinal of
  # the output on that line.  Template#name can carry a render-path suffix, so
  # it is not used here.  Resolved source values and the substituted call
  # structure are also excluded; those differ between render environments for
  # the same output.
  def template_site_key
    [@warning_code, self.file && self.file.relative, template_file_key, @line, @template_site_ordinal]
  end

  def template_file_key
    template && template.file && template.file.relative
  end

  # Stable identifier for this rule firing at this sink instance.  `occurrence`
  # orders identical structures within a scope, so two calls remain distinct
  # while a pure line move keeps its id.
  def sink_id
    @sink_id ||= Digest::SHA2.new(256).update(
      "sink-v1\0#{@warning_code}\0#{self.file && self.file.relative}\0#{scope_key.inspect}\0#{Brakeman::SinkIdentity.signature(@sink_expression)}\0#{@occurrence}"
    ).to_s
  end

  # Legacy fingerprint formula.  Published ignore files use this value, so it
  # remains available for migration.  It is intentionally not used for new
  # duplicates because it cannot distinguish identical calls.
  def legacy_fingerprint
    loc = self.location
    location_string = loc && loc.sort_by { |k, v| k.to_s }.inspect
    warning_code_string = sprintf("%03d", @warning_code)
    code_string = @code.inspect

    Digest::SHA2.new(256).update("#{warning_code_string}#{code_string}#{location_string}#{self.file.relative}#{self.confidence}").to_s
  end

  def fingerprint
    base = legacy_fingerprint

    if @collision_suffix
      Digest::SHA2.new(256).update("sink-v1\0#{@collision_suffix}\0#{base}").to_s
    else
      base
    end
  end

  # Merge another warning for the same physical template sink (the same output
  # reached through two render paths). Evidence and paths are unioned; the
  # strongest confidence is retained.
  def merge_sink! other
    return self unless template_mergeable?(other)

    # Sources may live in the other render environment, so keep both code and
    # the line where that source was resolved.  Identical evidence found in the
    # same location is never duplicated.
    combined_evidence = (@evidence + other.evidence).uniq { |e| [e.type, e.code, e.line] }
    @render_paths |= other.render_paths
    @render_paths << other.called_from if other.called_from && !@render_paths.include?(other.called_from)
    @called_from ||= other.called_from
    self.confidence = [self.confidence, other.confidence].compact.min
    @user_input ||= other.user_input
    @user_input_type ||= other.user_input_type

    # Different render environments can resolve the same template output to
    # different calls (e.g. `User.new(user_params)` vs `User.find(params[:id])`).
    # Pick a deterministic representative independent of traversal order so
    # fingerprints and machine reports are stable across runs and machines.
    if other.legacy_fingerprint < legacy_fingerprint
      @code = other.code
      @sink_expression = other.sink_expression
      @sink_id = nil
      @format_message = nil
    end

    @evidence = combined_evidence
    self
  end

  def template_mergeable? other
    other.is_a?(Brakeman::Warning) &&
      warning_set == :template && other.warning_set == :template &&
      template_site_key == other.template_site_key
  end

  def location include_renderer = true
    case @warning_set
    when :template
      { :type => :template, :template => self.view_name(include_renderer) }
    when :model
      { :type => :model, :model => self.model.name }
    when :controller
      { :type => :controller, :controller => self.controller }
    when :warning
      if self.class
        { :type => :method, :class => self.class, :method => self.method }
      else
        nil
      end
    end
  end

  def relative_path
    self.file.relative
  end

  def check_name
    @check_name ||= self.check.sub(/^Brakeman::Check/, '')
  end

  def confidence_name
    TEXT_CONFIDENCE[self.confidence]
  end

  def to_hash absolute_paths: true
    if self.called_from and not absolute_paths
      render_path = self.called_from.with_relative_paths
    else
      render_path = self.called_from
    end

    { :warning_type => self.warning_type,
      :warning_code => @warning_code,
      :fingerprint => self.fingerprint,
      :sink_id => self.sink_id,
      :evidence => self.evidence.map(&:to_h),
      :render_paths => self.render_paths.map { |path| path.respond_to?(:to_a) ? path.to_a : path },
      :check_name => self.check_name,
      :message => self.message.to_s,
      :file => (absolute_paths ? self.file.absolute : self.file.relative),
      :line => self.line,
      :link => self.link,
      :code => (@code && self.format_code(false)),
      :render_path => render_path,
      :location => self.location(false),
      :user_input => (@user_input && self.format_user_input(false)),
      :confidence => self.confidence_name,
      :cwe_id => cwe_id
    }
  end

  def to_json
    JSON.generate self.to_hash
  end

  private

  def scope_key
    loc = self.location(false)
    return loc if loc.nil?

    loc.sort_by { |k, v| k.to_s }.map { |k, v| [k, v.to_s] }
  end

  def build_evidence given = nil
    entries = case given
              when Array then given
              when Brakeman::SinkIdentity::Evidence, Hash then [given]
              else []
              end

    explicit = entries.map do |entry|
      if entry.is_a? Brakeman::SinkIdentity::Evidence
        entry
      elsif entry.is_a? Hash
        Brakeman::SinkIdentity::Evidence.new(
          type: entry[:type] || entry["type"],
          code: entry[:code] || entry["code"],
          line: entry[:line] || entry["line"]
        )
      end
    end.compact

    if explicit.empty? and @sink_expression
      explicit = Brakeman::SinkIdentity.collect_sources(@sink_expression).map do |type, exp|
        Brakeman::SinkIdentity::Evidence.new(
          type: type,
          code: Brakeman::SinkIdentity.format_code(exp),
          line: exp.respond_to?(:line) ? exp.line : nil
        )
      end
    end

    if explicit.empty? and @user_input
      explicit << Brakeman::SinkIdentity::Evidence.new(
        type: @user_input_type || :user_input,
        code: Brakeman::SinkIdentity.format_code(@user_input),
        line: @user_input.respond_to?(:line) ? @user_input.line : nil
      )
    end

    explicit.uniq { |e| [e.type, e.code, e.line] }
  end

  def format_ruby code, strip
    formatted = Brakeman::OutputProcessor.new.format(code)
    formatted = formatted.gsub(/(\t|\r|\n)+/, " ") if strip
    formatted
  end
end
