require 'set'
require 'brakeman/util'

module Brakeman
  # Where a template value is being emitted.
  #
  # The values are intentionally coarse. If the template does not determine
  # the context, +UNKNOWN+ is used instead of guessing.
  module TemplateContext
    HTML = :html
    HTML_ATTRIBUTE = :html_attribute
    SCRIPT_STRING = :script_string
    SCRIPT_TEMPLATE = :script_template
    SCRIPT_EXPRESSION = :script_expression
    JSON = :json
    JSON_STRING = :json_string
    UNKNOWN = :unknown

    SCRIPT = [SCRIPT_STRING, SCRIPT_TEMPLATE, SCRIPT_EXPRESSION, JSON, JSON_STRING].freeze

    def self.script? context
      SCRIPT.include? context
    end

  end

  # Incremental HTML lexer that tracks whether the current position is in
  # document HTML, an HTML attribute, a <script> body, or a JavaScript string
  # inside a <script> body.
  #
  # Only literal template text is fed in. No JavaScript is parsed or executed.
  class TemplateContextLexer
    JAVASCRIPT_TYPES = /\A(?:text\/javascript|application\/javascript|application\/ecmascript|text\/ecmascript|module)\z/i
    JSON_TYPES = /(?:\A|\/|\+)json\z/i
    NON_SCRIPT_TYPES = /\A(?:text\/(?:html|template|x-template|plain)|text\/css)\z/i

    attr_reader :uncertain

    def initialize
      @mode = :data
      @tag = +""
      @quote = nil
      @tag_name = nil
      @script_type = nil
      @script_type_unknown = false
      @tag_dynamic = false
      @attr_name = nil
      @raw_tail = +""
      @comment_tail = +""
      @string_escape = false
      @pending_slash = false
      @uncertain = false
    end

    def text string
      return unless string.is_a? String
      return if @uncertain

      string.each_char { |c| feed c }
    end

    def initialize_copy other
      super
      @tag = @tag.dup
      @raw_tail = @raw_tail.dup
      @comment_tail = @comment_tail.dup
    end

    def uncertain!
      @uncertain = true
    end

    # A comparable snapshot of the lexer's state. Used to merge template
    # conditionals: if all possible branches end in the same state, later
    # template text still has a determinate context.
    def state_signature
      # Partial terminators (raw/comment tails) are intentionally excluded:
      # different branch text still leaves the parser in the same state unless
      # it actually changed @mode, which is included.
      [@mode, @quote, @tag_name, @script_type, @script_type_unknown,
       @tag_dynamic, @attr_name, @uncertain]
    end

    # Called when a dynamic value is emitted while the lexer is in the middle
    # of a tag. The tag name/attributes can no longer be trusted.
    def dynamic_value!
      return unless @mode == :tag

      @tag_dynamic = true
      @script_type_unknown = true if @tag_name.to_s.casecmp("script").zero?

      # A dynamic value outside an attribute value could add attributes or
      # change the tag structure, so do not guess at later context.
      @uncertain = true unless @quote
    end

    def context
      return TemplateContext::UNKNOWN if @uncertain

      case @mode
      when :data
        TemplateContext::HTML
      when :tag
        if @quote
          if @attr_name and @attr_name.downcase.start_with?("on")
            TemplateContext::SCRIPT_EXPRESSION
          else
            TemplateContext::HTML_ATTRIBUTE
          end
        else
          TemplateContext::UNKNOWN
        end
      when :script, :script_line_comment, :script_block_comment
        script_context TemplateContext::SCRIPT_EXPRESSION, TemplateContext::JSON
      when :script_dq, :script_sq
        script_context TemplateContext::SCRIPT_STRING, TemplateContext::JSON_STRING
      when :script_bt
        script_context TemplateContext::SCRIPT_TEMPLATE, TemplateContext::JSON_STRING
      else
        TemplateContext::UNKNOWN
      end
    end

    private

    def script_context javascript_context, json_context
      if @script_type_unknown
        TemplateContext::UNKNOWN
      elsif @script_type.nil? or @script_type.empty?
        javascript_context
      elsif @script_type =~ JSON_TYPES
        json_context
      elsif @script_type =~ JAVASCRIPT_TYPES
        javascript_context
      else
        TemplateContext::UNKNOWN
      end
    end

    SCRIPT_MODES = [:script, :script_dq, :script_sq, :script_bt,
                    :script_line_comment, :script_block_comment]

    def feed c
      # HTML parsers end raw script data at </script regardless of JavaScript
      # strings or comments.
      if SCRIPT_MODES.include?(@mode) and raw_script_end?(c)
        @mode = :data
        @raw_tail = +""
        @comment_tail = +""
        @pending_slash = false
        return
      end

      case @mode
      when :data then data_char c
      when :tag then tag_char c
      when :declaration then @mode = :data if c == ">"
      when :comment then comment_char c
      when :script then script_char c
      when :script_dq then js_string_char c, '"'
      when :script_sq then js_string_char c, "'"
      when :script_bt then js_string_char c, "`"
      when :script_line_comment then @mode = :script if c == "\n"
      when :script_block_comment
        if comment_tail(c, 2) == "*/"
          @mode = :script
        end
      when :style
        if comment_tail(c, 8).downcase == "</style"
          @mode = :data
        end
      end
    end

    def data_char c
      return unless c == "<"

      @mode = :tag
      @tag = +""
      @quote = nil
      @tag_name = nil
      @script_type = nil
      @script_type_unknown = false
      @tag_dynamic = false
      @attr_name = nil
      @string_escape = false
    end

    def comment_tail c, length
      @comment_tail = ((@comment_tail || "") + c)[-length, length] || ((@comment_tail || "") + c)
    end

    def comment_char c
      if comment_tail(c, 3) == "-->"
        @mode = :data
      end
    end

    def tag_char c
      if @quote
        @tag << c

        if @string_escape
          @string_escape = false
        elsif c == "\\"
          @string_escape = true
        elsif c == @quote
          @quote = nil
          @attr_name = nil
        end
      elsif c == '"' or c == "'"
        @quote = c
        @string_escape = false
        @attr_name = attribute_name
        @tag << c
      elsif c == ">"
        finish_tag
      else
        @tag << c
      end
    end

    def attribute_name
      @tag[/\b([A-Za-z_:][-A-Za-z0-9_:.]*)\s*=\s*\z/, 1]
    end

    def finish_tag
      header = @tag.strip

      if header.start_with? "!--"
        @mode = :comment
        @comment_tail = +""
        @tag = +""
        return
      elsif header.start_with? "!"
        @mode = :declaration
        @tag = +""
        return
      end

      self_closing = header.end_with? "/"
      end_tag = header.start_with? "/"
      name = header[/\A\/?\s*([A-Za-z][A-Za-z0-9:_-]*)/, 1]
      name = name && name.downcase
      attributes = header.sub(/\A\/?\s*[A-Za-z][A-Za-z0-9:_-]*/, "")

      @uncertain = true if @tag_dynamic and name.nil?

      if name == "script"
        @tag_name = name
        @script_type = extract_script_type(attributes)
        @script_type_unknown = @tag_dynamic
        @mode = (self_closing or end_tag) ? :data : :script
        @raw_tail = +""
      elsif name == "style"
        @mode = self_closing ? :data : :style
        @comment_tail = +""
      else
        @mode = :data
      end

      @tag = +""
      @quote = nil
      @attr_name = nil
    end

    def extract_script_type attributes
      if attributes =~ /\btype\s*=\s*(?:"([^"]*)"|'([^']*)')/i
        ($1 || $2).strip
      elsif attributes =~ /\btype\s*=\s*([^\s>]+)/i
        $1.strip
      end
    end

    # Track a possible </script terminator one character at a time. Any
    # mismatch restarts the buffered suffix so text like "<a</script>" still
    # ends the script correctly.
    def raw_script_end? c
      @raw_tail = ((@raw_tail || "") + c)[-8, 8] || ((@raw_tail || "") + c)

      unless "</script".start_with?(@raw_tail.downcase)
        @raw_tail = +""
        @raw_tail << c if c == "<"
      end

      @raw_tail.downcase == "</script"
    end

    def script_char c
      if @pending_slash
        @pending_slash = false

        if c == "/"
          @mode = :script_line_comment
          return
        elsif c == "*"
          @mode = :script_block_comment
          @comment_tail = +""
          return
        end
      end

      case c
      when '"'
        @mode = :script_dq
        @string_escape = false
      when "'"
        @mode = :script_sq
        @string_escape = false
      when "`"
        @mode = :script_bt
        @string_escape = false
      when "/"
        @pending_slash = true
      end
    end

    def js_string_char c, quote
      if @string_escape
        @string_escape = false
      elsif c == "\\"
        @string_escape = true
      elsif c == quote
        @mode = :script
      end
    end
  end

  # Walks a compiled template AST in output order and records the context of
  # each dynamic insertion.
  #
  # Understands the buffer operations produced by Brakeman's ERB, Erubi, HAML,
  # and Slim processors. Insertions in ambiguous positions (conditionals,
  # dynamic markup, unsupported filters) are recorded as unknown.
  class TemplateContextTracker
    include Brakeman::Util

    FILTER_JAVASCRIPT = /Filters::(?:Javascript|Coffee)\z/
    FILTER_OTHER = /Filters::(?:Sass|Scss|Markdown)\z/
    TRANSPARENT = [:to_s, :strip, :freeze]

    HTML_ESCAPE_METHODS = [:h, :escapeHTML, :escape_once, :html_escape,
                           :html_escape_without_haml_xss, :escape_html,
                           :escape_html_safe, :u, :url_encode]
    HTML_SAFE_METHODS = [:raw, :html_safe, :html_safe!, :content_tag, :tag,
                         :link_to, :safe_join, :sanitize, :strip_tags]
    HTML_ESCAPING_SAFE_METHODS = [:content_tag, :tag, :link_to, :safe_join]

    # Lines, the contexts seen at those lines, and the escaping/conversion
    # marks observed on the dynamic value emitted there.
    attr_reader :contexts, :flags

    def initialize ast
      @ast = ast
      @lexer = TemplateContextLexer.new
      @contexts = Hash.new { |h, k| h[k] = Set.new }
      @flags = Hash.new { |h, k| h[k] = Set.new }
      @line = nil
      @last_line = nil
      @force_unknown = 0
    end

    def scan
      walk @ast
      @contexts
    end

    private

    def walk node
      return unless sexp? node
      update_line node

      case node.node_type
      when :block, :rlist, :scope
        node.each { |child| walk child }
      when :output, :escaped_output, :format, :format_escaped
        walk node.value if sexp?(node.value)
      when :if
        walk_conditional node
      when :call, :safe_call
        walk_call node
      when :attrasgn, :safe_attrasgn
        walk_assignment node
      else
        node.each { |child| walk child if sexp?(child) }
      end
    end

    def update_line node
      line = node.original_line || node.line
      if line and line > 0
        @line = line
        @last_line = line
      end
    end

    def walk_call node
      if buffer_append? node
        handle_buffer_value node.args.first
      elsif haml_push? node
        node.args.each { |arg| handle_buffer_value arg }
      elsif push_script? node
        in_script { handle_buffer_value node.args.first }
      elsif filter_call? node
        handle_filter node
      elsif preserve_call? node
        handle_buffer_value node.args.first if node.args.first
      else
        node.each { |child| walk child if sexp?(child) }
      end
    end

    def walk_assignment node
      if node.method.to_s.end_with?("append=") and node.target.node_type == :ivar and
         node.target.value == :@output_buffer
        handle_buffer_value node.first_arg
      else
        node.each { |child| walk child if sexp?(child) }
      end
    end

    def walk_conditional node
      branches = [node.then_clause, node.else_clause]
      start_lexer = @lexer.dup

      results = branches.map do |branch|
        lexer = start_lexer.dup
        contexts = Hash.new { |h, k| h[k] = Set.new }
        flags = Hash.new { |h, k| h[k] = Set.new }

        saved = [@lexer, @contexts, @flags]
        @lexer, @contexts, @flags = lexer, contexts, flags
        begin
          walk branch if sexp?(branch)
        ensure
          @lexer, @contexts, @flags = saved
        end

        [lexer, contexts, flags]
      end

      merge_branch_results results

      end_states = results.map { |lexer, _, _| lexer.state_signature }
      if end_states.uniq.length == 1
        @lexer = results.first.first
      else
        @lexer = start_lexer
        @lexer.uncertain!
      end
    end

    # Merge the contexts/flags found in each branch. A line is only assigned a
    # context when every branch agrees on it.
    def merge_branch_results results
      lines = results.flat_map { |_, contexts, _| contexts.keys }.uniq

      lines.each do |line|
        context_sets = results.map { |_, contexts, _| contexts[line] }

        # Values that are found only in one branch cannot be assigned a
        # definite surrounding context.
        if context_sets.any?(&:empty?)
          @contexts[line] << TemplateContext::UNKNOWN
        elsif context_sets.all? { |set| set == context_sets.first } and
              context_sets.first.length == 1
          @contexts[line] << context_sets.first.first
        else
          @contexts[line] << TemplateContext::UNKNOWN
        end
      end

      flag_results = results.map { |_, _, flags| flags }
      lines = flag_results.flat_map(&:keys).uniq

      lines.each do |line|
        sets = flag_results.map { |flags| flags[line] }

        if sets.all? { |set| set == sets.first }
          @flags[line].merge sets.first
        end
      end
    end

    def each_dynamic_value node, &block
      return unless sexp? node

      if dynamic_value? node
        yield node
      else
        node.each { |child| each_dynamic_value child, &block if sexp?(child) }
      end
    end

    def dynamic_value? node
      case node.node_type
      when :str, :lit, :nil, :true, :false, :arglist, :args, :hash, :array
        false
      when :call, :safe_call
        !TRANSPARENT.include?(node.method)
      else
        true
      end
    end

    def buffer_append? node
      return false unless [:<<, :concat, :safe_concat].include? node.method

      buffer_target? node.target
    end

    def buffer_target? target
      return false unless sexp? target

      case target.node_type
      when :lvar
        target.value == :_erbout or target.value == :_buf
      when :ivar
        target.value == :@output_buffer
      when :const
        [:SafeBuffer, :OutputBuffer].include? target.value
      when :call
        target.method == :buffer or buffer_target?(target.target)
      else
        false
      end
    end

    def haml_push? node
      [:push_text, :fix_textareas!].include?(node.method) and
        call? node.target and node.target.method == :_hamlout
    end

    def push_script? node
      node.method == :push_script and call? node.target and node.target.method == :_hamlout
    end

    def preserve_call? node
      [:find_and_preserve, :preserve].include? node.method
    end

    def filter_call? node
      name = class_name(node.target).to_s
      !!(name =~ FILTER_JAVASCRIPT or name =~ FILTER_OTHER or name.end_with?("BrakemanFilter"))
    end

    def handle_filter node
      name = class_name(node.target).to_s

      if name =~ FILTER_JAVASCRIPT
        in_script { handle_buffer_value node.args.first }
      elsif name.end_with?("BrakemanFilter")
        # The Haml 6 and Slim shims wrap filter text in BrakemanFilter.render.
        # Haml 6 does not pass the engine, so use the surrounding text. Slim
        # passes it, which lets non-JavaScript filters (Sass, Markdown) stay
        # out of script context.
        engine = class_name(node.args[1]).to_s

        if engine.empty?
          handle_buffer_value node.args.first
        elsif engine =~ /(?:Coffee|JavaScript)/
          in_script { handle_buffer_value node.args.first }
        elsif @lexer.context == TemplateContext::UNKNOWN
          with_unknown { handle_buffer_value node.args.first }
        else
          # Markdown/Sass text is not JavaScript even if the shim wrapped it
          # in script tags.
          with_unknown { handle_buffer_value node.args.first }
        end
      end
    end

    def in_script
      @lexer.text "<script>"
      yield
      @lexer.text "</script>"
    end

    def htmlescape_call? value
      HTML_ESCAPE_METHODS.include? value.method
    end

    def add_flags_only value
      line = value.original_line || value.line || @line
      line = @last_line unless line and line > 0
      return unless line and line > 0

      value_flags(value).each { |flag| @flags[line] << flag }
    end

    # Mark dynamic values produced by a non-script filter as unknown instead
    # of inheriting a surrounding <script> element that the template engine
    # shim happened to emit.
    def with_unknown
      @force_unknown += 1
      yield
    ensure
      @force_unknown -= 1
    end

    def handle_buffer_value value
      return unless sexp? value
      update_line value

      case value.node_type
      when :str
        @lexer.text value.value
      when :lit
        @lexer.text value.value if value.value.is_a? String
      when :dstr
        value.each do |part|
          if part.is_a? String
            @lexer.text part
          elsif sexp?(part)
            if part.node_type == :str
              @lexer.text part.value
            elsif part.node_type == :evstr
              handle_buffer_value part.value
            else
              handle_buffer_value part
            end
          end
        end
      when :evstr
        handle_buffer_value value.value
      when :call, :safe_call
        if TRANSPARENT.include? value.method
          handle_buffer_value(value.target || value.first_arg)
        elsif preserve_call? value
          value.args.each { |arg| handle_buffer_value arg if sexp?(arg) }
        elsif filter_call? value
          handle_filter value
        elsif htmlescape_call? value
          add_flags_only value
          handle_buffer_value(value.target || value.first_arg)
        else
          add_dynamic value
        end
      else
        add_dynamic value
      end
    end

    def add_dynamic value
      @lexer.dynamic_value!
      context = @force_unknown > 0 ? TemplateContext::UNKNOWN : @lexer.context
      add_context value, context
      add_flags value
    end

    def add_context value, context
      line = value.original_line || value.line || @line
      line = @last_line unless line and line > 0
      return unless line and line > 0

      @contexts[line] << context
    end

    def add_flags value
      line = value.original_line || value.line || @line
      line = @last_line unless line and line > 0
      return unless line and line > 0

      value_flags(value).each { |flag| @flags[line] << flag }
    end

    # Determine the conversions applied inside the emitted expression. This
    # is used because some template processors unwrap raw()/j() before
    # recording the output expression.
    def value_flags value, depth = 0
      flags = Set.new
      return flags unless sexp?(value)
      return flags if depth > 12

      case value.node_type
      when :call, :safe_call
        method = value.method

        if method == :j or method == :escape_javascript
          flags << :js_escaped
          flags << :html_safe
          flags.merge value_flags(value.first_arg, depth + 1)
        elsif HTML_ESCAPING_SAFE_METHODS.include? method
          flags << :html_escaped
          flags << :html_safe
          flags.merge value_flags(value.target || value.first_arg, depth + 1)
        elsif HTML_SAFE_METHODS.include? method
          flags << :html_safe
          flags.merge value_flags(value.target || value.first_arg, depth + 1)
        elsif HTML_ESCAPE_METHODS.include? method
          flags << :html_escaped
          flags.merge value_flags(value.target || value.first_arg, depth + 1)
        elsif method == :to_json or method == :encode
          flags << :json
          flags.merge value_flags(value.target, depth + 1)
        elsif TRANSPARENT.include? method
          flags.merge value_flags(value.target || value.first_arg, depth + 1)
        else
          value.each_arg { |arg| flags.merge value_flags(arg, depth + 1) }
        end
      when :dstr, :evstr, :if, :or, :and
        value.each do |child|
          flags.merge value_flags(child, depth + 1) if sexp?(child)
        end
      end

      flags
    end
  end
end
