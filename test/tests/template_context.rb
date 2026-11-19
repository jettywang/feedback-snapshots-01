require_relative '../test'
require 'brakeman/template_context'

class TemplateContextTests < Minitest::Test
  include Brakeman

  # Assign increasing line numbers to the top-level statements of a synthetic
  # compiled template.
  def with_lines ast
    ast.each_with_index do |node, index|
      node.line(index + 1) if node.is_a?(Sexp)
    end
    ast
  end

  def context_for text
    lexer = Brakeman::TemplateContextLexer.new
    lexer.text text
    lexer.context
  end

  def test_html_context
    assert_equal Brakeman::TemplateContext::HTML, context_for("<p>")
    assert_equal Brakeman::TemplateContext::HTML, context_for("<p>text</p>")
    assert_equal Brakeman::TemplateContext::HTML_ATTRIBUTE, context_for('<a href="')
  end

  def test_script_string_context
    assert_equal Brakeman::TemplateContext::SCRIPT_STRING, context_for('<script>var x = "')
    assert_equal Brakeman::TemplateContext::SCRIPT_STRING, context_for("<script>var x = '")
    assert_equal Brakeman::TemplateContext::SCRIPT_STRING, context_for("<script>var x = 'abc'; var y = '")
  end

  def test_script_expression_context
    assert_equal Brakeman::TemplateContext::SCRIPT_EXPRESSION, context_for("<script>var x = ")
    assert_equal Brakeman::TemplateContext::SCRIPT_EXPRESSION, context_for("<script>if (")
    assert_equal Brakeman::TemplateContext::SCRIPT_EXPRESSION, context_for("<script>var x = \"a\"; var y = ")
  end

  def test_template_literal_context
    assert_equal Brakeman::TemplateContext::SCRIPT_TEMPLATE, context_for("<script>var x = `")
  end

  def test_json_context
    assert_equal Brakeman::TemplateContext::JSON, context_for('<script type="application/json">')
    assert_equal Brakeman::TemplateContext::JSON_STRING, context_for('<script type="application/json">{"x": "')
    assert_equal Brakeman::TemplateContext::JSON, context_for('<script type="application/ld+json">{"x": ')
  end

  def test_closing_script_tag_is_not_script_context
    assert_equal Brakeman::TemplateContext::HTML, context_for("</script>")
    assert_equal Brakeman::TemplateContext::HTML, context_for("</script><p>")
    assert_equal Brakeman::TemplateContext::HTML, context_for("<script/>")
  end

  def test_script_ends_at_closing_tag_after_literal_less_than
    assert_equal Brakeman::TemplateContext::HTML, context_for("<script>if (a < b) {}</script><p>")
    assert_equal Brakeman::TemplateContext::HTML, context_for("<script>if (a <s b) {}</script><p>")
  end

  def test_script_ends_at_closing_tag
    assert_equal Brakeman::TemplateContext::HTML, context_for('<script>var x = "</script><p>')
    assert_equal Brakeman::TemplateContext::HTML, context_for('<script>// comment</script><p>')
    assert_equal Brakeman::TemplateContext::HTML, context_for('<script>/* comment */</script><p>')
  end

  def test_unknown_contexts
    assert_equal Brakeman::TemplateContext::UNKNOWN, context_for("<scr")
    assert_equal Brakeman::TemplateContext::UNKNOWN, context_for("<!-- ")
    assert_equal Brakeman::TemplateContext::UNKNOWN, context_for('<script type="text/template">')
    assert_equal Brakeman::TemplateContext::UNKNOWN, context_for("<style>")
  end

  # Comments are still script source: a value containing a newline or */
  # can break out, so they are not treated as inert.
  def test_script_comments_are_script_context
    assert_equal Brakeman::TemplateContext::SCRIPT_EXPRESSION, context_for("<script>// ")
    assert_equal Brakeman::TemplateContext::SCRIPT_EXPRESSION, context_for("<script>/* ")
  end

  def test_dynamic_tag_becomes_unknown
    lexer = Brakeman::TemplateContextLexer.new
    lexer.text "<div "
    lexer.dynamic_value!
    lexer.text 'class="x">'
    lexer.text "<script>var x = "
    assert_equal Brakeman::TemplateContext::UNKNOWN, lexer.context
  end

  def test_inline_event_handler_is_script_expression
    assert_equal Brakeman::TemplateContext::SCRIPT_EXPRESSION, context_for('<a onclick="')
  end

  def test_compiled_erb_ast
    ast = RubyParser.new.parse(<<~RUBY)
      _erbout = +''
      _erbout.<< "<p>"
      _erbout.<<(( params[:html] ).to_s)
      _erbout.<< "</p><script>\\nvar a = \\""
      _erbout.<<(( params[:str] ).to_s)
      _erbout.<< "\\";\\nvar b = "
      _erbout.<<(( params[:expr] ).to_s)
      _erbout.<< ";\\nvar c = \\""
      _erbout.<<(( j params[:js] ).to_s)
      _erbout.<< "\\";\\n"
    RUBY
    ast = with_lines(ast)

    tracker = Brakeman::TemplateContextTracker.new(ast)
    contexts = tracker.scan

    assert_equal Set[TemplateContext::HTML], contexts[3]
    assert_equal Set[TemplateContext::SCRIPT_STRING], contexts[5]
    assert_equal Set[TemplateContext::SCRIPT_EXPRESSION], contexts[7]
    assert_equal Set[TemplateContext::SCRIPT_STRING], contexts[9]
  end

  def test_haml_javascript_filter
    # Build the shape the HAML processor actually sees.
    ast = s(:call, nil, :find_and_preserve,
            s(:call, s(:colon2, s(:colon2, s(:const, :Haml), :Filters), :Javascript), :render_with_options,
              s(:dstr, "\nvar a = \"", s(:evstr, s(:call, nil, :j, s(:call, s(:call, nil, :params), :[], s(:lit, :a)))),
                      s(:str, "\";\nvar b = "), s(:evstr, s(:call, nil, :j, s(:call, s(:call, nil, :params), :[], s(:lit, :b)))),
                      s(:str, ";\n")),
              s(:call, nil, :_hamlout)),
            s(:call, nil, :_hamlout))
    ast.line(2)

    contexts = Brakeman::TemplateContextTracker.new(ast).scan
    assert_equal Set[TemplateContext::SCRIPT_STRING, TemplateContext::SCRIPT_EXPRESSION], contexts[2]
  end

  def test_haml_push_text_inside_script
    ast = s(:block,
            s(:call, s(:call, nil, :_hamlout), :push_text, s(:str, "<script>\nvar a = \"")),
            s(:call, s(:call, nil, :_hamlout), :push_text,
              s(:dstr, "", s(:evstr, s(:call, nil, :j, s(:call, s(:call, nil, :params), :[], s(:lit, :a)))))),
            s(:call, s(:call, nil, :_hamlout), :push_text, s(:str, "\";\n</script>")),
            s(:call, s(:call, nil, :_hamlout), :push_text, s(:str, "<p>")))
    ast.line(2)

    tracker = Brakeman::TemplateContextTracker.new(ast)
    contexts = tracker.scan

    assert_equal Set[TemplateContext::SCRIPT_STRING], contexts[2]
    assert_equal Set[:js_escaped, :html_safe], tracker.flags[2]
  end

  def test_haml6_filter_shim
    ast = s(:block,
            s(:call, s(:ivar, :@output_buffer), :safe_concat, s(:str, "<script>\n")),
            s(:call, s(:ivar, :@output_buffer), :safe_concat,
              s(:call, s(:call, s(:const, :BrakemanFilter), :render),
                s(:dstr, "\nvar x = ", s(:evstr, s(:call, s(:call, nil, :params), :[], s(:lit, :x)))))),
            s(:call, s(:ivar, :@output_buffer), :safe_concat, s(:str, "\n</script>")))
    ast.line(3)

    contexts = Brakeman::TemplateContextTracker.new(ast).scan
    assert_equal Set[TemplateContext::SCRIPT_EXPRESSION], contexts[3]
  end

  def test_conditional_branches_with_same_state
    branch_value = s(:call, s(:call, nil, :params), :[], s(:lit, :a))
    ast = s(:block,
            s(:call, s(:ivar, :@output_buffer), :safe_concat, s(:str, "<script>\nvar a = ")),
            s(:if, s(:call, s(:call, nil, :params), :[], s(:lit, :cond)),
              s(:call, s(:ivar, :@output_buffer), :safe_concat, s(:dstr, "\"", s(:evstr, branch_value))),
              s(:call, s(:ivar, :@output_buffer), :safe_concat, s(:dstr, "\"", s(:evstr, branch_value)))),
            s(:call, s(:ivar, :@output_buffer), :safe_concat, s(:dstr, "", s(:evstr, branch_value))))
    ast = with_lines ast

    contexts = Brakeman::TemplateContextTracker.new(ast).scan
    # Each branch inserts a value inside a newly opened JavaScript string, so
    # both branches agree and the later insertion is still in that string.
    assert_equal Set[TemplateContext::SCRIPT_STRING], contexts[3]
    assert_equal Set[TemplateContext::SCRIPT_STRING], contexts[4]
  end

  def test_conditional_one_sided_branch_is_unknown
    value = s(:call, s(:call, nil, :params), :[], s(:lit, :a))
    ast = s(:block,
            s(:call, s(:ivar, :@output_buffer), :safe_concat, s(:str, "<script>\nvar a = \"")),
            s(:if, s(:call, s(:call, nil, :params), :[], s(:lit, :cond)),
              s(:call, s(:ivar, :@output_buffer), :safe_concat, s(:dstr, "", s(:evstr, value))),
              nil),
            s(:call, s(:ivar, :@output_buffer), :safe_concat, s(:str, "\";\n")))
    ast.line(2)

    contexts = Brakeman::TemplateContextTracker.new(ast).scan
    assert_equal Set[TemplateContext::UNKNOWN], contexts[2]
  end
end
