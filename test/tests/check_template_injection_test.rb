require_relative '../test'

class CheckTemplateInjectionTests < Minitest::Test
  #Builds a tracker from inline Ruby source, indexes the call sites, runs the
  #template injection check, and returns the generated warnings.
  def warnings_for source
    tracker = BrakemanTester.new_tracker
    ast = RubyParser.new.parse(source)
    Brakeman::LibraryProcessor.new(tracker).process_library(ast, "fake_file.rb")
    tracker.index_call_sites

    check = Brakeman::CheckTemplateInjection.new(tracker)
    check.run_check
    check.warnings
  end

  def assert_one_warning source, confidence, line, code_line = nil
    warnings = warnings_for(source)
    matching = warnings.select { |w| w.warning_type == "Template Injection" }
    assert_equal 1, matching.length, "expected exactly one template injection warning, got #{matching.length}"
    warning = matching.first
    assert_equal confidence, warning.confidence_name
    assert_equal line, warning.line
    assert_equal code_line, warning.code.line if code_line
    warning
  end

  def assert_no_warning source
    warnings = warnings_for(source)
    matching = warnings.select { |w| w.warning_type == "Template Injection" }
    assert_equal 0, matching.length, "expected no template injection warning, got #{matching.map(&:message)}"
  end

  def test_direct_execution_of_request_source
    source = <<~RUBY
      class Reporter
        def run
          ERB.new(params[:template]).result
        end
      end
    RUBY

    warning = assert_one_warning source, "High", 3
    assert_equal "Template Injection", warning.warning_type
    assert_equal [1336], warning.cwe_id
  end

  def test_alias_of_compiled_object_is_executed
    source = <<~RUBY
      class Reporter
        def run
          template = ERB.new(params[:template])
          template.result
        end
      end
    RUBY

    assert_one_warning source, "High", 3
  end

  def test_constructed_but_not_executed_is_lower_confidence
    source = <<~RUBY
      class Reporter
        def run
          ERB.new(params[:template])
        end
      end
    RUBY

    assert_one_warning source, "Medium", 3
  end

  def test_alias_constructed_but_not_executed_is_lower_confidence
    source = <<~RUBY
      class Reporter
        def run
          template = ERB.new(params[:template])
          template
        end
      end
    RUBY

    assert_one_warning source, "Medium", 3
  end

  def test_constant_template_source_is_not_flagged
    source = <<~RUBY
      class Reporter
        def run
          ERB.new("hello <%= 1 %>").result
        end
      end
    RUBY

    assert_no_warning source
  end

  def test_template_variables_are_not_treated_as_source
    source = <<~RUBY
      class Reporter
        def run
          ERB.new("hi <%= name %>").result_with_hash(name: params[:name])
        end
      end
    RUBY

    assert_no_warning source
  end

  def test_html_escaped_request_source_is_still_flagged
    source = <<~RUBY
      class Reporter
        def run
          ERB.new(ERB::Util.html_escape(params[:template])).result
        end
      end
    RUBY

    assert_one_warning source, "High", 3
  end

  def test_html_escaped_output_alone_is_not_flagged
    source = <<~RUBY
      class Reporter
        def run
          ERB::Util.html_escape(params[:template])
        end
      end
    RUBY

    assert_no_warning source
  end

  def test_request_source_through_one_helper_layer
    source = <<~RUBY
      class Reporter
        def entry
          compile(params[:template]).result
        end

        def compile(input)
          ERB.new(input)
        end
      end
    RUBY

    #Warning line anchors on the request input while +code+ keeps the
    #ERB.new compilation site inside the helper.
    assert_one_warning source, "High", 3, 7
  end

  def test_request_source_through_two_helper_layers
    source = <<~RUBY
      class Reporter
        def entry
          render_tpl(build_tpl(params[:template]))
        end

        def build_tpl(input)
          ERB.new(input)
        end

        def render_tpl(template)
          template.result
        end
      end
    RUBY

    #Warning line anchors on the request input while +code+ keeps the
    #ERB.new compilation site inside the helper.
    assert_one_warning source, "High", 3, 7
  end

  def test_helper_with_untainted_parameter_is_not_flagged
    source = <<~RUBY
      class Reporter
        def compile(input)
          ERB.new(input)
        end
      end
    RUBY

    assert_no_warning source
  end

  def test_unknown_factory_is_not_speculatively_flagged
    source = <<~RUBY
      class Reporter
        def run
          TemplateEngine.compile(params[:template]).render
        end
      end
    RUBY

    assert_no_warning source
  end

  def test_dynamic_string_interpolation_in_source_is_executed
    source = <<~'RUBY'
      class Reporter
        def run
          ERB.new("prefix-#{params[:template]}").result
        end
      end
    RUBY

    assert_one_warning source, "High", 3
  end

  def test_safe_interpolation_with_only_literals_is_not_flagged
    source = <<~RUBY
      class Reporter
        def run
          ERB.new("prefix-#{1}").result
        end
      end
    RUBY

    assert_no_warning source
  end

  def test_cookie_input_in_source_is_flagged
    source = <<~RUBY
      class Reporter
        def run
          ERB.new(cookies[:template]).result
        end
      end
    RUBY

    assert_one_warning source, "High", 3
  end

  def test_erubi_engine_executed
    source = <<~RUBY
      class Reporter
        def run
          Erubi.new(params[:template]).render
        end
      end
    RUBY

    assert_one_warning source, "High", 3
  end

  def test_haml_engine_alias_executed
    source = <<~RUBY
      class Reporter
        def run
          engine = Haml::Engine.new(params[:template])
          engine.render
        end
      end
    RUBY

    assert_one_warning source, "High", 3
  end

  def test_slim_template_constructed_but_not_executed
    source = <<~RUBY
      class Reporter
        def run
          Slim::Template.new(params[:template])
        end
      end
    RUBY

    assert_one_warning source, "Medium", 3
  end

  def test_plain_render_text_is_not_template_injection
    source = <<~RUBY
      class Reporter
        def run
          render plain: params[:template]
        end
      end
    RUBY

    assert_no_warning source
  end

  def test_instance_variable_alias_is_executed
    source = <<~RUBY
      class Reporter
        def run
          @template = ERB.new(params[:template])
          @template.result
        end
      end
    RUBY

    assert_one_warning source, "High", 3
  end

  def test_execution_inside_block_is_observed
    source = <<~RUBY
      class Reporter
        def run
          [1, 2].map { |item| ERB.new(params[:template]).result }
        end
      end
    RUBY

    assert_one_warning source, "High", 3
  end

  def test_tainted_source_through_escape_helper_is_still_flagged
    source = <<~RUBY
      class Reporter
        def run
          ERB.new(h(params[:template])).result
        end
      end
    RUBY

    assert_one_warning source, "High", 3
  end
end
