require_relative '../test'

# Exercises Brakeman::CheckTranslationXSS against a small fixture that contains
# two locales (en, es) and a default/fallback chain. The same tainted value
# (params[:name]) flows through plain text keys, HTML semantic keys, call-level
# defaults and dynamic keys; each combination must produce a distinct,
# explainable warning rather than one blanket rule for every call.
class TranslationXSSTests < Minitest::Test
  include BrakemanTester::FindWarning
  include BrakemanTester::CheckExpected

  VIEW = /show\.html\.erb/

  def report
    @@report ||= BrakemanTester.run_scan "translation_xss", "Translation XSS", run_all_checks: true
  end

  def expected
    @@expected ||= {
      :controller => 0,
      :model => 0,
      :template => 12,
      :generic => 2
    }
  end

  # Case 1: plain text key with tainted interpolation is escaped -> no
  # translation warning (only fixed trusted text is involved).
  def test_plain_text_key_with_tainted_interpolation_has_no_translation_warning
    assert_no_warning :type => :template,
      :warning_code => 130,
      :line => 2,
      :file => VIEW
  end

  # Case 2: HTML semantic key + tainted interpolation -> high confidence XSS,
  # pinned to the locale source that grants the HTML capability.
  def test_html_key_tainted_interpolation
    assert_warning :type => :template,
      :warning_code => 130,
      :confidence => 0,
      :line => 5,
      :file => VIEW,
      :message => /Unescaped interpolation.*%\{name\}.*parameter.*HTML translation key.*greetings\.bold_html.*en\.yml/
  end

  # Case 3: HTML key with fixed trusted text and no interpolation -> a weak
  # capability notice, not a high-confidence XSS (trusted text != safe args).
  def test_html_key_fixed_text_only_is_weak
    assert_warning :type => :template,
      :warning_code => 130,
      :confidence => 2,
      :line => 8,
      :file => VIEW,
      :message => /HTML translation key.*greetings\.safe_html.*rendered without escaping.*no tainted interpolation/
  end

  # Case 4: plain primary key whose symbol default resolves to an HTML key ->
  # both an HTML-leg warning and an explicit capability-switch warning. The
  # primary key's "text is safe" conclusion must not be reused.
  def test_fallback_switches_text_to_html_capability
    assert_warning :type => :template,
      :warning_code => 131,
      :confidence => 0,
      :line => 11,
      :file => VIEW,
      :message => /Fallback.*fallback\.html_tail_html.*switches.*from text to HTML capability/
  end

  def test_fallback_html_leg_also_reported
    assert_warning :type => :template,
      :warning_code => 130,
      :confidence => 0,
      :line => 11,
      :file => VIEW,
      :message => /HTML translation key.*fallback\.html_tail_html/
  end

  # Case 5: HTML primary key with a plain-text fallback still warns on the
  # primary HTML leg (the primary key is tried first and is itself HTML).
  def test_html_primary_with_text_fallback_warns_primary
    assert_warning :type => :template,
      :warning_code => 130,
      :confidence => 0,
      :line => 14,
      :file => VIEW,
      :message => /HTML translation key.*greetings\.bold_html/
  end

  # Case 6: call-level string default gives inline text capability even though
  # the primary key is missing -> escaped, no translation warning.
  def test_call_level_string_default_is_text_capability
    assert_no_warning :type => :template,
      :warning_code => 132,
      :line => 17,
      :file => VIEW
  end

  # Case 7: dynamic, unresolvable key -> medium dynamic-key warning.
  def test_dynamic_key
    assert_warning :type => :template,
      :warning_code => 132,
      :confidence => 1,
      :line => 20,
      :file => VIEW,
      :message => /Dynamic translation key.*params\[:key\].*cannot be resolved statically/
  end

  # Case 8: plain text key passed through raw() -> dedicated raw-bypass warning,
  # distinct from the generic CrossSiteScripting warning that also fires.
  def test_raw_plain_text_translation
    assert_warning :type => :template,
      :warning_code => 133,
      :confidence => 0,
      :line => 23,
      :file => VIEW,
      :message => /Plain-text translation.*pages\.title.*raw.*%\{name\}.*bypasses HTML escaping/

    assert_warning :type => :template,
      :warning_code => 2,
      :confidence => 2,
      :line => 23,
      :file => VIEW
  end

  # Case 9: HTML key with a non-tainted interpolation stays weak.
  def test_html_key_with_safe_interpolation_is_weak
    assert_warning :type => :template,
      :warning_code => 130,
      :confidence => 2,
      :line => 26,
      :file => VIEW
  end

  # Case 10: translate() alias behaves like t() for a plain key -> no warning.
  def test_translate_alias_plain_key
    assert_no_warning :type => :template,
      :warning_code => 130,
      :line => 29,
      :file => VIEW
  end

  # Case 11: I18n.t library helper follows the same HTML capability rules.
  def test_i18n_t_html_key
    assert_warning :type => :template,
      :warning_code => 130,
      :confidence => 0,
      :line => 32,
      :file => VIEW,
      :message => /I18n\.t|greetings\.bold_html/
  end

  # Case 12: array default chain where the second leg is HTML -> the switch is
  # attributed to the specific second leg, not the first text leg.
  def test_array_default_chain_second_leg_switch
    warning = report[:template_warnings].find do |w|
      w.warning_code == 131 and w.line == 35
    end

    refute_nil warning, "Expected a capability-switch warning on line 35"
    assert_match(/fallback\.html_tail_html/, warning.message.to_s)
    refute_match(/fallback\.text_tail.*switches/, warning.message.to_s)
  end

  # The two locales must both contribute source locations; the Spanish locale
  # proves the store parses more than one file.
  def test_locale_store_parses_both_locales
    store = Brakeman::LocaleStore.new(Brakeman::AppTree.new(report_app_path))

    bold = store["greetings.bold_html"]
    refute_nil bold
    assert_equal Set[:name], bold.placeholders
    assert bold.html_key
    assert_equal ["en", "es"].sort, bold.values.keys.sort
    assert_equal "<b>Hola %{name}</b>", bold.value_for("es")
  end

  def test_locale_store_distinguishes_plain_and_html_keys
    store = Brakeman::LocaleStore.new(Brakeman::AppTree.new(report_app_path))

    refute store["greetings.plain"].html_key
    assert store["greetings.bold_html"].html_key
    assert_nil store["greetings.does_not_exist"]
  end

  private

  def report_app_path
    File.expand_path("../../apps/translation_xss", __FILE__)
  end
end
