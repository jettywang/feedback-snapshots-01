# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path('../lib', __dir__)
require 'grape-entity'

require_relative 'tracer'
require_relative 'role_dsl'
require_relative 'example_a_direct'
require_relative 'example_b_shortcircuit'
require_relative 'blocked_catalog'

module Runner
  module_function

  def render(klass, object, options)
    RoleMigration::Tracer.reset!
    output = klass.new(object, options).serializable_hash
    {
      output: output,
      inits: RoleMigration::Tracer.entity_inits.map { |e| { entity: e[:entity], options: e[:options] } },
      fields: RoleMigration::Tracer.records.map { |r| snapshot(r) }
    }
  end

  def snapshot(record)
    {
      field: record[:field],
      exposed: record[:exposed],
      short_circuited: record[:short_circuited],
      calls: record[:calls].map { |c| "#{c[:index]}/#{c[:of]} #{c[:kind]}#{c[:inverse] ? '(unless)' : ''}[#{c[:detail].inspect}] => #{c[:result]}" }
    }
  end

  def assert_equal(actual, expected, message)
    raise "EQUIVALENCE FAILURE: #{message}\n expected=#{expected.inspect}\n actual=#{actual.inspect}" unless actual == expected

    @passes << message
  end

  def run_a
    lines = []
    lines << '## Example A — directly migratable (old view == new role)'
    lines << ''
    ExampleAData::CASES.each do |test_case|
      gadget = ExampleAData.gadget
      old_base = render(OldGadgetEntity, gadget, test_case[:old])
      new_base = render(NewGadgetEntity, gadget, test_case[:new])
      old_pro = render(OldGadgetProEntity, gadget, test_case[:old])
      new_pro = render(NewGadgetProEntity, gadget, test_case[:new])

      assert_equal(new_base[:output], old_base[:output], "A/base output identical [#{test_case[:label]}]")
      assert_equal(new_pro[:output], old_pro[:output], "A/Pro  output identical [#{test_case[:label]}]")

      lines << "### case #{test_case[:label]}"
      lines << "- public output (old == new): `#{new_base[:output].inspect}`"
      lines << "- Pro output   (old == new): `#{new_pro[:output].inspect}`"
      lines << '- nested entity actually constructed + options received:'
      new_base[:inits].each { |i| lines << "    - `#{i[:entity]}` got `#{i[:options].inspect}`" }
      lines << '- condition call order (NEW pipeline, short-circuit visible):'
      new_base[:fields].each do |f|
        marker = f[:short_circuited] ? ' [SHORT-CIRCUIT]' : ''
        lines << "    - #{f[:field]} exposed=#{f[:exposed]}#{marker}"
        f[:calls].each { |c| lines << "        - #{c}" }
      end
      lines << ''
    end
    lines
  end

  def run_b
    lines = []
    lines << '## Example B — inherited gate + parent short-circuit'
    lines << ''
    doc = ExampleBData.document
    results = ExampleBData::CASES.map do |test_case|
      opts = { role: test_case[:role], view: test_case[:view] }
      {
        label: test_case[:label],
        old: render(OldMemoEntity, doc, opts),
        naive: render(NaiveMemoEntity, doc, opts),
        fixed: render(FixedMemoEntity, doc, opts)
      }
    end

    # Fix must reproduce the OLD visibility for every role.
    results.each do |r|
      assert_equal(r[:fixed][:output], r[:old][:output], "B/fixed preserves old visibility [#{r[:label]}]")
    end

    # Naive must over-expose for :auditor exactly the fields the old view gate
    # used to hide: archive_code (inherited gate broadened) + risk_score
    # (trailing gate now evaluated and passing).
    auditor = results.find { |r| r[:label] == 'auditor' }
    over = auditor[:naive][:output].keys - auditor[:old][:output].keys
    raise "unexpected over-exposure: #{over.inspect}" unless over.sort == %i[archive_code risk_score].sort

    @over_exposed = over

    # Distinguish "newly visible because decision ORDER changed" from
    # "condition never evaluated" (short-circuit / unconditional fields).
    auditor_old_fields = auditor[:old][:fields]
    never_evaluated = auditor_old_fields.select { |f| f[:short_circuited] }.map do |f|
      "#{f[:field]} (#{f[:calls].size} of its conditions ran; the rest were skipped)"
    end
    no_gate = auditor_old_fields.select { |f| f[:calls].empty? }.map { |f| f[:field] }
    lines << '### auditor summary — over-exposure vs not-evaluated'
    lines << "- OVER-EXPOSED by naive rewrite (order change made a gate pass): #{over.inspect}"
    lines << "- NOT EVALUATED in OLD rule (parent gate short-circuited the chain): #{never_evaluated.inspect}"
    lines << "- NO GATE AT ALL (unconditional, evaluated trivially / always present): #{no_gate.inspect}"
    lines << ''

    results.each do |r|
      lines << "### role=#{r[:label]}"
      lines << "- OLD public output   : `#{r[:old][:output].inspect}`"
      lines << "- NAIVE public output : `#{r[:naive][:output].inspect}`"
      lines << "- FIXED public output : `#{r[:fixed][:output].inspect}`"
      custodian_built = ->(rendered) { rendered[:inits].any? { |i| i[:entity].end_with?('CustodianEntity') } }
      lines << "- nested custodian constructed? OLD=#{custodian_built.call(r[:old])} NAIVE=#{custodian_built.call(r[:naive])} FIXED=#{custodian_built.call(r[:fixed])}"
      r[:fixed][:inits].select { |i| i[:entity].end_with?('CustodianEntity') }.each do |i|
        lines << "    - custodian options when built: `#{i[:options].inspect}`"
      end
      lines << '- OLD archive_code condition order (first gate fails => trailing block NOT evaluated):'
      r[:old][:fields].find { |f| f[:field] == :archive_code }&.then do |f|
        lines << "    - exposed=#{f[:exposed]} short_circuited=#{f[:short_circuited]}"
        f[:calls].each { |c| lines << "        - #{c}" }
      end
      lines << '- fields with NO condition (never evaluated, simply always present):'
      no_cond = r[:old][:fields].select { |f| f[:calls].empty? }.map { |f| f[:field] }
      lines << "    - #{no_cond.inspect}"
      lines << ''
    end
    lines
  end

  def run_catalog
    lines = []
    lines << '## Migration classifier — blocked declaration sites'
    lines << ''
    lines << '| entity.field | verdict | reason | suggested rewrite |'
    lines << '|---|---|---|---|'
    [EntityB1, EntityB2, EntityB3, EntityB4, EntityB5, EntityB6, EntityControl].each do |klass|
      klass.root_exposures.each do |exposure|
        verdict = RoleMigration::MigrationClassifier.classify(exposure)
        key = "#{klass.name}.#{verdict[:field]}"
        guidance = BlockedData::GUIDANCE[key] || 'pure role gate — safe to migrate mechanically'
        reason = verdict[:reasons].empty? ? 'all conditions are role-derived' : verdict[:reasons].join('; ')
        lines << "| #{key} | #{verdict[:status]} | #{reason} | #{guidance} |"
      end
    end
    lines
  end

  def run
    @passes = []
    report = []
    report << '# Grape Entity view -> role migration evidence'
    report << ''
    report.concat(run_a)
    report.concat(run_b)
    report.concat(run_catalog)

    report << '## Assertions'
    @passes.each { |p| report << "- PASS: #{p}" }
    report << "- PASS: naive migration over-exposes #{@over_exposed.inspect} for :auditor (the trap)"

    File.write(File.join(__dir__, 'evidence_report.md'), "#{report.join("\n")}\n")
    puts report
    puts "\n#{@passes.size + 1} assertions passed. Report -> role_migration/evidence_report.md"
  end
end

Runner.run
