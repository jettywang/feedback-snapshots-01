require 'spec_helper'
require 'bundler/audit/scanner'

describe Bundler::Audit::Runtime::Assessment do
  let(:database) { 'spec/fixtures/runtime/database' }
  let(:advisories) { Bundler::Audit::Runtime::AdvisorySet.new(database) }
  let(:declaration) { nil }

  def assess(target,advisory_set: advisories,declaration: nil)
    described_class.new(
      target:       target,
      advisory_set: advisory_set,
      declaration:  declaration
    )
  end

  describe "MRI target" do
    it "reports an unpatched MRI version" do
      target     = Bundler::Audit::Runtime::Target.new(engine: :ruby, version: '2.5.0', patchlevel: 0)
      assessment = assess(target)

      expect(assessment).to be_affected
      expect(assessment.affected_findings.map { |finding| finding.advisory.id }).to include('CVE-2018-8780')
    end

    it "reports a patched MRI version as clean for that advisory" do
      target     = Bundler::Audit::Runtime::Target.new(engine: :ruby, version: '2.6.3')
      assessment = assess(target)

      finding = assessment.findings.find { |f| f.advisory.id == 'CVE-2018-8780' }

      expect(finding.status).to eq(:patched)
    end

    it "uses the patchlevel for four component advisories" do
      vulnerable = assess(Bundler::Audit::Runtime::Target.new(engine: :ruby, version: '1.8.7', patchlevel: 248))
      fixed      = assess(Bundler::Audit::Runtime::Target.new(engine: :ruby, version: '1.8.7', patchlevel: 249))

      expect(vulnerable.findings.find { |f| f.advisory.id == 'OSVDB-61774' }.status).to eq(:affected)
      expect(fixed.findings.find { |f| f.advisory.id == 'OSVDB-61774' }.status).to eq(:patched)
      expect(vulnerable.findings.find { |f| f.advisory.id == 'OSVDB-61774' }.evaluated_version.to_s).to eq('1.8.7.248')
    end

    it "leaves patchlevel specific advisories unknown when the patchlevel is missing" do
      assessment = assess(Bundler::Audit::Runtime::Target.new(engine: :ruby, version: '1.8.7'))

      finding = assessment.findings.find { |f| f.advisory.id == 'OSVDB-61774' }

      expect(finding.status).to eq(:unknown)
      expect(finding.reason).to eq(:missing_patchlevel)
    end

    it "reports an MRI target without a patchlevel as an input note" do
      assessment = assess(Bundler::Audit::Runtime::Target.new(engine: :ruby, version: '2.5.0'))

      expect(assessment.notes).to include(hash_including(code: :missing_target_patchlevel))
      expect(assessment.findings.find { |f| f.advisory.id == 'CVE-2018-8780' }.status).to eq(:affected)
    end

    it "does not apply a four component advisory to a different MRI series" do
      assessment = assess(Bundler::Audit::Runtime::Target.new(engine: :ruby, version: '3.2.2', patchlevel: 53))

      finding = assessment.findings.find { |f| f.advisory.id == 'OSVDB-61774' }

      expect(finding.status).to eq(:patched)
    end
  end

  describe "JRuby target" do
    it "evaluates the engine version instead of the Ruby compatibility version" do
      target = Bundler::Audit::Runtime::Target.new(
        engine: :jruby, version: '2.5.0', patchlevel: 0, engine_version: '9.2.9.0'
      )

      assessment = assess(target)

      expect(assessment).to be_affected
      expect(assessment.affected_findings.map { |finding| finding.advisory.id }).to include('CVE-2019-0001')
      expect(assessment.findings.find { |f| f.advisory.id == 'CVE-2019-0002' }.status).to eq(:patched)
    end

    it "does not use MRI advisories for JRuby" do
      target = Bundler::Audit::Runtime::Target.new(
        engine: :jruby, version: '2.5.0', patchlevel: 0, engine_version: '9.2.9.0'
      )

      ids = assess(target).findings.map { |finding| finding.advisory.id }

      expect(ids).to_not include('CVE-2018-8780')
    end

    it "is unknown without an engine version" do
      target = Bundler::Audit::Runtime::Target.new(engine: :jruby, version: '2.5.0')

      assessment = assess(target)

      expect(assessment).to be_unknown
      expect(assessment.notes).to include(hash_including(code: :missing_target_engine_version))
    end
  end

  describe "declaration conflicts" do
    it "records the declaration differences while keeping the manifest target authoritative" do
      target      = Bundler::Audit::Runtime::Target.new(engine: :jruby, version: '2.5.0', patchlevel: 0, engine_version: '9.2.9.0')
      declaration = Bundler::Audit::Runtime::Declaration.parse('ruby 3.2.2p53')

      assessment = assess(target,declaration: declaration)

      expect(assessment.target.engine).to eq('jruby')
      expect(assessment.notes).to include(hash_including(code: :engine_mismatch))
      expect(assessment).to be_affected
    end

    it "does not switch to the lock file declaration when the manifest is missing" do
      assessment = described_class.new(
        target:      Bundler::Audit::Runtime::Target.new,
        declaration: Bundler::Audit::Runtime::Declaration.parse('ruby 2.5.0p0'),
        advisory_set: advisories
      )

      expect(assessment).to be_unknown
    end
  end

  describe "evidence handling" do
    it "leaves an advisory without patched versions unknown" do
      assessment = assess(Bundler::Audit::Runtime::Target.new(engine: :ruby, version: '2.5.0', patchlevel: 0))

      finding = assessment.findings.find { |f| f.advisory.id == 'CVE-2019-0003' }

      expect(finding.status).to eq(:unknown)
      expect(finding.reason).to eq(:missing_patched_versions)
    end

    it "treats an explicitly unaffected version as not vulnerable" do
      unaffected = Bundler::Audit::Runtime::AdvisorySet.new('spec/fixtures/runtime/database_unaffected')
      assessment = assess(
        Bundler::Audit::Runtime::Target.new(engine: :ruby, version: '2.5.0'),
        advisory_set: unaffected
      )

      expect(assessment).to be_clean
      expect(assessment.findings.first.reason).to eq(:unaffected_version)
    end

    it "does not treat an advisory with only unaffected versions as clean for other versions" do
      unaffected = Bundler::Audit::Runtime::AdvisorySet.new('spec/fixtures/runtime/database_unaffected')
      assessment = assess(
        Bundler::Audit::Runtime::Target.new(engine: :ruby, version: '2.6.0'),
        advisory_set: unaffected
      )

      expect(assessment).to be_unknown
      expect(assessment.findings.first.reason).to eq(:insufficient_advisory_data)
    end

    it "leaves an advisory with invalid requirements unknown" do
      assessment = assess(Bundler::Audit::Runtime::Target.new(engine: :ruby, version: '2.5.0', patchlevel: 0))

      finding = assessment.findings.find { |f| f.advisory.id == 'CVE-2019-0004' }

      expect(finding.status).to eq(:unknown)
      expect(finding.reason).to eq(:invalid_version_requirements)
    end

    it "leaves a misfiled advisory unknown instead of preferring the directory or body" do
      misfiled = Bundler::Audit::Runtime::AdvisorySet.new('spec/fixtures/runtime/database_misfiled')
      assessment = assess(
        Bundler::Audit::Runtime::Target.new(
          engine: :jruby, version: '2.5.0', patchlevel: 0, engine_version: '9.2.9.0'
        ),
        advisory_set: misfiled
      )

      expect(assessment).to be_unknown
      expect(assessment.findings.first.reason).to eq(:misplaced_advisory)
    end

    it "does not pick one of two conflicting advisories" do
      conflict_set = Bundler::Audit::Runtime::AdvisorySet.new('spec/fixtures/runtime/database_conflicting')
      assessment   = assess(
        Bundler::Audit::Runtime::Target.new(engine: :ruby, version: '2.6.3'),
        advisory_set: conflict_set
      )

      expect(assessment).to be_unknown
      expect(assessment.findings.length).to eq(1)
      expect(assessment.findings.first.reason).to eq(:conflicting_advisories)
      expect(assessment.findings.first.advisories.length).to eq(2)
    end

    it "does not score a clean result when advisories are absent for the engine" do
      assessment = assess(Bundler::Audit::Runtime::Target.new(engine: :ruby, version: '2.5.0'),
                          advisory_set: Bundler::Audit::Runtime::AdvisorySet.new('spec/fixtures/runtime/database_empty_rubies'))

      expect(assessment).to be_unknown
    end

    it "is unknown when the database has no rubies tree" do
      assessment = assess(Bundler::Audit::Runtime::Target.new(engine: :ruby, version: '2.5.0'),
                          advisory_set: Bundler::Audit::Runtime::AdvisorySet.new('spec/fixtures/runtime/database_missing_rubies'))

      expect(assessment).to be_unknown
      expect(assessment.notes).to include(hash_including(code: :runtime_advisories_unavailable))
    end

    it "does not infer the target from the scanning interpreter when no runtime inputs exist" do
      scanner = Bundler::Audit::Scanner.new('spec/bundle/runtime_mri','Gemfile.lock',
        Bundler::Audit::Database.new('spec/fixtures/runtime/database'))
      report  = scanner.report(runtime: {})

      expect(report.runtime_audit).to be_unknown
      expect(report.runtime_audit.target.engine).to be_nil
      expect(report.runtime_audit.target.version).to be_nil
      expect(report.runtime_audit.inputs['engine']).to be_nil
    end

    it "is unknown when no advisory source is supplied" do
      assessment = described_class.new(target: Bundler::Audit::Runtime::Target.new(engine: :ruby, version: '2.5.0'))

      expect(assessment).to be_unknown
      expect(assessment.notes).to include(hash_including(code: :runtime_advisories_missing))
    end
  end

  describe "#inputs" do
    it "records the target and advisory source which were used" do
      assessment = assess(Bundler::Audit::Runtime::Target.new(engine: :ruby, version: '2.5.0', patchlevel: 0))

      expect(assessment.inputs['evaluated_version']).to eq('2.5.0')
      expect(assessment.inputs['runtime_advisories']).to eq(advisories.to_s)
    end
  end
end

describe "Bundler::Audit::Runtime gem name independence" do
  let(:database) { Bundler::Audit::Database.new('spec/fixtures/runtime/database') }
  let(:scanner)  { Bundler::Audit::Scanner.new('spec/bundle/runtime_gem_same_name','Gemfile.lock',database) }

  it "keeps the gem audit separate from the runtime audit" do
    report = scanner.report(
      runtime: {
        target:     {engine: :ruby, version: '2.5.0', patchlevel: 0},
        advisories: 'spec/fixtures/runtime/database'
      }
    )

    gem_results = report.select { |result| result.kind_of?(Bundler::Audit::Results::UnpatchedGem) }
    runtime     = report.runtime_audit

    expect(gem_results.map { |result| result.advisory.id }).to include('CVE-2019-9999')
    expect(runtime.findings.map { |finding| finding.advisory.id }).to_not include('CVE-2019-9999')
  end

  it "does not use a gem advisory when no runtime advisories exist" do
    scanner = Bundler::Audit::Scanner.new(
      'spec/bundle/runtime_gem_same_name', 'Gemfile.lock',
      Bundler::Audit::Database.new('spec/fixtures/runtime/database_missing_rubies')
    )

    report = scanner.report(
      runtime: {
        target:     {engine: :ruby, version: '2.5.0'},
        advisories: 'spec/fixtures/runtime/database_missing_rubies'
      }
    )

    expect(report.runtime_audit).to be_unknown
    expect(report.runtime_audit.findings).to be_empty
  end
end

describe "Bundler::Audit::Scanner optional runtime audit" do
  let(:database) { Bundler::Audit::Database.new('spec/fixtures/runtime/database') }
  let(:scanner)  { Bundler::Audit::Scanner.new('spec/bundle/runtime_mri','Gemfile.lock',database) }

  it "does not run the runtime audit by default" do
    report = scanner.report

    expect(report.runtime_audit).to be_nil
    expect(report.to_h).to_not have_key(:runtime)
  end

  it "runs the runtime audit when a manifest is supplied" do
    report = scanner.report(
      runtime: {
        manifest:   'spec/fixtures/runtime/manifests/mri.yml',
        advisories: 'spec/fixtures/runtime/database'
      }
    )

    expect(report.runtime_audit).to_not be_nil
    expect(report.to_h[:runtime][:inputs]['manifest']).to eq(File.expand_path('spec/fixtures/runtime/manifests/mri.yml'))
  end

  it "binds the report to the supplied lock file" do
    report = scanner.report(
      runtime: {
        manifest:   'spec/fixtures/runtime/manifests/jruby.yml',
        advisories: 'spec/fixtures/runtime/database'
      }
    )

    expect(report.runtime_audit.to_h[:inputs]['lockfile']).to eq(File.expand_path('spec/bundle/runtime_mri/Gemfile.lock'))
  end

  it "raises when the manifest does not exist" do
    expect {
      scanner.report(runtime: {manifest: 'spec/fixtures/runtime/manifests/nope.yml'})
    }.to raise_error(Bundler::Audit::Runtime::Error)
  end

  it "raises when the runtime options are not a Hash" do
    expect {
      scanner.report(runtime: 42)
    }.to raise_error(Bundler::Audit::Runtime::Error)
  end
end
