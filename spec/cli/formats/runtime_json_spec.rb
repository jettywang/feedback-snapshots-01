require 'spec_helper'
require 'bundler/audit/cli/formats'
require 'bundler/audit/cli/formats/json'
require 'bundler/audit/report'
require 'bundler/audit/runtime'
require 'bundler/audit/results/runtime_audit'

describe Bundler::Audit::CLI::Formats::JSON do
  let(:options) { {} }

  subject do
    Bundler::Audit::CLI.new([],options).tap do |obj|
      obj.extend described_class
    end
  end

  let(:stdout) { StringIO.new }

  before { subject.print_report(report,stdout) }

  let(:output_json) { JSON.parse(stdout.string, symbolize_names: true) }

  context "when the runtime audit has findings" do
    let(:target) do
      Bundler::Audit::Runtime::Target.new(
        engine: :jruby, version: '2.5.0', patchlevel: 0, engine_version: '9.2.9.0'
      )
    end
    let(:report) do
      assessment = Bundler::Audit::Runtime::Assessment.new(
        target:       target,
        advisory_set: Bundler::Audit::Runtime::AdvisorySet.new('spec/fixtures/runtime/database'),
        inputs:       {'manifest' => 'deploy/manifest.yml'}
      )

      Bundler::Audit::Report.new([Bundler::Audit::Results::RuntimeAudit.new(assessment)])
    end

    it "keeps runtime results out of the gem results array" do
      expect(output_json[:results]).to be_empty
    end

    it "includes a runtime section bound to the target" do
      expect(output_json[:runtime][:status]).to eq('affected')
      expect(output_json[:runtime][:target][:engine]).to eq('jruby')
      expect(output_json[:runtime][:target][:engine_version]).to eq('9.2.9.0')
      expect(output_json[:runtime][:inputs][:manifest]).to eq('deploy/manifest.yml')
    end

    it "includes the runtime findings" do
      findings = output_json[:runtime][:findings]

      expect(findings.map { |finding| finding[:status] }).to include('affected', 'patched')
    end
  end

  context "when only gem results exist" do
    let(:gem) do
      Gem::Specification.new do |spec|
        spec.name    = 'test'
        spec.version = '0.1.0'
      end
    end
    let(:advisory) { Bundler::Audit::Advisory.load(Fixtures.join('advisory','CVE-2020-1234.yml')) }
    let(:report) do
      Bundler::Audit::Report.new([
        Bundler::Audit::Results::UnpatchedGem.new(gem,advisory)
      ])
    end

    it "does not include a runtime key" do
      expect(output_json).to_not have_key(:runtime)
    end
  end
end
