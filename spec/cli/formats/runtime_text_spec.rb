require 'spec_helper'
require 'bundler/audit/cli/formats'
require 'bundler/audit/cli/formats/text'
require 'bundler/audit/report'
require 'bundler/audit/runtime'
require 'bundler/audit/results/runtime_audit'

describe Bundler::Audit::CLI::Formats::Text do
  let(:options) { {} }

  subject do
    Bundler::Audit::CLI.new([],options).tap do |obj|
      obj.extend described_class
    end
  end

  def runtime_report(target,advisories: 'spec/fixtures/runtime/database', declaration: nil)
    assessment = Bundler::Audit::Runtime::Assessment.new(
      target:       target,
      advisory_set: Bundler::Audit::Runtime::AdvisorySet.new(advisories),
      declaration:  declaration,
      inputs:       {'manifest' => 'deploy/manifest.yml', 'lockfile' => 'Gemfile.lock'}
    )

    Bundler::Audit::Report.new([Bundler::Audit::Results::RuntimeAudit.new(assessment)])
  end

  describe "#print_report" do
    let(:stdout) { StringIO.new }
    let(:output) { stdout.string }
    let(:output_lines) { output.lines.map(&:chomp) }

    context "when the runtime is affected" do
      let(:target) do
        Bundler::Audit::Runtime::Target.new(
          engine: :jruby, version: '2.5.0', patchlevel: 0, engine_version: '9.2.9.0'
        )
      end
      let(:report) { runtime_report(target) }

      before { subject.print_report(report,stdout) }

      it "prints the deployment target which was used" do
        expect(output_lines).to include("Target: jruby 9.2.9.0")
      end

      it "prints the manifest and lock file inputs" do
        expect(output_lines).to include("Manifest: deploy/manifest.yml", "Lockfile: Gemfile.lock")
      end

      it "prints the runtime advisory" do
        expect(output_lines).to include("Name: CVE-2019-0001", "Engine: jruby")
      end

      it "prints the affected status and overall result" do
        expect(output_lines).to include("Status: affected", "Vulnerabilities found!")
      end
    end

    context "when the runtime audit is unknown" do
      let(:target) { Bundler::Audit::Runtime::Target.new(engine: :jruby, version: '2.5.0') }
      let(:report) { runtime_report(target) }

      before { subject.print_report(report,stdout) }

      it "prints the unknown status and notes" do
        expect(output_lines).to include("Status: unknown", "Runtime audit inconclusive")
        expect(output).to include("engine version is missing")
      end
    end

    context "when the runtime audit is clean" do
      let(:target) do
        Bundler::Audit::Runtime::Target.new(
          engine: :jruby, version: '2.5.0', patchlevel: 0, engine_version: '9.3.0.0'
        )
      end
      let(:report) { runtime_report(target) }

      before { subject.print_report(report,stdout) }

      it "prints the clean status" do
        expect(output_lines).to include("Status: clean", "No vulnerabilities found")
      end
    end
  end
end
