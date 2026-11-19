require 'spec_helper'
require 'bundler/audit/cli/formats'
require 'bundler/audit/cli/formats/junit'
require 'bundler/audit/report'
require 'bundler/audit/runtime'
require 'bundler/audit/results/runtime_audit'

describe Bundler::Audit::CLI::Formats::Junit do
  let(:options) { {} }

  subject do
    Bundler::Audit::CLI.new([],options).tap do |obj|
      obj.extend described_class
    end
  end

  let(:stdout) { StringIO.new }

  def runtime_report(target)
    assessment = Bundler::Audit::Runtime::Assessment.new(
      target:       target,
      advisory_set: Bundler::Audit::Runtime::AdvisorySet.new('spec/fixtures/runtime/database')
    )

    Bundler::Audit::Report.new([Bundler::Audit::Results::RuntimeAudit.new(assessment)])
  end

  context "when the runtime is affected" do
    let(:target) do
      Bundler::Audit::Runtime::Target.new(
        engine: :ruby, version: '2.5.0', patchlevel: 0
      )
    end

    before { subject.print_report(runtime_report(target),stdout) }

    let(:output) { stdout.string }

    it "prints a failing runtime testcase" do
      expect(output).to include('id="ruby-runtime:CVE-2018-8780"')
      expect(output).to include('failures="1"')
    end
  end

  context "when the runtime audit is unknown" do
    let(:target) { Bundler::Audit::Runtime::Target.new(engine: :jruby, version: '2.5.0') }

    before { subject.print_report(runtime_report(target),stdout) }

    let(:output) { stdout.string }

    it "marks the runtime testcase as skipped without a failure" do
      expect(output).to include('<skipped')
      expect(output).to include('failures="0"')
    end
  end
end
