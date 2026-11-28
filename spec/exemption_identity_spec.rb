require 'spec_helper'
require 'bundler/audit/scanner'
require 'bundler/audit/cli/formats'
require 'bundler/audit/cli/formats/text'

#
# Demonstrates exemption identity resolution with two synthetic advisories
# and one lockfile:
#
# * `INTERNAL-2026-0001` (gem `alpha`) was filed as an internal record and
#   later supplemented with the CVE-2026-1111 and GHSA-aaaa-bbbb-cccc
#   aliases.
# * `INTERNAL-2026-0002` (gem `beta`) shares the GHSA-aaaa-bbbb-cccc alias
#   with `INTERNAL-2026-0001`.
#
describe "exemption identity" do
  let(:database) { Database.new(Fixtures.join('synthetic_db')) }
  let(:directory) { File.join('spec','bundle','exemption_identity') }
  let(:scanner) { Scanner.new(directory,'Gemfile.lock',database) }

  let(:report) { scanner.report }

  describe Database do
    describe "#lookup" do
      it "must resolve canonical ids and supplemented aliases to the same record" do
        expect(database.lookup('INTERNAL-2026-0001').map(&:id)).to eq(['INTERNAL-2026-0001'])
        expect(database.lookup('CVE-2026-1111').map(&:id)).to eq(['INTERNAL-2026-0001'])
      end

      it "must return every record sharing an alias" do
        expect(database.lookup('GHSA-aaaa-bbbb-cccc').map(&:id)).to contain_exactly('INTERNAL-2026-0001','INTERNAL-2026-0002')
      end

      it "must return an empty Array for unknown identifiers" do
        expect(database.lookup('CVE-0000-0000')).to eq([])
      end
    end
  end

  describe "supplemented aliases" do
    it "must carry over the legacy exemption for the internal record id" do
      expect(report.unpatched_gems.map { |result| result.gem.name }).not_to include('alpha')
    end

    it "must record the identity of the supplemented record as the basis" do
      decision = report.decisions.find { |d| d.approval.advisory == 'INTERNAL-2026-0001' }

      expect(decision).to be_applied
      expect(decision.gem.name).to eq('alpha')
      expect(decision.advisory.id).to eq('INTERNAL-2026-0001')
      expect(decision.reason).to include('CVE-2026-1111')
      expect(decision.reason).to include('GHSA-aaaa-bbbb-cccc')
    end
  end

  describe "shared alias" do
    context "when the approval explicitly binds the gem and the advisory" do
      it "must apply the approval to the bound gem only" do
        expect(report.unpatched_gems.map { |result| result.gem.name }).not_to include('beta')
      end

      it "must record the shared alias and the binding as the basis" do
        decision = report.decisions.find { |d| d.approval.advisory == 'GHSA-aaaa-bbbb-cccc' }

        expect(decision).to be_applied
        expect(decision.gem.name).to eq('beta')
        expect(decision.advisory.id).to eq('INTERNAL-2026-0002')
        expect(decision.reason).to include('shared')
        expect(decision.reason).to include("gem 'beta'")
      end

      it "must not suppress the other gem sharing the alias" do
        config = Configuration.new(ignore: [{'advisory' => 'GHSA-aaaa-bbbb-cccc', 'gem' => 'beta'}])
        allow(scanner).to receive(:config).and_return(config)

        report = scanner.report

        expect(report.unpatched_gems.map { |result| result.gem.name }).to contain_exactly('alpha')
      end
    end

    context "when the approval passed to the command is not bound" do
      let(:report) { scanner.report(ignore: ['GHSA-aaaa-bbbb-cccc']) }

      it "must not suppress either advisory" do
        expect(report.unpatched_gems.map { |result| result.gem.name }).to contain_exactly('alpha','beta')
      end

      it "must flag the approval for review" do
        decision = report.decisions.find { |d| d.approval.advisory == 'GHSA-aaaa-bbbb-cccc' }

        expect(decision.status).to eq(:review)
        expect(decision.reason).to include('INTERNAL-2026-0001')
        expect(decision.reason).to include('INTERNAL-2026-0002')
      end
    end
  end

  describe "expired approval" do
    it "must record the expired approval as the basis" do
      decision = report.decisions.find { |d| d.approval.advisory == 'CVE-2026-1111' }

      expect(decision.status).to eq(:expired)
      expect(decision.reason).to include('2020-06-01')
    end

    it "must not suppress the advisory when it is the only approval" do
      config = Configuration.new(ignore: [{'advisory' => 'CVE-2026-1111', 'gem' => 'alpha', 'expires' => '2020-06-01'}])
      allow(scanner).to receive(:config).and_return(config)

      report = scanner.report

      expect(report.unpatched_gems.map { |result| result.gem.name }).to include('alpha')
    end
  end

  describe "scan report" do
    let(:cli) do
      Bundler::Audit::CLI.new([],{}).tap do |cli|
        cli.extend Bundler::Audit::CLI::Formats::Text
      end
    end

    it "must include the decisions in the report Hash" do
      statuses = report.to_h[:decisions].map { |decision| decision[:status] }

      expect(statuses).to contain_exactly(:applied,:applied,:expired)
    end

    it "must print the basis for each exemption decision" do
      output = StringIO.new
      cli.print_report(report,output)

      expect(output.string).to include('Exemption decisions:')
      report.decisions.each do |decision|
        expect(output.string).to include(decision.to_s)
      end
    end
  end
end
