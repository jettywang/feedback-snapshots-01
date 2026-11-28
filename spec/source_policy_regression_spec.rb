require 'spec_helper'
require 'bundler/audit/scanner'
require 'bundler/audit/cli'
require 'bundler/audit/cli/formats/json'
require 'json'
require 'stringio'

# Regression coverage for keeping source policy decisions independent from
# version advisory exemptions. The fixtures use a local advisory database and
# a deterministic resolver so no network access is required.
describe "source policy vs. version exemptions" do
  class SourcePolicyResolver
    def initialize(addresses={})
      @addresses = addresses
    end

    def getaddresses(host)
      value = @addresses.fetch(host) do
        raise Resolv::ResolvError,"no fixture address for #{host}"
      end

      return value if value.kind_of?(Array)

      raise Resolv::ResolvError,"fixture lookup failed for #{host}"
    end
  end

  let(:fixture_root) { File.expand_path('fixtures/source_policy',__dir__) }
  let(:database)     { Bundler::Audit::Database.new(File.join(fixture_root,'db')) }
  let(:resolver) do
    SourcePolicyResolver.new(
      'legacy.example.com'   => ['203.0.113.10'],
      'gems.internal.example' => ['10.20.30.40']
    )
  end
  let(:bundle)    { 'source_policy_clean' }
  let(:directory) { File.expand_path("../spec/bundle/#{bundle}",__dir__) }
  let(:scanner) do
    Bundler::Audit::Scanner.new(directory,'Gemfile.lock',database,'.bundler-audit.yml',
                                resolver: resolver)
  end

  def report
    scanner.report
  end

  def result_ids(results)
    results.map { |result| result.advisory.id }
  end

  context "when a version advisory is exempted" do
    let(:bundle) { 'source_policy_exempted' }

    it "passes when the source itself is secure" do
      expect(report.passes?).to be(true)
    end

    it "keeps the approved advisory and its reason in the report" do
      approved = report.exemptions

      expect(approved).to all(be_kind_of(Bundler::Audit::Results::ExemptedGem))
      expect(result_ids(approved)).to contain_exactly(
        'CVE-2026-0001',
        'GHSA-aaaa-bbbb-0002'
      )

      approved.each do |result|
        expect(result.disposition).to eq(:approved)
        expect(result.reason).to eq('vendor patch shipped in the application image')
        expect(result.expires_on).to eq(Date.new(2026,12,31))
      end
    end

    it "does not produce unpatched gem results for the exempted advisories" do
      expect(report.unpatched_gems).to be_empty
    end
  end

  context "when only one version advisory is exempted" do
    let(:bundle) { 'source_policy_partial_exemption' }

    it "blocks on the remaining advisory" do
      expect(report.passes?).to be(false)
      expect(result_ids(report.unpatched_gems)).to contain_exactly('GHSA-aaaa-bbbb-0002')
      expect(result_ids(report.exemptions)).to contain_exactly('CVE-2026-0001')
    end
  end

  context "when an exemption has expired" do
    let(:bundle) { 'source_policy_expired' }

    it "blocks on the advisory and explains the expired exemption" do
      expect(report.passes?).to be(false)

      blocked = report.unpatched_gems
      expect(result_ids(blocked)).to contain_exactly(
        'CVE-2026-0001',
        'GHSA-aaaa-bbbb-0002'
      )
      expect(blocked).to all(satisfy { |result| result.reason == 'exemption expired' })
      expect(blocked.first.evidence[:expired_exemption]).to include(
        expires_on: '2026-01-01'
      )
    end
  end

  context "when an exempted version is bundled from an explicitly blocked source" do
    let(:bundle) { 'source_policy_blocked_source' }

    it "still reports the blocked source" do
      expect(report.passes?).to be(false)
      expect(report.blocked_sources.map(&:source)).to eq(['http://legacy.example.com/'])
      expect(report.blocked_sources.map(&:reason)).to eq(['insecure http source'])
    end

    it "keeps the version exemption separate from the source verdict" do
      expect(result_ids(report.exemptions)).to contain_exactly(
        'CVE-2026-0001',
        'GHSA-aaaa-bbbb-0002'
      )
      expect(report.unpatched_gems).to be_empty
      expect(report.blocking_results).to all(be_kind_of(Bundler::Audit::Results::InsecureSource))
    end

    it "does not let scan_sources be affected by version exemptions" do
      results = scanner.scan_sources.to_a
      exemptions = scanner.scan_specs.to_a

      expect(results.map(&:source)).to eq(['http://legacy.example.com/'])
      expect(result_ids(exemptions)).to contain_exactly(
        'CVE-2026-0001',
        'GHSA-aaaa-bbbb-0002'
      )
    end
  end

  context "when an exempted version comes from an unidentifiable source" do
    let(:bundle) { 'source_policy_undetermined_source' }
    let(:resolver) { SourcePolicyResolver.new }

    it "blocks without claiming the source was explicitly prohibited" do
      expect(report.passes?).to be(false)
      expect(report.blocked_sources).to be_empty
      expect(report.undetermined_sources.length).to eq(1)

      undetermined = report.undetermined_sources.first
      expect(undetermined.source).to eq('http://gems.internal.example/')
      expect(undetermined.disposition).to eq(:undetermined)
      expect(undetermined.reason).to eq('source host could not be resolved')
      expect(undetermined.evidence[:resolution]).to eq(:unresolved)
    end

    it "still records the approved version advisory and its reason" do
      expect(result_ids(report.exemptions)).to contain_exactly(
        'CVE-2026-0001',
        'GHSA-aaaa-bbbb-0002'
      )
    end

    it "reports the undetermined source through scan_sources as well" do
      results = scanner.scan_sources.to_a

      expect(results.length).to eq(1)
      expect(results.first).to be_kind_of(Bundler::Audit::Results::SourceAssessment)
      expect(results.first).to be_undetermined
    end
  end

  context "when a source is internal and resolvable" do
    let(:bundle) { 'source_policy_undetermined_source' }
    let(:resolver) do
      SourcePolicyResolver.new('gems.internal.example' => ['10.20.30.40'])
    end

    it "allows the internal http source" do
      assessment = scanner.assess_sources.to_a.first

      expect(assessment.disposition).to eq(:allowed)
      expect(assessment.reason).to eq('internal source')
      expect(report.blocked_sources).to be_empty
      expect(report.undetermined_sources).to be_empty
    end
  end

  context "when the source cannot be identified at all" do
    let(:bundle) { 'source_policy_undetermined_source' }
    let(:resolver) { SourcePolicyResolver.new('gems.internal.example' => ['not-an-ip']) }

    it "treats an unparseable address as unsettled evidence" do
      assessment = scanner.assess_sources.to_a.first

      expect(assessment.disposition).to eq(:undetermined)
      expect(assessment.reason).to eq('source host returned an unparseable address')
    end
  end

  context "when a source resolves to a public address" do
    let(:bundle) { 'source_policy_blocked_source' }

    it "blocks the insecure http source with public-address evidence" do
      source = report.blocked_sources.first

      expect(source.disposition).to eq(:blocked)
      expect(source.evidence[:addresses]).to eq(['203.0.113.10'])
      expect(source.evidence[:internal]).to be(false)
    end
  end

  context "when the source list is clean and no advisories apply" do
    let(:bundle) { 'source_policy_clean' }

    it "passes with an allowed source assessment" do
      expect(report.passes?).to be(true)
      expect(report.vulnerable?).to be(false)
      expect(report.allowed_sources.map(&:source)).to eq(['https://rubygems.org/'])
      expect(report.blocking_results).to be_empty
    end
  end

  context "when an ignore list is also supplied" do
    let(:bundle) { 'source_policy_blocked_source' }

    it "does not change the independently computed source result" do
      report = scanner.report(ignore: ['CVE-2026-0001'])

      expect(report.blocked_sources.map(&:source)).to eq(['http://legacy.example.com/'])
      expect(report.passes?).to be(false)
    end
  end

  context "when exemptions are passed as scan options" do
    let(:bundle) { 'source_policy_partial_exemption' }

    it "applies them to version results and still evaluates sources" do
      report = scanner.report(ignore: ['GHSA-aaaa-bbbb-0002'],
        exemptions: [{
          advisory:    'CVE-2026-0001',
          gem:         'testgem',
          reason:      'vendor patch shipped in the application image',
          expires_on:  '2026-12-31',
          approved_by: 'security-team'
        }])

      expect(result_ids(report.exemptions)).to contain_exactly('CVE-2026-0001')
      expect(report.unpatched_gems).to be_empty
      expect(report.allowed_sources.map(&:source)).to eq(['https://rubygems.org/'])
      expect(report.passes?).to be(true)
    end
  end

  describe "the approval registry" do
    it "keeps every approved exemption with its reason and scope" do
      registry = JSON.parse(File.read(File.join(fixture_root,'approvals','registry.json')))
      approved = registry.fetch('exemptions')

      expect(approved).not_to be_empty

      approved.each do |entry|
        expect(entry['reason']).not_to be_empty
        expect(entry['scope']).to eq('version-only')
        expect(entry['approved_by']).not_to be_empty
        expect(entry['expires_on']).not_to be_empty
      end
    end

    it "matches the exemptions loaded from the fixture configuration" do
      registry = JSON.parse(File.read(File.join(fixture_root,'approvals','registry.json')))
      configured = Bundler::Audit::Configuration.load(
        File.join(__dir__,'bundle','source_policy_exempted','.bundler-audit.yml')
      )

      expect(configured.exemptions.map(&:to_h)).to match_array(
        registry.fetch('exemptions').map do |entry|
          entry.slice('advisory','gem','reason','expires_on','approved_by').transform_keys(&:to_sym)
        end
      )
    end
  end

  describe "the JSON output" do
    let(:bundle) { 'source_policy_blocked_source' }
    let(:cli) do
      Bundler::Audit::CLI.new([],{}).tap do |cli|
        cli.extend Bundler::Audit::CLI::Formats::JSON
      end
    end

    it "keeps the source summary separate from the version decisions" do
      output = StringIO.new
      cli.print_report(report,output)

      json = JSON.parse(output.string,symbolize_names: true)

      expect(json[:passed]).to be(false)
      expect(json[:sources][:blocked]).to eq(['http://legacy.example.com/'])
      expect(json[:sources][:undetermined]).to be_empty

      approved = json[:results].select { |result| result[:type] == 'exempted_gem' }
      expect(approved.length).to eq(2)
      expect(approved).to all(include(
        disposition: 'approved',
        reason:      'vendor patch shipped in the application image'
      ))
    end
  end

  describe "the report hash" do
    let(:bundle) { 'source_policy_blocked_source' }

    it "exposes pass/fail plus per-result disposition and reason" do
      hash = report.to_h

      expect(hash[:passed]).to be(false)

      source = hash[:results].find { |result| result[:type] == :insecure_source }
      expect(source[:disposition]).to eq(:blocked)
      expect(source[:reason]).to eq('insecure http source')

      approved = hash[:results].select { |result| result[:type] == :exempted_gem }
      expect(approved.length).to eq(2)
      expect(approved).to all(include(
        disposition: :approved,
        reason: 'vendor patch shipped in the application image'
      ))
    end
  end
end
