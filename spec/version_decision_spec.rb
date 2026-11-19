require 'spec_helper'
require 'bundler/audit/advisory'
require 'bundler/audit/version_decision'

describe Bundler::Audit::VersionDecision do
  let(:path) { Fixtures.join('advisory','CVE-2020-1234.yml') }
  let(:advisory) { Bundler::Audit::Advisory.load(path) }

  def decision(version,gem_name='test',adv=advisory)
    described_class.new(adv,Gem::Version.new(version),gem_name)
  end

  describe '#initialize' do
    it 'binds the advisory source file and identity to the decision' do
      d = decision('0.1.0')

      expect(d.advisory).to be(advisory)
      expect(d.advisory_id).to eq('CVE-2020-1234')
      expect(d.advisory_path).to eq(path)
      expect(d.gem_name).to eq('test')
    end

    it 'accepts a String version and normalizes it to a Gem::Version' do
      d = described_class.new(advisory,'0.1.0','test')

      expect(d.version).to eq(Gem::Version.new('0.1.0'))
      expect(d.raw_version).to eq('0.1.0')
    end

    it 'records one range check per declared requirement' do
      # 1 unaffected + 3 patched in CVE-2020-1234.yml
      expect(decision('0.1.0').range_checks.size).to eq(4)
    end
  end

  describe 'version normalization' do
    it 'treats equivalent string and Gem::Version inputs identically' do
      from_string = described_class.new(advisory,'1.2.3','test')
      from_version = described_class.new(advisory,Gem::Version.new('1.2.3'),'test')

      expect(from_string.range_checks).to eq(from_version.range_checks)
      expect(from_string.verdict).to eq(from_version.verdict)
    end

    it 'flags prerelease versions' do
      expect(decision('1.0.0.beta').prerelease?).to be(true)
      expect(decision('1.0.0').prerelease?).to be(false)
    end
  end

  describe 'per-range checks' do
    it 'records the kind, requirement, match result and a reason for each range' do
      check = decision('0.1.0').range_checks.first

      expect(check[:kind]).to eq(:unaffected)
      expect(check[:requirement]).to eq('< 0.1.0')
      expect(check[:matched]).to eq(false)
      expect(check[:reason]).to be_a(String)
      expect(check[:reason]).to include('0.1.0')
    end

    it 'marks a satisfied range as matched' do
      patched = decision('0.1.42').patched_checks.find { |c| c[:matched] }

      expect(patched).to_not be_nil
      expect(patched[:reason]).to include('satisfies')
    end

    it 'explains why a non-prerelease requirement excludes a prerelease' do
      advisory = Bundler::Audit::Advisory.load(
        Fixtures.join('database','gems','bson','CVE-2015-4412.yml'))
      d = described_class.new(advisory,Gem::Version.new('2.0.0.pre'),'bson')

      check = d.range_checks.first
      expect(check[:matched]).to eq(false)
      expect(check[:reason]).to include('prerelease')
    end
  end

  describe 'verdict precedence' do
    context 'when an unaffected range matches' do
      it 'is unaffected even if a patched range would also apply' do
        # CVE-2016-2098: >= 5.0.0.beta1 is unaffected; 5.1.0 is a normal release
        adv = Bundler::Audit::Advisory.load(
          Fixtures.join('database','gems','actionpack','CVE-2016-2098.yml'))
        d = described_class.new(adv,Gem::Version.new('5.1.0'),'actionpack')

        expect(d.verdict).to eq(:unaffected)
        expect(d.unaffected?).to eq(true)
        expect(d.patched?).to eq(false)
        expect(d.vulnerable?).to eq(false)
        expect(d.undetermined?).to eq(false)
      end
    end

    context 'when only a patched range matches' do
      it 'is patched' do
        d = decision('0.1.42')

        expect(d.verdict).to eq(:patched)
        expect(d.patched?).to eq(true)
        expect(d.vulnerable?).to eq(false)
      end
    end

    context 'when no range matches a normal release' do
      it 'is vulnerable' do
        d = decision('0.1.1')

        expect(d.verdict).to eq(:vulnerable)
        expect(d.affected?).to eq(true)
        expect(d.vulnerable?).to eq(true)
        expect(d.undetermined?).to eq(false)
      end
    end

    context 'when a prerelease is not coverable by any range' do
      it 'is undetermined but still surfaced as vulnerable' do
        adv = Bundler::Audit::Advisory.load(
          Fixtures.join('database','gems','bson','CVE-2015-4412.yml'))
        d = described_class.new(adv,Gem::Version.new('2.0.0.pre'),'bson')

        expect(d.verdict).to eq(:undetermined)
        expect(d.undetermined?).to eq(true)
        # backwards-compatible boolean treatment: do not silently call it safe
        expect(d.vulnerable?).to eq(true)
        expect(d.explain).to include('cannot determine whether it is affected')
        expect(d.to_h[:reason]).to include('undetermined')
      end
    end

    context 'when a prerelease is covered by a prerelease requirement' do
      it 'classifies it positively instead of undetermined' do
        adv = Bundler::Audit::Advisory.load(
          Fixtures.join('database','gems','actionpack','CVE-2016-2098.yml'))
        d = described_class.new(adv,Gem::Version.new('5.0.0.beta1'),'actionpack')

        expect(d.undetermined?).to eq(false)
        expect(d.verdict).to eq(:unaffected)
        expect(d.vulnerable?).to eq(false)
      end
    end

    context 'when the advisory declares no ranges at all' do
      let(:empty_advisory) do
        Bundler::Audit::Advisory.new.tap do |a|
          a.id = 'CVE-9999-0000'
          a.path = 'nonexistent/CVE-9999-0000.yml'
          a.unaffected_versions = []
          a.patched_versions = []
        end
      end

      it 'is vulnerable with an explicit no-patch explanation' do
        d = described_class.new(empty_advisory,Gem::Version.new('1.0.0'),'gem')

        expect(d.verdict).to eq(:vulnerable)
        expect(d.range_checks).to be_empty
        expect(d.explain).to include('no unaffected_versions or patched_versions')
      end
    end
  end

  describe 'boolean / explanation consistency' do
    let(:versions) { %w[0.1.0 0.1.42 0.1.43 0.2.42 1.0.0 2.0.0 0.0.9] }

    it 'derives the boolean from the same range_checks as the explanation' do
      versions.each do |v|
        d = decision(v)
        recomputed = !d.patched? && !d.unaffected?

        expect(d.vulnerable?).to eq(recomputed),
          "boolean diverged from range checks for #{v}"
      end
    end

    it 'exposes a verdict consistent with its boolean predicates' do
      versions.each do |v|
        d = decision(v)
        case d.verdict
        when :unaffected then expect(d.unaffected?).to eq(true)
        when :patched    then expect(d.patched?).to eq(true)
        when :vulnerable
          expect(d.unaffected?).to eq(false)
          expect(d.patched?).to eq(false)
        when :undetermined
          expect(d.undetermined?).to eq(true)
          expect(d.vulnerable?).to eq(true)
        end
      end
    end

    it 'produces an explanation whose verdict line matches the verdict accessor' do
      versions.each do |v|
        d = decision(v)
        expect(d.explain).to include("verdict: #{d.verdict}")
        expect(d.to_s).to eq(d.explain)
      end
    end
  end

  describe '#to_h' do
    subject { decision('0.1.1').to_h }

    it 'is JSON serializable with no struct leakage' do
      expect { ::JSON.generate(subject) }.to_not raise_error
    end

    it 'includes the dependency identity and normalized version' do
      expect(subject[:gem]).to include(
        name: 'test',
        raw_version: '0.1.1',
        version: '0.1.1',
        prerelease: false
      )
    end

    it 'binds the advisory id and source path' do
      expect(subject[:advisory]).to include(
        id: 'CVE-2020-1234',
        path: path
      )
    end

    it 'serializes every range check with string kinds and a verdict' do
      expect(subject[:range_checks]).to all(
        include(
          kind: a_string_matching(/\A(unaffected|patched)\z/),
          matched: a_kind_of(TrueClass).or(a_kind_of(FalseClass)),
          reason: a_string_including('requirement')
        )
      )
      expect(subject[:verdict]).to eq('vulnerable')
      expect(subject[:vulnerable]).to eq(true)
      expect(subject[:undetermined]).to eq(false)
    end
  end

  describe 'recomputation against the real advisory database' do
    Dir.glob(File.join(Fixtures::Database::PATH,'gems','*','*.yml')).each do |file|
      context File.basename(File.dirname(file)) + '/' + File.basename(file) do
        let(:adv) { Bundler::Audit::Advisory.load(file) }
        let(:name) { File.basename(File.dirname(file)) }

        let(:probe_versions) do
          requirements = (adv.unaffected_versions + adv.patched_versions)
          versions = requirements.flat_map { |req|
            req.requirements.map { |(_op,gem_version)| gem_version.version }
          }.uniq
          versions.concat(%w[0.0.1 999.999.999])
          versions.uniq
        end

        it 'keeps the boolean equal to an independent recomputation' do
          probe_versions.each do |v|
            d = described_class.new(adv,Gem::Version.new(v),name)
            independent = adv.unaffected_versions.none? { |r| r.satisfied_by?(Gem::Version.new(v)) } &&
                          adv.patched_versions.none? { |r| r.satisfied_by?(Gem::Version.new(v)) }

            expect(d.vulnerable?).to eq(independent),
              "decision boolean != independent range eval for #{v}"
            expect(adv.vulnerable?(Gem::Version.new(v))).to eq(d.vulnerable?),
              "Advisory#vulnerable? diverged from the decision for #{v}"
          end
        end

        it 'records a check for every declared range on every probe' do
          probe_versions.each do |v|
            d = described_class.new(adv,Gem::Version.new(v),name)
            expected = adv.unaffected_versions.size + adv.patched_versions.size

            expect(d.range_checks.size).to eq(expected)
          end
        end
      end
    end
  end

  #
  # Mutant: an implementation that deliberately inverts the range priority by
  # letting patched ranges win over unaffected ones when choosing the verdict.
  # The boolean `vulnerable?` stays an AND of the two, so the defect is exposed
  # through (a) the verdict/explanation classification and (b) a cross-check
  # harness that recomputes the verdict independently.
  #
  describe 'inverted-priority variant' do
    # The buggy classifier: same Gem::Requirement comparisons, but patched is
    # allowed to win the verdict over unaffected.
    let(:inverted_classifier) do
      lambda do |advisory,version|
        v = Gem::Version.new(version.to_s)
        patched = advisory.patched_versions.any? { |r| r.satisfied_by?(v) }
        unaffected = advisory.unaffected_versions.any? { |r| r.satisfied_by?(v) }

        # BUG: patched branch is evaluated first and takes precedence.
        return :patched if patched
        return :unaffected if unaffected

        :vulnerable
      end
    end

    # An advisory whose unaffected and patched ranges overlap for 2.5.0.
    let(:overlap_advisory) do
      adv = Bundler::Audit::Advisory.new
      adv.id = 'MUTANT-1'
      adv.path = 'mutant/MUTANT-1.yml'
      adv.unaffected_versions = [Gem::Requirement.new('>= 1.0.0')]
      adv.patched_versions    = [Gem::Requirement.new('>= 2.0.0')]
      adv
    end

    let(:overlap_version) { '2.5.0' }

    it 'is caught because the inverted verdict disagrees with the engine' do
      correct = described_class.new(
        overlap_advisory,Gem::Version.new(overlap_version),'gem')
      buggy_verdict = inverted_classifier.call(overlap_advisory,overlap_version)

      expect(correct.range_checks.count { |c| c[:matched] }).to eq(2)
      expect(correct.verdict).to eq(:unaffected)
      expect(buggy_verdict).to eq(:patched)
      expect(buggy_verdict).to_not eq(correct.verdict)
    end

    it 'is caught because the explanation reproduces the correct precedence' do
      correct = described_class.new(
        overlap_advisory,Gem::Version.new(overlap_version),'gem')

      expect(correct.explain).to include('verdict: unaffected')
      expect(correct.explain).to include(overlap_advisory.path)
      expect(correct.explain).to include('unaffected takes precedence')
      expect(correct.to_h[:verdict]).to eq('unaffected')
    end

    it 'keeps the boolean stable even though the verdict flips' do
      # Documents why the boolean alone is insufficient: both orderings agree
      # on `vulnerable?`, but only the explanation/verdict reveals the defect.
      correct = described_class.new(
        overlap_advisory,Gem::Version.new(overlap_version),'gem')

      expect(correct.vulnerable?).to eq(false)
      expect(overlap_advisory.vulnerable?(Gem::Version.new(overlap_version))).to eq(false)
    end

    it 'detects the ordering difference across every dual-range real advisory' do
      dual = Dir.glob(File.join(Fixtures::Database::PATH,'gems','*','*.yml')).select do |file|
        data = Bundler::Audit::Advisory.load(file)
        !data.unaffected_versions.empty? && !data.patched_versions.empty?
      end

      expect(dual).to_not be_empty

      drift_found = dual.any? do |file|
        adv = Bundler::Audit::Advisory.load(file)
        name = File.basename(File.dirname(file))
        probes = (adv.unaffected_versions + adv.patched_versions).flat_map { |req|
          req.requirements.map { |_op, gem_version| gem_version.version }
        }.uniq

        probes.any? do |v|
          correct = described_class.new(adv,Gem::Version.new(v),name)
          buggy_verdict = inverted_classifier.call(adv,v)
          correct.verdict != buggy_verdict
        end
      end

      expect(drift_found).to eq(true)
    end
  end
end
