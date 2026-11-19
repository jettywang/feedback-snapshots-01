require 'spec_helper'
require 'bundler/audit/remediation'
require 'bundler/audit/advisory'

describe Bundler::Audit::Remediation do
  def build_advisory(id, patched: [], unaffected: [])
    Bundler::Audit::Advisory.new(
      nil,
      id,
      nil,
      "Advisory #{id}",
      nil,
      nil,
      nil,
      nil,
      nil,
      nil,
      nil,
      nil,
      unaffected.map { |requirements| Gem::Requirement.new(*requirements) },
      patched.map { |requirements| Gem::Requirement.new(*requirements) }
    )
  end

  let(:gem_name) { 'testgem' }

  describe "#suggest" do
    context "when advisories have multiple patched branches" do
      let(:advisories) do
        [
          build_advisory('CVE-2015-0001', patched: [['>= 1.8']]),
          build_advisory('CVE-2016-0002', patched: [['>= 1.2', '< 1.9'], ['>= 2.0']])
        ]
      end

      let(:versions) { %w[1.5.0 1.8.1 1.9.5 2.0.0] }

      subject do
        described_class.new(gem: gem_name, versions: versions, advisories: advisories).suggest
      end

      it "must select the minimal version avoiding every advisory, not the maximum patched lower bound" do
        expect(subject).to be_a(described_class::Suggestion)
        expect(subject.version).to eq(Gem::Version.new('1.8.1'))
        expect(subject.version).to be < Gem::Version.new('2.0.0')
      end

      it "must record per-advisory evidence with the exact matching requirement" do
        evidence = subject.advisory_evidence

        expect(evidence.length).to eq(2)
        expect(evidence[0][:advisory].id).to eq('CVE-2015-0001')
        expect(evidence[0][:status]).to eq(:patched)
        expect(evidence[0][:requirement]).to eq(Gem::Requirement.new('>= 1.8'))
        expect(evidence[1][:advisory].id).to eq('CVE-2016-0002')
        expect(evidence[1][:status]).to eq(:patched)
        expect(evidence[1][:requirement]).to eq(Gem::Requirement.new('>= 1.2', '< 1.9'))
      end

      it "must preserve the actual exclusion reasons for every rejected candidate" do
        exclusions = subject.exclusions

        vulnerable_to_first = exclusions.find { |evaluation| evaluation.version == Gem::Version.new('1.5.0') }
        expect(vulnerable_to_first.reasons).to eq([
          {type: :advisory, advisory: advisories[0]}
        ])

        vulnerable_to_second = exclusions.find { |evaluation| evaluation.version == Gem::Version.new('1.9.5') }
        expect(vulnerable_to_second.reasons).to eq([
          {type: :advisory, advisory: advisories[1]}
        ])
      end

      it "must provide minimality evidence covering every smaller candidate" do
        minimality = subject.minimality_evidence

        expect(minimality.map(&:version)).to eq([Gem::Version.new('1.5.0')])
        expect(minimality.first.reasons.first[:advisory].id).to eq('CVE-2015-0001')
      end

      it "must be definite when no source or platform metadata is involved" do
        expect(subject.definite?).to be(true)
        expect(subject.caveats).to be_empty
      end
    end

    context "when a version falls into an unaffected range" do
      let(:advisories) do
        [
          build_advisory('CVE-2017-0003',
                         unaffected: [['< 1.0']],
                         patched:    [['>= 2.0']])
        ]
      end

      let(:versions) { %w[0.9.9 1.5.0 2.0.0] }

      subject do
        described_class.new(gem: gem_name, versions: versions, advisories: advisories).suggest
      end

      it "must accept the unaffected version as minimal" do
        expect(subject.version).to eq(Gem::Version.new('0.9.9'))
      end

      it "must record the unaffected status and matching requirement" do
        evidence = subject.advisory_evidence.first

        expect(evidence[:status]).to eq(:unaffected)
        expect(evidence[:requirement]).to eq(Gem::Requirement.new('< 1.0'))
      end

      it "must exclude versions that are neither patched nor unaffected" do
        excluded = subject.exclusions.find { |evaluation| evaluation.version == Gem::Version.new('1.5.0') }

        expect(excluded.reasons).to eq([{type: :advisory, advisory: advisories[0]}])
      end
    end

    context "when the minimal patched version is a prerelease" do
      let(:advisories) do
        [build_advisory('CVE-2018-0004', patched: [['>= 1.2.0.rc1']])]
      end

      let(:versions) { %w[1.1.0 1.2.0.rc1 1.2.0] }

      context "and prereleases are not permitted" do
        subject do
          described_class.new(gem: gem_name, versions: versions, advisories: advisories).suggest
        end

        it "must skip the prerelease and select the minimal stable version" do
          expect(subject.version).to eq(Gem::Version.new('1.2.0'))
        end

        it "must record the prerelease exclusion reason" do
          excluded = subject.exclusions.find { |evaluation| evaluation.version == Gem::Version.new('1.2.0.rc1') }

          expect(excluded.reasons).to include({type: :prerelease})
        end
      end

      context "and prereleases are permitted" do
        subject do
          described_class.new(gem: gem_name, versions: versions, advisories: advisories, allow_prerelease: true).suggest
        end

        it "must select the prerelease version" do
          expect(subject.version).to eq(Gem::Version.new('1.2.0.rc1'))
        end
      end
    end

    context "when the project declares explicit constraints" do
      let(:advisories) do
        [build_advisory('CVE-2019-0005', patched: [['>= 1.2']])]
      end

      let(:constraints) { ['>= 1.1', '< 2.0'] }
      let(:versions)    { %w[1.0.0 1.1.0 1.2.0 2.0.0] }

      subject do
        described_class.new(
          gem:         gem_name,
          versions:    versions,
          advisories:  advisories,
          constraints: constraints
        ).suggest
      end

      it "must select the minimal version satisfying every constraint" do
        expect(subject.version).to eq(Gem::Version.new('1.2.0'))
      end

      it "must record which requirement excluded each candidate" do
        too_low = subject.exclusions.find { |evaluation| evaluation.version == Gem::Version.new('1.0.0') }
        expect(too_low.reasons).to include(
          {type: :constraint, requirement: Gem::Requirement.new('>= 1.1')}
        )

        too_high = subject.exclusions.find { |evaluation| evaluation.version == Gem::Version.new('2.0.0') }
        expect(too_high.reasons).to include(
          {type: :constraint, requirement: Gem::Requirement.new('< 2.0')}
        )
      end
    end

    context "when three mutually constraining advisories leave no common candidate" do
      # After the two project constraints (>= 1.1, < 2.2) the candidates are
      # 1.1.0, 1.2.0, 1.5.0, 2.0.0, and 2.1.0. Each advisory is avoidable on
      # its own and each pair of advisories shares a candidate, but no single
      # version avoids all three:
      #
      #   CVE-2020-0011: {1.2.0, 1.5.0}
      #   CVE-2020-0012: {1.5.0, 2.1.0}
      #   CVE-2020-0013: {1.2.0, 2.1.0}
      #
      let(:advisories) do
        [
          build_advisory('CVE-2020-0011', patched: [['>= 1.2', '< 2.0']]),
          build_advisory('CVE-2020-0012', patched: [['~> 1.5.0'], ['~> 2.1.0']]),
          build_advisory('CVE-2020-0013', patched: [['~> 1.2.0'], ['~> 2.1.0']])
        ]
      end

      let(:constraints) { ['>= 1.1', '< 2.2'] }
      let(:versions)    { %w[1.0.0 1.1.0 1.2.0 1.5.0 2.0.0 2.1.0 2.2.0] }

      subject do
        described_class.new(
          gem:         gem_name,
          versions:    versions,
          advisories:  advisories,
          constraints: constraints
        ).suggest
      end

      it "must report the gem as unsatisfiable instead of faking a solution" do
        expect(subject).to be_a(described_class::Unsatisfiable)
        expect(subject.definite?).to be(false)
      end

      it "must show the candidates that survived the project constraints" do
        expect(subject.constraint_survivors).to eq(
          %w[1.1.0 1.2.0 1.5.0 2.0.0 2.1.0].map { |version| Gem::Version.new(version) }
        )
      end

      it "must show that each advisory is individually avoidable" do
        expect(subject.advisory_survivors['CVE-2020-0011']).to eq(
          [Gem::Version.new('1.2.0'), Gem::Version.new('1.5.0')]
        )
        expect(subject.advisory_survivors['CVE-2020-0012']).to eq(
          [Gem::Version.new('1.5.0'), Gem::Version.new('2.1.0')]
        )
        expect(subject.advisory_survivors['CVE-2020-0013']).to eq(
          [Gem::Version.new('1.2.0'), Gem::Version.new('2.1.0')]
        )
      end

      it "must record why the out-of-constraint candidates were rejected" do
        too_low = subject.exclusions.find { |evaluation| evaluation.version == Gem::Version.new('1.0.0') }
        expect(too_low.reasons).to include(
          {type: :constraint, requirement: Gem::Requirement.new('>= 1.1')}
        )

        too_high = subject.exclusions.find { |evaluation| evaluation.version == Gem::Version.new('2.2.0') }
        expect(too_high.reasons).to include(
          {type: :constraint, requirement: Gem::Requirement.new('< 2.2')}
        )
      end

      it "must record which advisories excluded each surviving candidate" do
        excluded = subject.exclusions.find { |evaluation| evaluation.version == Gem::Version.new('1.5.0') }

        expect(excluded.reasons).to eq([{type: :advisory, advisory: advisories[2]}])
      end

      context "but any pair of the advisories still shares a candidate" do
        it "must find a suggestion when one advisory is removed" do
          result = described_class.new(
            gem:         gem_name,
            versions:    versions,
            advisories:  advisories.first(2),
            constraints: constraints
          ).suggest

          expect(result).to be_a(described_class::Suggestion)
          expect(result.version).to eq(Gem::Version.new('1.5.0'))
        end
      end
    end

    context "when a candidate comes from a source not covered by the constraints" do
      let(:advisories) do
        [build_advisory('CVE-2021-0006', patched: [['>= 1.2']])]
      end

      context "and a covered candidate also survives" do
        subject do
          described_class.new(
            gem:      gem_name,
            versions: [
              {version: '1.2.0', source: :git},
              {version: '1.3.0', source: :rubygems}
            ],
            advisories:      advisories,
            covered_sources: [:rubygems]
          ).suggest
        end

        it "must select the minimal covered candidate" do
          expect(subject.version).to eq(Gem::Version.new('1.3.0'))
          expect(subject.definite?).to be(true)
        end

        it "must note the smaller uncovered candidate in the caveats" do
          expect(subject.caveats.length).to eq(1)
          expect(subject.caveats.first).to include('1.2.0')
          expect(subject.caveats.first).to include(':git')
        end
      end

      context "and only uncovered candidates survive" do
        subject do
          described_class.new(
            gem:      gem_name,
            versions: [{version: '1.2.0', source: :git}],
            advisories: advisories
          ).suggest
        end

        it "must not give a definite suggestion" do
          expect(subject).to be_a(described_class::Suggestion)
          expect(subject.definite?).to be(false)
        end

        it "must explain that the source is not covered" do
          expect(subject.caveats.first).to include('source :git is not covered')
        end
      end
    end

    context "when a candidate targets a platform not covered by the constraints" do
      let(:advisories) do
        [build_advisory('CVE-2022-0007', patched: [['>= 1.2']])]
      end

      subject do
        described_class.new(
          gem:      gem_name,
          versions: [{version: '1.2.0', platform: :java}],
          advisories:       advisories,
          covered_platforms: [:ruby]
        ).suggest
      end

      it "must not give a definite suggestion" do
        expect(subject.definite?).to be(false)
        expect(subject.caveats.first).to include('platform :java is not covered')
      end
    end

    context "when the candidate list is empty" do
      subject do
        described_class.new(gem: gem_name, versions: []).suggest
      end

      it "must report the gem as unsatisfiable" do
        expect(subject).to be_a(described_class::Unsatisfiable)
        expect(subject.constraint_survivors).to be_empty
      end
    end
  end

  describe ".suggest" do
    it "must delegate to an instance" do
      result = described_class.suggest(gem: gem_name, versions: %w[1.0.0])

      expect(result).to be_a(described_class::Suggestion)
      expect(result.version).to eq(Gem::Version.new('1.0.0'))
    end
  end

  describe "result serialization" do
    let(:advisories) do
      [build_advisory('CVE-2023-0008', patched: [['>= 1.2']])]
    end

    it "must serialize a suggestion to a Hash" do
      suggestion = described_class.new(
        gem:         gem_name,
        versions:    %w[1.1.0 1.2.0],
        advisories:  advisories,
        constraints: ['>= 1.0']
      ).suggest

      hash = suggestion.to_h

      expect(hash[:type]).to eq(:remediation_suggestion)
      expect(hash[:version]).to eq(Gem::Version.new('1.2.0'))
      expect(hash[:advisory_evidence]).to eq([
        {advisory: 'CVE-2023-0008', status: :patched, requirement: '>= 1.2'}
      ])
      expect(hash[:exclusions]).to eq([
        {version: Gem::Version.new('1.1.0'), reasons: [{type: :advisory, advisory: 'CVE-2023-0008'}]}
      ])
    end

    it "must serialize an unsatisfiable result to a Hash" do
      result = described_class.new(
        gem:        gem_name,
        versions:   %w[1.0.0],
        advisories: advisories
      ).suggest

      hash = result.to_h

      expect(hash[:type]).to eq(:remediation_unsatisfiable)
      expect(hash[:advisory_survivors]).to eq('CVE-2023-0008' => [])
    end
  end
end
