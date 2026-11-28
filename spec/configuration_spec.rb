require 'spec_helper'
require 'bundler/audit/configuration'

describe Bundler::Audit::Configuration do
  describe "when building from a yaml file" do
    let(:fixtures_dir) { File.expand_path('../fixtures/config',__FILE__) }

    subject { described_class.load(path) }

    context "when the file does not exist" do
      let(:path) { File.join(fixtures_dir,'bad','does_not_exist.yml') }

      it 'raises an error' do
        expect { subject }.to raise_error(described_class::FileNotFound, /Configuration file '.*' does not exist/)
      end
    end

    context "when the file does exist" do
      let(:path) { File.join(fixtures_dir,'valid.yml')   }

      it { should be_a(described_class) }
    end

    context "validations" do
      context "when the file is empty" do
        let(:path) { File.join(fixtures_dir,'bad','empty.yml') }

        it 'raises a validation error' do
          expect { subject }.to raise_error(described_class::InvalidConfigurationError)
        end
      end

      context "when ignore is not an array" do
        let(:path) { File.join(fixtures_dir,'bad','ignore_is_not_an_array.yml') }

        it 'raises a validation error' do
          expect { subject }.to raise_error(described_class::InvalidConfigurationError)
        end
      end

      context "when exemptions is not an array" do
        let(:path) { File.join(fixtures_dir,'bad','exemptions_is_not_an_array.yml') }

        it 'raises a validation error' do
          expect { subject }.to raise_error(described_class::InvalidConfigurationError)
        end
      end

      context "when an exemption is missing its reason" do
        let(:path) { File.join(fixtures_dir,'bad','exemption_missing_reason.yml') }

        it "raises a validation error naming the reason" do
          expect { subject }.to raise_error(described_class::InvalidConfigurationError,/reason/)
        end
      end

      context 'when ignore is an array' do
        context 'when ignore only contains strings' do
          let(:path) { File.join(fixtures_dir,'valid.yml')   }

          it { should be_a(described_class) }
        end

        describe "when ignore contains non-strings" do
          let(:path) { File.join(fixtures_dir,'bad','ignore_contains_a_non_string.yml') }

          it "raises a validation error" do
            expect { subject }.to raise_error(described_class::InvalidConfigurationError)
          end
        end
      end
    end
  end

  describe "#initialize" do
    context "when given no arguments" do
      it "must set @ignore to an empty Set" do
        expect(subject.ignore).to be_kind_of(Set)
        expect(subject.ignore).to be_empty
      end
    end

    context "when given :ignore" do
      let(:advisory_ids) { %w[CVE-123 CVE-456] }

      subject { described_class.new(ignore: advisory_ids) }

      it "must initialize @ignore to contain :ignore" do
        expect(subject.ignore).to be_kind_of(Set)
        expect(subject.ignore).to be == Set.new(advisory_ids)
      end
    end

    context "when given :exemptions" do
      let(:exemption) do
        {
          advisory:    'CVE-2026-0001',
          gem:         'example',
          reason:      'vendor patch',
          expires_on:  '2026-12-31',
          approved_by: 'security-team'
        }
      end

      subject { described_class.new(exemptions: [exemption]) }

      it "must build Exemption objects" do
        expect(subject.exemptions.length).to eq(1)

        built = subject.exemptions.first
        expect(built).to be_kind_of(Bundler::Audit::Exemption)
        expect(built.advisory).to eq('CVE-2026-0001')
        expect(built.gem).to eq('example')
        expect(built.reason).to eq('vendor patch')
        expect(built.expires_on).to eq(Date.new(2026,12,31))
        expect(built.approved_by).to eq('security-team')
      end

      context "when the exemption is invalid" do
        let(:exemption) { {advisory: 'CVE-2026-0001'} }

        it "raises an invalid configuration error" do
          expect {
            described_class.new(exemptions: [exemption])
          }.to raise_error(described_class::InvalidConfigurationError,/reason/)
        end
      end
    end
  end

  describe "loading exemptions from YAML" do
    let(:path) { File.join(__dir__,'bundle','source_policy_exempted','.bundler-audit.yml') }

    subject { described_class.load(path) }

    it "must load the exemption and its approval reason" do
      expect(subject.ignore).to be_empty
      expect(subject.exemptions.length).to eq(2)

      first = subject.exemptions.first
      expect(first.advisory).to eq('CVE-2026-0001')
      expect(first.gem).to eq('testgem')
      expect(first.reason).to eq('vendor patch shipped in the application image')
      expect(first.approved_by).to eq('security-team')
      expect(first.expires_on).to eq(Date.new(2026,12,31))
    end
  end
end
