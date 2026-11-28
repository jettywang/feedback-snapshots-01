require 'spec_helper'
require 'bundler/audit/cli/formats'
require 'bundler/audit/cli/formats/text'
require 'bundler/audit/report'

describe Bundler::Audit::CLI::Formats::Text do
  it "must register the 'text' format" do
    expect(Bundler::Audit::CLI::Formats[:text]).to be described_class
  end

  let(:options) { {} }

  subject do
    Bundler::Audit::CLI.new([],options).tap do |obj|
      obj.extend described_class
    end
  end

  describe "#print_report" do
    let(:report) { Bundler::Audit::Report.new }
    let(:stdout) { StringIO.new }

    before { subject.print_report(report,stdout) }

    let(:output) { stdout.string }
    let(:output_lines) { output.lines.map(&:chomp) }

    context "when vulnerabilities were found" do
      context "when the report contains InsecureSources" do
        let(:uri) { URI('git://github.com/foo/bar.git') }
        let(:insecure_source) do
          Bundler::Audit::Results::InsecureSource.new(uri)
        end

        let(:report) do
          super().tap do |report|
            report << insecure_source
          end
        end

        it 'must print "Insecure Source URI found: ..."' do
          expect(output_lines).to include("Insecure Source URI found: #{uri}")
        end

        it 'must print "Vulnerabilities found!"' do
          expect(output_lines).to include("Vulnerabilities found!")
        end
      end

      context "when the report contains UnpatchedGems" do
        let(:gem) do
          Gem::Specification.new do |spec|
            spec.name = 'test'
            spec.version = '0.1.0'
          end
        end

        let(:advisory) do
          Bundler::Audit::Advisory.load(Fixtures.join('advisory','CVE-2020-1234.yml'))
        end
        let(:unpatched_gem) do
          Bundler::Audit::Results::UnpatchedGem.new(gem,advisory)
        end

        let(:report) do
          super().tap do |report|
            report << unpatched_gem
          end
        end

        it "must print 'Name: ...'" do
          expect(output_lines).to include("Name: #{gem.name}")
        end

        it "must print 'Version: ...'" do
          expect(output_lines).to include("Version: #{gem.version}")
        end

        context "when the advisory has a CVE ID" do
          it "must print 'CVE: CVE-YYYY-NNNN'" do
            expect(output_lines).to include("CVE: CVE-#{advisory.cve}")
          end
        end

        context "when the advisory does not have a CVE ID" do
          before { advisory.cve = nil }

          it "must not print 'CVE: CVE-YYYY-NNNN'" do
            expect(output_lines).to_not include("CVE: CVE-#{advisory.cve}")
          end
        end

        context "when the advisory has a GHSA ID" do
          it "must print 'GHSA: GHSA-xxxx-xxxx-xxxx'" do
            expect(output_lines).to include("GHSA: GHSA-#{advisory.ghsa}")
          end
        end

        context "when the advisory does not have a GHSA ID" do
          before { advisory.ghsa = nil }

          it "must not print 'GHSA: GHSA-xxxx-xxxx-xxxx'" do
            expect(output_lines).to_not include("GHSA: GHSA-#{advisory.ghsa}")
          end
        end

        context "when CVSS v4 is present" do
          context "when Advisory#criticality is :none" do
            let(:advisory) do
              super().tap do |advisory|
                advisory.cvss_v4 = 0.0
              end
            end

            it "must print 'Criticality: None'" do
              expect(output_lines).to include("Criticality: None")
            end
          end

          context "when Advisory#criticality is :low" do
            let(:advisory) do
              super().tap do |advisory|
                advisory.cvss_v4 = 0.1
              end
            end

            it "must print 'Criticality: Low'" do
              expect(output_lines).to include("Criticality: Low")
            end
          end

          context "when Advisory#criticality is :medium" do
            let(:advisory) do
              super().tap do |advisory|
                advisory.cvss_v4 = 4.0
              end
            end

            it "must print 'Criticality: Medium'" do
              expect(output_lines).to include("Criticality: Medium")
            end
          end

          context "when Advisory#criticality is :high" do
            let(:advisory) do
              super().tap do |advisory|
                advisory.cvss_v4 = 7.0
              end
            end

            it "must print 'Criticality: High'" do
              expect(output_lines).to include("Criticality: High")
            end
          end

          context "when Advisory#criticality is :critical" do
            let(:advisory) do
              super().tap do |advisory|
                advisory.cvss_v4 = 9.0
              end
            end

            it "must print 'Criticality: High'" do
              expect(output_lines).to include("Criticality: Critical")
            end
          end
        end

        context "when CVSS v3 is present" do
          let(:advisory) do
            super().tap do |advisory|
              advisory.cvss_v4 = nil
            end
          end

          context "when Advisory#criticality is :none" do
            let(:advisory) do
              super().tap do |advisory|
                advisory.cvss_v3 = 0.0
              end
            end

            it "must print 'Criticality: None'" do
              expect(output_lines).to include("Criticality: None")
            end
          end

          context "when Advisory#criticality is :low" do
            let(:advisory) do
              super().tap do |advisory|
                advisory.cvss_v3 = 0.1
              end
            end

            it "must print 'Criticality: Low'" do
              expect(output_lines).to include("Criticality: Low")
            end
          end

          context "when Advisory#criticality is :medium" do
            let(:advisory) do
              super().tap do |advisory|
                advisory.cvss_v3 = 4.0
              end
            end

            it "must print 'Criticality: Medium'" do
              expect(output_lines).to include("Criticality: Medium")
            end
          end

          context "when Advisory#criticality is :high" do
            let(:advisory) do
              super().tap do |advisory|
                advisory.cvss_v3 = 7.0
              end
            end

            it "must print 'Criticality: High'" do
              expect(output_lines).to include("Criticality: High")
            end
          end

          context "when Advisory#criticality is :critical" do
            let(:advisory) do
              super().tap do |advisory|
                advisory.cvss_v3 = 9.0
              end
            end

            it "must print 'Criticality: High'" do
              expect(output_lines).to include("Criticality: Critical")
            end
          end
        end

        context "when CVSS v2 is present" do
          let(:advisory) do
            super().tap do |advisory|
              advisory.cvss_v3 = nil
              advisory.cvss_v4 = nil
            end
          end

          context "when Advisory#criticality is :low" do
            let(:advisory) do
              super().tap do |advisory|
                advisory.cvss_v2 = 0.0
              end
            end

            it "must print 'Criticality: Low'" do
              expect(output_lines).to include("Criticality: Low")
            end
          end

          context "when Advisory#criticality is :medium" do
            let(:advisory) do
              super().tap do |advisory|
                advisory.cvss_v2 = 4.0
              end
            end

            it "must print 'Criticality: Medium'" do
              expect(output_lines).to include("Criticality: Medium")
            end
          end

          context "when Advisory#criticality is :high" do
            let(:advisory) do
              super().tap do |advisory|
                advisory.cvss_v2 = 7.0
              end
            end

            it "must print 'Criticality: High'" do
              expect(output_lines).to include("Criticality: High")
            end
          end
        end

        it "must print 'URL: ...'" do
          expect(output_lines).to include("URL: #{advisory.url}")
        end

        context "when :verbose is enabled" do
          let(:options) { {verbose: true} }

          it 'must print "Description:" and the advisory description' do
            expect(output_lines).to include("Description:","","  #{advisory.description.chomp}",'')
          end
        end

        context "when :verbose is not enabled" do
          it 'must print "Title:" and the advisory description' do
            expect(output_lines).to include("Title: #{advisory.title}")
          end
        end

        context "when Advisory#patched_versions is not empty" do
          it 'must print "Solution: update to ..."' do
            expect(output_lines).to include("Solution: update to #{advisory.patched_versions.map { |v| "'#{v}'" }.join(', ')}")
          end
        end

        context "when Advisory#patched_versions is empty" do
          let(:advisory) do
            super().tap do |advisory|
              advisory.patched_versions = []
            end
          end

          it 'must print "Solution: remove or disable this gem until a patch is available!"' do
            expect(output_lines).to include("Solution: remove or disable this gem until a patch is available!")
          end
        end

        it 'must print "Vulnerabilities found!"' do
          expect(output_lines).to include("Vulnerabilities found!")
        end
      end
    end

    context "when an advisory was exempted" do
      let(:exemption) do
        Bundler::Audit::Exemption.new(
          advisory: 'CVE-2020-1234',
          reason:   'vendor patch shipped in the application image',
          expires_on: '2026-12-31'
        )
      end
      let(:gem) do
        Gem::Specification.new do |spec|
          spec.name = 'test'
          spec.version = '0.1.0'
        end
      end
      let(:advisory) do
        Bundler::Audit::Advisory.load(Fixtures.join('advisory','CVE-2020-1234.yml'))
      end
      let(:exempted_gem) do
        Bundler::Audit::Results::ExemptedGem.new(gem,advisory,exemption)
      end
      let(:report) do
        super().tap { |report| report << exempted_gem }
      end

      it "prints the approval and its reason" do
        expect(output_lines).to include(
          'Name: test',
          'Advisory: CVE-2020-1234',
          'Exempted: vendor patch shipped in the application image',
          'Expires on: 2026-12-31'
        )
      end

      it "does not report vulnerabilities" do
        expect(output_lines).to include('No vulnerabilities found')
        expect(output_lines).to_not include('Vulnerabilities found!')
      end
    end

    context "when a source is undetermined" do
      let(:assessment) do
        Bundler::Audit::Results::SourceAssessment.new('http://gems.internal.example/',:undetermined,
          reason: 'source host could not be resolved')
      end
      let(:report) do
        super().tap { |report| report << assessment }
      end

      it "distinguishes undetermined evidence from an explicit block" do
        expect(output_lines).to include(
          'Source identity undetermined: http://gems.internal.example/',
          'Reason: source host could not be resolved',
          'Vulnerabilities found!',
          'Source identity undetermined for 1 source(s)'
        )
        expect(output_lines.join("\n")).to_not include('Insecure Source URI found')
      end
    end

    context "when no vulnerabilities were found" do
      it 'must print "No vulnerabilities found"' do
        expect(output_lines).to include('No vulnerabilities found')
      end

      context "when :quiet is enabled" do
        let(:options) { {quiet: true} }

        it "should print nothing" do
          expect(output_lines).to be_empty
        end
      end
    end

    it "must restore $stdout" do
      expect($stdout).to_not be(stdout)
    end
  end
end
