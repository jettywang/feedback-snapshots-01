require 'spec_helper'
require 'bundler/audit/correlation'
require 'bundler/audit/results/insecure_source'
require 'bundler/audit/results/unpatched_gem'
require 'bundler/audit/report'
require 'bundler/audit/scanner'
require 'bundler/audit/advisory'

require 'fileutils'
require 'support/correlation_check'

describe Bundler::Audit::Correlation do
  let(:sample_dir) { File.join('spec','bundle','correlation_sample') }
  let(:database)   { SpecSupport::StaticDatabase.new(File.join('spec','fixtures','correlation_db')) }
  let(:lockfile)   { File.read(File.join(sample_dir,'Gemfile.lock')) }

  let(:advisory) do
    Bundler::Audit::Advisory.load(Fixtures.join('advisory','CVE-2020-1234.yml'))
  end

  let(:gem_1_0) do
    Gem::Specification.new do |spec|
      spec.name    = 'widget'
      spec.version = '1.0.0'
    end
  end

  let(:gem_1_5) do
    Gem::Specification.new do |spec|
      spec.name    = 'widget'
      spec.version = '1.5.0'
    end
  end

  let(:gem_2_0) do
    Gem::Specification.new do |spec|
      spec.name    = 'widget'
      spec.version = '2.0.0'
    end
  end

  def finding(gem)
    Bundler::Audit::Results::UnpatchedGem.new(gem,advisory)
  end

  describe ".dependency" do
    it "returns a dependency-prefixed ID" do
      expect(finding(gem_1_0).correlation_id).to match(/^BA-DEP-[0-9a-f]{16}$/)
    end

    it "is deterministic for identical evidence" do
      expect(finding(gem_1_0).correlation_id).to be == finding(gem_1_0).correlation_id
    end

    it "ignores lockfile ordering by depending only on evidence" do
      expect(finding(gem_1_0).correlation_id).to be == finding(gem_1_0.dup).correlation_id
    end

    it "distinguishes different locked versions" do
      expect(finding(gem_1_0).correlation_id).to_not be == finding(gem_1_5).correlation_id
    end

    it "distinguishes the same version locked for different platforms" do
      native = Gem::Specification.new do |spec|
        spec.name     = 'widget'
        spec.version  = '1.0.0'
        spec.platform = 'x86_64-linux'
      end

      expect(finding(gem_1_0).correlation_id).to_not be == finding(native).correlation_id
    end

    it "distinguishes different advisories for the same gem" do
      other_advisory = Bundler::Audit::Advisory.load(Fixtures.join('advisory','CVE-2020-1234.yml'))
      other_advisory.id = 'CVE-2026-9999'

      other = Bundler::Audit::Results::UnpatchedGem.new(gem_1_0,other_advisory)

      expect(finding(gem_1_0).correlation_id).to_not be == other.correlation_id
    end

    it "distinguishes the same version from different sources" do
      rubygems_source = Bundler::Source::Rubygems.new(
        'remotes' => ['https://rubygems.org/']
      )
      git_source = Bundler::Source::Git.new(
        'uri'      => 'https://github.com/acme/widget.git',
        'revision' => '0123456789abcdef0123456789abcdef01234567'
      )

      gem_2_0.source = rubygems_source
      other         = Gem::Specification.new do |spec|
        spec.name    = 'widget'
        spec.version = '2.0.0'
      end
      other.source = git_source

      expect(finding(gem_2_0).correlation_id).to_not be == finding(other).correlation_id
    end

    it "distinguishes the same version locked from different git revisions" do
      source_a = Bundler::Source::Git.new(
        'uri'      => 'https://github.com/acme/widget.git',
        'revision' => '0123456789abcdef0123456789abcdef01234567'
      )
      source_b = Bundler::Source::Git.new(
        'uri'      => 'https://github.com/acme/widget.git',
        'revision' => 'fedcba9876543210fedcba9876543210fedcba98'
      )

      gem_2_0.source = source_a
      other         = Gem::Specification.new do |spec|
        spec.name    = 'widget'
        spec.version = '2.0.0'
      end
      other.source = source_b

      expect(finding(gem_2_0).correlation_id).to_not be == finding(other).correlation_id
    end
  end

  describe ".source" do
    it "returns a source-prefixed ID" do
      expect(Bundler::Audit::Results::InsecureSource.new('git://example.com/x.git').correlation_id).to match(/^BA-SRC-[0-9a-f]{16}$/)
    end

    it "is deterministic" do
      uri = URI('git://github.com/rails/jquery-rails.git')

      expect(Bundler::Audit::Results::InsecureSource.new(uri).correlation_id).to be ==
        Bundler::Audit::Results::InsecureSource.new(uri.to_s).correlation_id
    end

    it "normalizes scheme and host casing" do
      lower = Bundler::Audit::Results::InsecureSource.new('git://github.com/acme/widget.git')
      mixed = Bundler::Audit::Results::InsecureSource.new('GIT://GitHub.COM/acme/widget.git')

      expect(lower.correlation_id).to be == mixed.correlation_id
    end

    it "distinguishes different sources" do
      a = Bundler::Audit::Results::InsecureSource.new('git://github.com/acme/widget.git')
      b = Bundler::Audit::Results::InsecureSource.new('http://rubygems.org/')

      expect(a.correlation_id).to_not be == b.correlation_id
    end

    it "never collides with a dependency finding" do
      dependency = finding(gem_1_0).correlation_id
      source     = Bundler::Audit::Results::InsecureSource.new('git://example.com/x.git').correlation_id

      expect(dependency).to_not be == source
    end
  end

  describe "integration with the scanner" do
    before do
      allow(Resolv).to receive(:getaddresses).and_return(['93.184.216.34'])
    end

    let(:report) { Bundler::Audit::Scanner.new(sample_dir,'Gemfile.lock',database).report }

    it "produces one finding per locked gem instance" do
      expect(report.unpatched_gems.map { |result|
        [result.gem.name, result.gem.version.to_s]
      }).to match_array([
        ['gadget',    '0.9.0'],
        ['local-tool','0.1.0'],
        ['widget',    '1.0.0'],
        ['widget',    '1.5.0'],
        ['widget',    '2.0.0']
      ])
    end

    it "produces a finding for the insecure source" do
      expect(report.insecure_sources.map(&:to_s)).to be == ['http://rubygems.org/']
    end

    it "assigns a distinct correlation ID to each finding" do
      expect(report.correlation_ids).to all(match(/^BA-(DEP|SRC)-[0-9a-f]{16}$/))
      expect(report.correlation_ids.uniq.length).to be == report.results.length
    end
  end

  describe "all three output formats" do
    let(:report) { Bundler::Audit::Scanner.new(sample_dir,'Gemfile.lock',database).report }

    before do
      allow(Resolv).to receive(:getaddresses).and_return(['93.184.216.34'])
    end

    let(:artifacts) { SpecSupport.render_all(report) }

    it "expose the same set of correlation IDs" do
      expected = report.correlation_ids.sort

      expect(SpecSupport.text_correlation_ids(artifacts['text']).sort).to be == expected
      expect(SpecSupport.json_correlation_ids(artifacts['json']).sort).to be == expected
      expect(SpecSupport.junit_correlation_ids(artifacts['junit']).sort).to be == expected
    end

    it "exposes exactly one correlation ID per finding in each format" do
      count = report.results.length

      expect(SpecSupport.text_correlation_ids(artifacts['text']).length).to be == count
      expect(SpecSupport.json_correlation_ids(artifacts['json']).length).to be == count
      expect(SpecSupport.junit_correlation_ids(artifacts['junit']).length).to be == count
    end

    it "cross-checks the three artifacts without merges or omissions" do
      check = SpecSupport.cross_check(
        artifacts['text'],
        artifacts['json'],
        artifacts['junit']
      )

      expect(check[:consistent]).to be true
      expect(check[:duplicates].values).to all(be_empty)
      expect(check[:missing].values).to all(be_empty)
      expect(check[:sets]['json']).to be == report.correlation_ids
    end

    it "uses the correlation ID as the JUnit testcase id" do
      expect(artifacts['junit']).to include(
        %{<testcase id="#{report.insecure_sources.first.correlation_id}"}
      )
    end

    it "keeps the plain-text advisory block intact" do
      result = report.unpatched_gems.first

      expect(artifacts['text']).to include("Name: #{result.gem.name}")
      expect(artifacts['text']).to include("Version: #{result.gem.version}")
      expect(artifacts['text']).to include("Correlation ID: #{result.correlation_id}")
    end
  end

  describe "lockfile reordering" do
    let(:reordered_dir) { File.join(Fixtures::TMP_DIR,'correlation_reordered') }

    before do
      allow(Resolv).to receive(:getaddresses).and_return(['93.184.216.34'])

      FileUtils.rm_rf(reordered_dir)
      FileUtils.mkdir_p(reordered_dir)

      reordered = lockfile.
        sub(%{    gadget (0.9.0)\n    widget (1.0.0)\n    widget (1.5.0)\n      gadget (~> 0.9)\n},
            %{    widget (1.5.0)\n      gadget (~> 0.9)\n    gadget (0.9.0)\n    widget (1.0.0)\n}).
        sub(%{  remote: http://rubygems.org/\n  remote: https://mirror.example.org/\n},
            %{  remote: https://mirror.example.org/\n  remote: http://rubygems.org/\n})

      File.write(File.join(reordered_dir,'Gemfile.lock'),reordered)
    end

    it "mints the same correlation IDs as the original order" do
      original  = Bundler::Audit::Scanner.new(sample_dir,'Gemfile.lock',database).report
      reordered = Bundler::Audit::Scanner.new(reordered_dir,'Gemfile.lock',database).report

      expect(reordered.correlation_ids.sort).to be == original.correlation_ids.sort
    end
  end

  describe "evidence changes" do
    before do
      allow(Resolv).to receive(:getaddresses).and_return(['93.184.216.34'])
    end

    let(:changed_dir) { File.join(Fixtures::TMP_DIR,'correlation_changed') }

    before do
      FileUtils.rm_rf(changed_dir)
      FileUtils.mkdir_p(changed_dir)
    end

    it "mints a new ID when a locked version changes" do
      original = Bundler::Audit::Scanner.new(sample_dir,'Gemfile.lock',database).report

      changed = lockfile.sub('    widget (1.5.0)','    widget (1.5.1)')
      File.write(File.join(changed_dir,'Gemfile.lock'),changed)

      updated = Bundler::Audit::Scanner.new(changed_dir,'Gemfile.lock',database).report

      expect(updated.correlation_ids).to_not be == original.correlation_ids
      expect((updated.correlation_ids - original.correlation_ids).length).to be == 1
    end

    it "mints a new ID when a git revision changes" do
      original = Bundler::Audit::Scanner.new(sample_dir,'Gemfile.lock',database).report

      changed = lockfile.sub('revision: 0123456789abcdef0123456789abcdef01234567',
                             'revision: fedcba9876543210fedcba9876543210fedcba98')
      File.write(File.join(changed_dir,'Gemfile.lock'),changed)

      updated = Bundler::Audit::Scanner.new(changed_dir,'Gemfile.lock',database).report

      expect(updated.correlation_ids).to_not be == original.correlation_ids
      expect((updated.correlation_ids - original.correlation_ids).length).to be == 1
    end

    it "mints a new ID when a git source changes" do
      original = Bundler::Audit::Scanner.new(sample_dir,'Gemfile.lock',database).report

      changed = lockfile.sub('  remote: https://github.com/acme/widget.git',
                             '  remote: https://github.com/acme/widget-fork.git')
      File.write(File.join(changed_dir,'Gemfile.lock'),changed)

      updated = Bundler::Audit::Scanner.new(changed_dir,'Gemfile.lock',database).report

      expect(updated.correlation_ids).to_not be == original.correlation_ids
      expect((updated.correlation_ids - original.correlation_ids).length).to be == 1
    end

    it "mints new IDs for every gem locked from a changed rubygems source" do
      original = Bundler::Audit::Scanner.new(sample_dir,'Gemfile.lock',database).report

      changed = lockfile.sub('  remote: http://rubygems.org/','  remote: https://rubygems.org/')
      File.write(File.join(changed_dir,'Gemfile.lock'),changed)

      updated = Bundler::Audit::Scanner.new(changed_dir,'Gemfile.lock',database).report

      expect(updated.correlation_ids).to_not be == original.correlation_ids
      expect((updated.correlation_ids - original.correlation_ids).length).to be == 3
      expect(updated.correlation_ids).to_not include(original.insecure_sources.first.correlation_id)
    end
  end
end
