require 'spec_helper'
require 'bundler/audit/runtime'

describe Bundler::Audit::Runtime::Target do
  describe "#engine" do
    it "normalizes engine aliases" do
      expect(described_class.new(engine: :mri).engine).to eq('ruby')
      expect(described_class.new(engine: 'CRuby').engine).to eq('ruby')
      expect(described_class.new(engine: :jruby).engine).to eq('jruby')
      expect(described_class.new(engine: :rubinius).engine).to eq('rbx')
    end

    it "is nil when no engine was supplied" do
      expect(described_class.new.engine).to be_nil
    end
  end

  describe "#known_engine?" do
    it "is true for supported engines" do
      expect(described_class.new(engine: :ruby)).to be_known_engine
      expect(described_class.new(engine: :jruby)).to be_known_engine
    end

    it "is false for unknown engines" do
      expect(described_class.new(engine: 'weirdruby')).to_not be_known_engine
    end
  end

  describe "#patchlevel" do
    it "keeps patchlevel separate from the version" do
      target = described_class.new(engine: :ruby, version: '3.2.2', patchlevel: 53)

      expect(target.version).to eq(Gem::Version.new('3.2.2'))
      expect(target.patchlevel).to eq(53)
    end

    it "splits a combined `2.5.0p0` version" do
      target = described_class.new(engine: :ruby, version: '2.5.0p0')

      expect(target.version).to eq(Gem::Version.new('2.5.0'))
      expect(target.patchlevel).to eq(0)
    end

    it "does not fold the patchlevel into an MRI version" do
      target = described_class.new(engine: :ruby, version: '3.2.2', patchlevel: 53)

      expect(target.version.to_s).to eq('3.2.2')
    end
  end

  describe "#evaluation_version" do
    it "keeps the MRI patchlevel separate from the evaluation version" do
      target = described_class.new(engine: :ruby, version: '1.8.7', patchlevel: 249)

      expect(target.evaluation_version.to_s).to eq('1.8.7')
      expect(target.effective_mri_version.to_s).to eq('1.8.7.249')
    end

    it "uses the JRuby engine version, not the Ruby compatibility version" do
      target = described_class.new(
        engine: :jruby, version: '2.5.0', patchlevel: 0,
        engine_version: '9.2.9.0'
      )

      expect(target.compatibility_version.to_s).to eq('2.5.0')
      expect(target.evaluation_version.to_s).to eq('9.2.9.0')
    end

    it "is nil for a JRuby target without an engine version" do
      target = described_class.new(engine: :jruby, version: '2.5.0')

      expect(target.evaluation_version).to be_nil
      expect(target.notes.map { |note| note[:code] }).to include(:missing_target_engine_version)
    end

    it "infers an unambiguous JRuby engine version and clears the compatibility version" do
      target = described_class.new(engine: :jruby, version: '9.2.9.0')

      expect(target.evaluation_version.to_s).to eq('9.2.9.0')
      expect(target.version).to be_nil
      expect(target).to be_inferred_engine_version
    end

    it "does not infer an ambiguous JRuby version" do
      target = described_class.new(engine: :jruby, version: '2.5.0')

      expect(target.engine_version).to be_nil
      expect(target).to_not be_inferred_engine_version
    end
  end

  describe "#notes" do
    it "reports an unparsable target version" do
      target = described_class.new(engine: :ruby, version: 'not-a-version')

      expect(target.version).to be_nil
      expect(target.notes).to include(hash_including(code: :invalid_target_version))
    end
  end
end

describe Bundler::Audit::Runtime::Declaration do
  describe ".from_lockfile_text" do
    it "returns nil when the lock file has no RUBY VERSION section" do
      text = "GEM\n  specs:\n"

      expect(described_class.from_lockfile_text(text)).to be_nil
    end

    it "parses an MRI declaration" do
      text = "RUBY VERSION\n   ruby 3.2.2p53\n\nGEM\n  specs:\n"

      declaration = described_class.from_lockfile_text(text)

      expect(declaration.engine).to eq('ruby')
      expect(declaration.version.to_s).to eq('3.2.2')
      expect(declaration.patchlevel).to eq(53)
    end

    it "parses a JRuby declaration with separate compatibility and engine versions" do
      text = "RUBY VERSION\n   ruby 2.5.0p0 (jruby 9.2.9.0)\n\nGEM\n  specs:\n"

      declaration = described_class.from_lockfile_text(text)

      expect(declaration.engine).to eq('jruby')
      expect(declaration.version.to_s).to eq('2.5.0')
      expect(declaration.patchlevel).to eq(0)
      expect(declaration.engine_version.to_s).to eq('9.2.9.0')
    end

    it "parses a bare engine declaration" do
      declaration = described_class.parse('jruby 9.2.9.0')

      expect(declaration.engine).to eq('jruby')
      expect(declaration.version).to be_nil
      expect(declaration.engine_version.to_s).to eq('9.2.9.0')
    end

    it "accepts a Bundler::RubyVersion object without losing the patchlevel" do
      ruby_version = Bundler::RubyVersion.new('2.5.0', '0', 'jruby', '9.2.9.0')

      declaration = described_class.from_lockfile(ruby_version)

      expect(declaration.engine).to eq('jruby')
      expect(declaration.patchlevel).to eq(0)
      expect(declaration.engine_version.to_s).to eq('9.2.9.0')
      expect(declaration.to_h[:raw]).to eq('ruby 2.5.0p0 (jruby 9.2.9.0)')
    end
  end

  describe "#differences" do
    it "reports engine differences" do
      declaration = described_class.parse('ruby 2.5.0p0')
      target      = Bundler::Audit::Runtime::Target.new(
        engine: :jruby, version: '2.5.0', patchlevel: 0, engine_version: '9.2.9.0'
      )

      expect(declaration.differences(target)).to include(hash_including(code: :engine_mismatch))
    end

    it "reports version, patchlevel, and engine version differences" do
      declaration = described_class.parse('ruby 2.5.0p0 (jruby 9.2.9.0)')
      target      = Bundler::Audit::Runtime::Target.new(
        engine: :jruby, version: '2.6.0', patchlevel: 1, engine_version: '9.3.0.0'
      )

      codes = declaration.differences(target).map { |note| note[:code] }

      expect(codes).to include(:version_mismatch, :patchlevel_mismatch, :engine_version_mismatch)
    end

    it "reports no differences for matching declarations" do
      declaration = described_class.parse('ruby 3.2.2p53')
      target      = Bundler::Audit::Runtime::Target.new(engine: :ruby, version: '3.2.2', patchlevel: 53)

      expect(declaration.differences(target)).to be_empty
    end
  end

  describe "#notes" do
    it "reports a missing patchlevel for MRI" do
      declaration = described_class.parse('ruby 3.2.2')

      expect(declaration.notes).to include(hash_including(code: :missing_declared_patchlevel))
    end

    it "reports an unknown engine" do
      declaration = described_class.parse('weirdruby 1.0.0')

      expect(declaration.engine).to eq('weirdruby')
      expect(declaration.notes).to include(hash_including(code: :declaration_unknown_engine))
    end
  end
end

describe Bundler::Audit::Runtime::Manifest do
  let(:manifests) { Fixtures.join('runtime','manifests') }

  describe ".load" do
    it "loads an MRI manifest" do
      manifest = described_class.load(File.join(manifests,'mri.yml'))

      expect(manifest.target.engine).to eq('ruby')
      expect(manifest.target.version.to_s).to eq('2.5.0')
      expect(manifest.target.patchlevel).to eq(0)
      expect(manifest.source).to eq('deploy/mri.yml')
    end

    it "loads a JRuby manifest with a separate engine version" do
      manifest = described_class.load(File.join(manifests,'jruby.yml'))

      expect(manifest.target.engine).to eq('jruby')
      expect(manifest.target.version.to_s).to eq('2.5.0')
      expect(manifest.target.engine_version.to_s).to eq('9.2.9.0')
    end

    it "raises for a missing file" do
      expect {
        described_class.load(File.join(manifests,'does_not_exist.yml'))
      }.to raise_error(Bundler::Audit::Runtime::Error, /does not exist/)
    end

    it "raises when the manifest has no ruby section" do
      expect {
        described_class.load(File.join(manifests,'no_ruby_section.yml'))
      }.to raise_error(Bundler::Audit::Runtime::Error, /no `ruby` section/)
    end

    it "raises when the manifest is not a Hash" do
      expect {
        described_class.load(File.join(manifests,'not_a_hash.yml'))
      }.to raise_error(Bundler::Audit::Runtime::Error, /not a Hash/)
    end
  end
end
