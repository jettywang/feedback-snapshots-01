require 'spec_helper'
require 'bundler/audit/cli'
require 'tmpdir'

describe "bundle-audit check runtime options" do
  let(:database) { Bundler::Audit::Database.new('spec/fixtures/runtime/database') }
  let(:bundle)   { 'spec/bundle/runtime_jruby' }

  around do |example|
    Dir.mktmpdir('bundler-audit-runtime') do |directory|
      @output_dir = directory
      example.run
    end
  end

  before do
    allow(Bundler::Audit::Database).to receive(:new).and_return(database)
  end

  def run_cli(dir=bundle,options={})
    output_path = File.join(@output_dir,'report.txt')

    options = {
      format:           'text',
      database:         'spec/fixtures/runtime/database',
      config:           '.bundler-audit.yml',
      gemfile_lock:     'Gemfile.lock',
      output:           output_path
    }.merge(options)

    cli = Bundler::Audit::CLI.new([],options)

    status = nil

    begin
      cli.check(dir)
    rescue SystemExit => exception
      status = exception.status
    end

    [File.exist?(output_path) ? File.read(output_path) : '',status]
  end

  it "does not use the scanning host's Ruby as the target" do
    output, _status = run_cli

    expect(output).to_not include('Ruby Runtime')
  end

  it "uses the explicit deployment manifest" do
    output, status = run_cli(bundle,
      runtime_manifest:   'spec/fixtures/runtime/manifests/jruby.yml',
      runtime_advisories: 'spec/fixtures/runtime/database'
    )

    expect(output).to include('Target: jruby 9.2.9.0')
    expect(output).to include('Declared: ruby 2.5.0p0 (jruby 9.2.9.0)')
    expect(status).to eq(1)
  end

  it "reports a declaration mismatch with the deployment manifest" do
    output, _status = run_cli('spec/bundle/runtime_mismatch',
      runtime_manifest:   'spec/fixtures/runtime/manifests/mri.yml',
      runtime_advisories: 'spec/fixtures/runtime/database'
    )

    expect(output).to include('Target: ruby 2.5.0p0')
    expect(output).to include('Declared: ruby 3.2.2p53')
  end

  it "does not fall back to the lock file declaration when the manifest is absent" do
    output, status = run_cli('spec/bundle/runtime_jruby',
      runtime_advisories: 'spec/fixtures/runtime/database'
    )

    expect(output).to include('Status: unknown')
    expect(status).to be_nil
  end

  it "exits with 1 for an inconclusive runtime audit with --runtime-strict" do
    _output, status = run_cli('spec/bundle/runtime_jruby',
      runtime_advisories: 'spec/fixtures/runtime/database',
      runtime_strict:     true
    )

    expect(status).to eq(1)
  end

  it "rejects --runtime-strict without a deployment runtime" do
    _output, status = run_cli(bundle, runtime_strict: true)

    expect(status).to eq(1)
  end
end
