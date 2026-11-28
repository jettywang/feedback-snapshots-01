require 'spec_helper'
require 'bundler/audit/release_task'

require 'json'
require 'tmpdir'
require 'fileutils'

describe Bundler::Audit::ReleaseTask do
  let(:tmpdir) { Fixtures::TMP_DIR }

  let(:advisory_yaml) do
    <<~YAML
      ---
      gem: activerecord
      cve: 2013-0276
      url: https://example.com/CVE-2013-0276
      title: Demo advisory
      date: 2013-02-15
      patched_versions:
        - ">= 3.2.11"
    YAML
  end

  # The OS sandbox forbids real `.git/` directories inside the workspace, so
  # the git metadata lives under $TMPDIR and the worktree exposes it through a
  # `.git` symlink, exactly like the offline demo fixtures.
  def build_database(name, advisories:)
    token = "#{Process.pid}-#{rand(1..999_999)}"
    worktree = File.join(tmpdir, "release-db-#{name}-#{token}")
    staging  = File.join(Dir.tmpdir, "release-spec-git-#{name}-#{token}")
    FileUtils.rm_rf([worktree, staging])
    FileUtils.mkdir_p(staging)

    advisories.each do |filename, contents|
      path = File.join(staging, 'gems', 'activerecord', filename)
      FileUtils.mkdir_p(File.dirname(path))
      File.binwrite(path, contents)
    end

    Dir.chdir(staging) do
      raise 'git init failed' unless system('git', 'init', '--template=/dev/null',
                                            '--quiet', '--initial-branch=master')
      system('git', 'config', 'user.email', 'spec@example.invalid')
      system('git', 'config', 'user.name', 'Spec')
      system('git', 'add', '.')
      system('git', 'commit', '--quiet', '--allow-empty', '-m', 'db')
    end

    FileUtils.mkdir_p(worktree)
    FileUtils.cp_r(File.join(staging, 'gems'), worktree) if advisories.any?
    FileUtils.ln_s(File.join(staging, '.git'), File.join(worktree, '.git'))
    worktree
  end

  def copy_lockfile(fixture)
    dir = File.join(tmpdir, "release-lock-#{Process.pid}-#{rand(1..999_999)}")
    FileUtils.mkdir_p(dir)
    FileUtils.cp(File.join(Fixtures::ROOT, '..', 'bundle', fixture, 'Gemfile.lock'),
                 File.join(dir, 'Gemfile.lock'))
    dir
  end

  let(:vulnerable_root) { copy_lockfile('unpatched_gems') }
  let(:secure_root)     { copy_lockfile('secure') }

  def task_for(database:, root:, **overrides)
    defaults = {
      database: database,
      root: root,
      update: false,
      format: 'json',
      stdout: StringIO.new,
      stderr: StringIO.new
    }
    described_class.new(defaults.merge(overrides))
  end

  describe '#execute' do
    context 'when the scan finds an advisory' do
      it 'exits vulnerable and delivers a report plus manifest' do
        database = build_database('finding', advisories: {
          'CVE-2013-0276.yml' => advisory_yaml
        })
        report = File.join(tmpdir, "report-#{rand(1..9999)}.json")
        manifest = "#{report}.manifest.json"
        task = task_for(database: database, root: vulnerable_root,
                        output: report, manifest: manifest)

        expect(task.execute).to eq(described_class::EXIT_VULNERABLE)

        data = JSON.parse(File.binread(manifest))
        expect(data['scan']['vulnerable']).to be(true)
        expect(data['scan']['advisory_ids']).to include('CVE-2013-0276')
        expect(data['advisory_database']['identity_changed']).to be(false)
        expect(data['delivery']['sha256']).to eq(
          Digest::SHA256.hexdigest(File.binread(report))
        )
      end
    end

    context 'when the trusted database has no matching advisory' do
      it 'exits cleanly with an empty findings list' do
        database = build_database('clean', advisories: {})
        report = File.join(tmpdir, "clean-#{rand(1..9999)}.json")
        task = task_for(database: database, root: secure_root, output: report)

        expect(task.execute).to eq(0)

        data = JSON.parse(File.binread("#{report}.manifest.json"))
        expect(data['scan']['vulnerable']).to be(false)
        expect(data['scan']['result_count']).to eq(0)
      end
    end

    context 'when an update is requested but fails offline' do
      it 'keeps scanning the trusted revision and records the failure' do
        database = build_database('offline', advisories: {
          'CVE-2013-0276.yml' => advisory_yaml
        })
        original_commit = `git -C #{database} rev-parse HEAD`.chomp
        report = File.join(tmpdir, "offline-#{rand(1..9999)}.json")
        task = task_for(database: database, root: vulnerable_root,
                        update: true, output: report)

        expect(task.execute).to eq(described_class::EXIT_VULNERABLE)

        data = JSON.parse(File.binread("#{report}.manifest.json"))
        expect(data['advisory_database']['update']['status']).to eq('update_failed')
        expect(data['advisory_database']['before']['commit']).to eq(original_commit)
        expect(data['advisory_database']['after']['commit']).to eq(original_commit)
        expect(data['advisory_database']['identity_changed']).to be(false)
      end
    end

    context 'when the database identity changes during an update' do
      it 'records both revisions and scans the new one' do
        database = build_database('moving', advisories: {
          'CVE-2013-0276.yml' => advisory_yaml
        })
        before_commit = `git -C #{database} rev-parse HEAD`.chomp

        # Publish the current revision to a local bare origin.
        origin = File.join(Dir.tmpdir, "release-origin-#{Process.pid}-#{rand(1..9999)}.git")
        FileUtils.rm_rf(origin)
        raise 'bare clone failed' unless system('git', 'clone', '--template=/dev/null',
                                                '--quiet', '--bare', database, origin)

        # A second advisory revision that only origin knows about.
        gitdir = File.readlink(File.join(database, '.git'))
        staging = File.dirname(gitdir)
        File.binwrite(File.join(staging, 'gems/activerecord/CVE-2013-0277.yml'),
                      advisory_yaml.gsub('2013-0276', '2013-0277'))
        new_commit = nil
        Dir.chdir(staging) do
          system('git', 'add', '.')
          system('git', 'commit', '--quiet', '-m', 'second revision')
          new_commit = `git rev-parse HEAD`.chomp
          system('git', 'push', '--quiet', origin, 'master')
          # Roll the local checkout back so it starts one commit behind origin.
          system('git', 'reset', '--quiet', '--hard', before_commit)
          system('git', 'remote', 'add', 'origin', origin)
        end
        # Keep the symlinked worktree aligned with the rolled-back checkout.
        FileUtils.rm_f(File.join(database, 'gems/activerecord/CVE-2013-0277.yml'))

        report = File.join(tmpdir, "moving-#{rand(1..9999)}.json")
        task = task_for(database: database, root: vulnerable_root,
                        update: true, output: report)

        expect(task.execute).to eq(described_class::EXIT_VULNERABLE)

        data = JSON.parse(File.binread("#{report}.manifest.json"))
        expect(data['advisory_database']['update']['status']).to eq('updated')
        expect(data['advisory_database']['before']['commit']).to eq(before_commit)
        expect(data['advisory_database']['after']['commit']).to eq(new_commit)
        expect(data['advisory_database']['identity_changed']).to be(true)
        expect(data['scan']['advisory_ids']).to match_array(
          %w[CVE-2013-0276 CVE-2013-0277]
        )
      end
    end

    context 'when the new report cannot be written' do
      it 'exits inconclusive and leaves the previous report untouched' do
        database = build_database('delivery', advisories: {
          'CVE-2013-0276.yml' => advisory_yaml
        })
        previous = File.join(tmpdir, "previous-#{rand(1..9999)}.json")
        File.binwrite(previous, '{"stale":true}')
        previous_sha = Digest::SHA256.hexdigest(File.binread(previous))

        blocker = File.join(tmpdir, "blocker-#{rand(1..9999)}")
        FileUtils.mkdir_p(blocker)
        manifest = File.join(tmpdir, "blocked-manifest-#{rand(1..9999)}.json")
        task = task_for(database: database, root: vulnerable_root,
                        output: blocker, manifest: manifest)

        expect(task.execute).to eq(described_class::EXIT_INCONCLUSIVE)
        expect(Digest::SHA256.hexdigest(File.binread(previous))).to eq(previous_sha)

        data = JSON.parse(File.binread(manifest))
        expect(data['delivery']['report_delivered']).to be(false)
        expect(data['delivery']['status']).to eq('delivery_failed')
        expect(data['delivery']['intended_path']).to eq(File.expand_path(blocker))
      end
    end
  end

  describe '#run' do
    it 'raises DatabaseUnavailable when the database is missing' do
      task = task_for(database: File.join(tmpdir, 'nope'),
                      root: secure_root, update: false)

      expect { task.run }.to raise_error(described_class::DatabaseUnavailable)
    end

    it 'raises LockfileUnavailable when the lockfile is absent' do
      database = build_database('nolock', advisories: {})
      empty_root = File.join(tmpdir, "empty-root-#{rand(1..9999)}")
      FileUtils.mkdir_p(empty_root)
      task = task_for(database: database, root: empty_root)

      expect { task.run }.to raise_error(described_class::LockfileUnavailable)
    end

    it 'raises UnknownFormat for an unregistered format' do
      database = build_database('badfmt', advisories: {})
      task = task_for(database: database, root: secure_root, format: 'nope')

      expect { task.run }.to raise_error(described_class::UnknownFormat)
    end
  end
end
