# Builds the fully local, offline fixtures for the four release-scan scenarios.
#
# The OS sandbox used during development forbids creating real `.git/`
# directories inside the workspace. Each advisory database therefore keeps its
# full git directory in $TMPDIR and exposes it through a `.git` symlink in the
# worktree. Bundler::Audit::Database follows the symlink, so `git?`,
# `commit_id`, `last_updated_at` and `update!` behave exactly like a normal
# cloned ruby-advisory-db.
#
# A shared bare repository in $TMPDIR acts as the offline `origin`:
#   * db-updateable starts one commit behind origin, so a successful
#     `git pull` moves HEAD and changes the database identity (scenario 3).
#   * db-no-origin has no remote, so `git pull` fails and the scan must keep
#     using the last trusted revision while recording the update failure.
#
#   ruby .feedback/demo/setup_demo.rb
require 'fileutils'
require 'tmpdir'

ROOT = File.expand_path('../..', __dir__)
DEMO = File.join(ROOT, '.feedback', 'demo')
GIT_HOME = File.join(Dir.tmpdir, 'bundle-audit-demo-git')
ORIGIN   = File.join(Dir.tmpdir, 'bundle-audit-demo-origin.git')

ADVISORY = <<~YAML
  ---
  gem: activerecord
  cve: 2013-0276
  url: https://example.com/CVE-2013-0276
  title: Demo advisory for activerecord 3.2.10
  date: 2013-02-15
  description: |
    Local offline advisory used by the release-task migration demo.
  cvss_v3: 7.5
  patched_versions:
    - ">= 3.2.11"
YAML

VULNERABLE_LOCK = File.read(File.join(ROOT, 'spec/bundle/unpatched_gems/Gemfile.lock'))
SECURE_LOCK     = File.read(File.join(ROOT, 'spec/bundle/secure/Gemfile.lock'))

def write(path, contents)
  FileUtils.mkdir_p(File.dirname(path))
  File.binwrite(path, contents)
end

def sh!(*command)
  system(*command) or raise "command failed: #{command.join(' ')}"
end

# Creates a worktree whose `.git` entry is a symlink to a real git directory
# kept under GIT_HOME.
def git_db(name, files)
  worktree = File.join(DEMO, 'advisory-dbs', name)
  gitdir   = File.join(GIT_HOME, name, '.git')
  staging  = File.join(GIT_HOME, name)
  FileUtils.rm_rf([worktree, staging])
  FileUtils.mkdir_p(staging)

  Dir.chdir(staging) do
    sh!('git', 'init', '--template=/dev/null', '--quiet', '--initial-branch=master')
    sh!('git', 'config', 'user.email', 'demo@example.invalid')
    sh!('git', 'config', 'user.name', 'Demo DB')
    File.binwrite(File.join(staging, 'README'),
                  "Local offline ruby-advisory-db stand-in (#{name}).\n")
    files.each do |relative, contents|
      path = File.join(staging, relative)
      FileUtils.mkdir_p(File.dirname(path))
      File.binwrite(path, contents)
    end
    sh!('git', 'add', '.')
    sh!('git', 'commit', '--quiet', '-m', "initial advisory db (#{name})")
  end

  FileUtils.mkdir_p(worktree)
  FileUtils.cp_r(File.join(staging, 'README'), File.join(worktree, 'README'))
  files.each_key do |relative|
    target = File.join(worktree, relative)
    FileUtils.mkdir_p(File.dirname(target))
    FileUtils.cp_r(File.join(staging, relative), target)
  end
  FileUtils.ln_s(gitdir, File.join(worktree, '.git'))
  worktree
end

# Bare shared origin, rebuilt from the finding database content.
FileUtils.rm_rf(ORIGIN)
FileUtils.mkdir_p(File.dirname(ORIGIN))
sh!('git', 'init', '--template=/dev/null', '--quiet', '--bare',
    '--initial-branch=master', ORIGIN)

db_with     = git_db('db-with-advisory',
                     'gems/activerecord/CVE-2013-0276.yml' => ADVISORY)
db_clean    = git_db('db-clean', {})
db_no_origin = git_db('db-no-origin',
                      'gems/activerecord/CVE-2013-0276.yml' => ADVISORY)
db_updateable = git_db('db-updateable',
                       'gems/activerecord/CVE-2013-0276.yml' => ADVISORY)

# Publish the finding database to origin, then add a newer commit that only
# the origin knows about.
sh!('git', '-C', db_updateable, 'remote', 'add', 'origin', ORIGIN)
sh!('git', '-C', db_updateable, 'push', '--quiet', '-u', 'origin', 'master')

staging = File.join(GIT_HOME, 'db-updateable')
File.binwrite(File.join(staging, 'gems/activerecord/CVE-2013-0277.yml'),
              ADVISORY.sub('2013-0276', '2013-0277'))
Dir.chdir(staging) do
  sh!('git', 'add', '.')
  sh!('git', 'commit', '--quiet', '-m', 'second advisory revision on origin')
  sh!('git', 'push', '--quiet', 'origin', 'master')
  # Roll the local checkout back so it starts one commit behind origin.
  sh!('git', 'reset', '--quiet', '--hard', 'HEAD~1')
end
# Keep the worktree in sync with the rolled-back local checkout.
FileUtils.rm_f(File.join(db_updateable, 'gems/activerecord/CVE-2013-0277.yml'))

write(File.join(DEMO, 'locks/vulnerable/Gemfile.lock'), VULNERABLE_LOCK)
write(File.join(DEMO, 'locks/secure/Gemfile.lock'), SECURE_LOCK)
FileUtils.mkdir_p(File.join(DEMO, 'out'))

def head(path)
  `git -C #{path} rev-parse HEAD`.chomp
end

puts "advisory db (finding):     #{db_with}  HEAD=#{head(db_with)}"
puts "advisory db (clean):       #{db_clean}  HEAD=#{head(db_clean)}"
puts "advisory db (no origin):   #{db_no_origin}  HEAD=#{head(db_no_origin)}"
puts "advisory db (updateable):  #{db_updateable}  HEAD=#{head(db_updateable)} (origin is one ahead)"
puts "vulnerable lock:           #{File.join(DEMO, 'locks/vulnerable/Gemfile.lock')}"
puts "secure lock:               #{File.join(DEMO, 'locks/secure/Gemfile.lock')}"
puts "output double dir:         #{File.join(DEMO, 'out')}"
