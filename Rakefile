require 'rubygems'

begin
  require 'bundler/setup'
rescue LoadError => e
  abort e.message
end

require 'rake'
require 'time'

require 'rubygems/tasks'
Gem::Tasks.new

require 'rspec/core/rake_task'
RSpec::Core::RakeTask.new

%w[secure unpatched_gems insecure_sources].each do |bundle|
  bundle_dir   = File.join('spec/bundle',bundle)
  gemfile      = File.join(bundle_dir,'Gemfile')
  gemfile_lock = File.join(bundle_dir,'Gemfile.lock')

  file gemfile_lock => gemfile do
    chdir(bundle_dir) do
      sh 'unset BUNDLE_BIN_PATH BUNDLE_GEMFILE RUBYOPT && bundle install --path ../../../vendor/bundle'
    end
  end

  desc "Generates the spec/bundler/*/Gemfile.lock files"
  task 'spec:bundle' => gemfile_lock
end

task :test    => :spec
task :default => :spec

require 'yard'
YARD::Rake::YardocTask.new
task :doc => :yard

require 'bundler/audit/task'
Bundler::Audit::Task.new

require 'bundler/audit/release_task'

namespace :bundle do
  namespace :audit do
    desc 'Release-pipeline scan with an auditable update, scan and delivery trail'
    task :release do
      task = Bundler::Audit::ReleaseTask.new(
        database:      ENV['BUNDLER_AUDIT_DB'],
        root:          ENV['BUNDLER_AUDIT_ROOT'] || Dir.pwd,
        gemfile_lock:  ENV['BUNDLER_AUDIT_GEMFILE_LOCK'] || 'Gemfile.lock',
        update:        ENV.key?('BUNDLER_AUDIT_UPDATE') ? ENV['BUNDLER_AUDIT_UPDATE'] != 'false' : :auto,
        ignore:        ENV['BUNDLER_AUDIT_IGNORE'] ? ENV['BUNDLER_AUDIT_IGNORE'].split(',') : [],
        format:        ENV['BUNDLER_AUDIT_FORMAT'] || 'json',
        output:        ENV['BUNDLER_AUDIT_OUTPUT'],
        manifest:      ENV['BUNDLER_AUDIT_MANIFEST']
      )

      exit(task.execute)
    end
  end
end

require 'rubocop/rake_task'
RuboCop::RakeTask.new
