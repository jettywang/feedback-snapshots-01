# Executes the four release-pipeline migration scenarios against the local
# lockfiles, advisory databases and output doubles built by setup_demo.rb.
#
#   ruby .feedback/demo/run_scenarios.rb
#
# Each scenario prints the ReleaseTask exit code and points at the report and
# reconciliation manifest that were delivered.
require 'json'
require 'fileutils'

ROOT = File.expand_path('../..', __dir__)
$LOAD_PATH.unshift(File.join(ROOT, 'lib'))
require 'bundler/audit/release_task'

DEMO   = File.join(ROOT, '.feedback', 'demo')
OUT    = File.join(DEMO, 'out')
DB     = File.join(DEMO, 'advisory-dbs')
LOCKS  = File.join(DEMO, 'locks')

FileUtils.rm_rf(OUT)
FileUtils.mkdir_p(OUT)

def scenario(number, title)
  puts "\n=== scenario #{number}: #{title} ==="
end

def show(out_dir, report_name, code)
  report   = File.join(out_dir, report_name)
  manifest = "#{report}.manifest.json"
  data     = JSON.parse(File.binread(manifest))

  puts "exit_code=#{code}"
  puts "update=#{data.dig('advisory_database', 'update', 'status')}"
  puts "identity_changed=#{data.dig('advisory_database', 'identity_changed')}"
  puts "commit_before=#{data.dig('advisory_database', 'before', 'commit')}"
  puts "commit_after=#{data.dig('advisory_database', 'after', 'commit')}"
  puts "vulnerable=#{data.dig('scan', 'vulnerable')} " \
       "findings=#{data.dig('scan', 'result_count')} " \
       "ids=#{data.dig('scan', 'advisory_ids').inspect}"
  puts "delivery=#{data.dig('delivery', 'mode')} " \
       "report_sha256=#{data.dig('delivery', 'sha256') || 'n/a'}"
  puts "report=#{report}"
  puts "manifest=#{manifest}"
end

# --- Scenario 1: normal scan, advisory found -------------------------------
scenario(1, 'normal scan with an advisory hit')
task = Bundler::Audit::ReleaseTask.new(
  database: File.join(DB, 'db-with-advisory'),
  root:     File.join(LOCKS, 'vulnerable'),
  update:   false,
  format:   'json',
  output:   File.join(OUT, 's1-report.json')
)
show(OUT, 's1-report.json', task.execute)

# --- Scenario 2: trusted offline DB, update unavailable, no findings --------
scenario(2, 'trusted offline database with no findings')
task = Bundler::Audit::ReleaseTask.new(
  database: File.join(DB, 'db-clean'),
  root:     File.join(LOCKS, 'secure'),
  update:   true,
  format:   'json',
  output:   File.join(OUT, 's2-report.json')
)
# The clean DB is a git repository without an origin: update fails, but the
# trusted local revision still backs a real, clean scan.
show(OUT, 's2-report.json', task.execute)

# --- Scenario 3: database identity changes during the update ----------------
scenario(3, 'database identity changes while updating')
task = Bundler::Audit::ReleaseTask.new(
  database: File.join(DB, 'db-updateable'),
  root:     File.join(LOCKS, 'vulnerable'),
  update:   true,
  format:   'json',
  output:   File.join(OUT, 's3-report.json')
)
show(OUT, 's3-report.json', task.execute)

# --- Scenario 4: previous report exists, new delivery fails -----------------
scenario(4, 'stale report present but the new report cannot be written')
previous = File.join(OUT, 's4-report.json')
File.binwrite(previous, '{"stale":"previous scan report"}')
stale_sha = Digest::SHA256.hexdigest(File.binread(previous))

# Output double: make the report path a directory so File.rename onto it
# fails. The pre-existing report must stay byte-identical and must not be
# cited as evidence for this run. The manifest goes to a separate writable
# path so the delivery failure itself is still auditable.
blocker = File.join(OUT, 's4-blocker')
FileUtils.mkdir_p(blocker)
manifest_path = File.join(OUT, 's4-manifest.json')
task = Bundler::Audit::ReleaseTask.new(
  database: File.join(DB, 'db-with-advisory'),
  root:     File.join(LOCKS, 'vulnerable'),
  update:   false,
  format:   'json',
  output:   blocker,
  manifest: manifest_path
)
code = task.execute
puts "exit_code=#{code}"
puts "stale_report_unchanged=#{::Digest::SHA256.hexdigest(File.binread(previous)) == stale_sha}"
puts "stale_report=#{previous}"
puts "blocker_path=#{blocker} (directory, rename cannot replace it)"
if File.exist?(manifest_path)
  data = JSON.parse(File.binread(manifest_path))
  puts "manifest=#{manifest_path}"
  puts "manifest_intended_path=#{data.dig('delivery', 'intended_path').inspect}"
  puts "manifest_report_delivered=#{data.dig('delivery', 'report_delivered')}"
  puts "manifest_vulnerable=#{data.dig('scan', 'vulnerable')} (recorded but never delivered as a report)"
else
  puts "manifest=#{manifest_path} (not written)"
end
