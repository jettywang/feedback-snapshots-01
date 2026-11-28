#
# Copyright (c) 2013-2026 Hal Brodigan (postmodern.mod3 at gmail.com)
#
# bundler-audit is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# bundler-audit is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with bundler-audit.  If not, see <https://www.gnu.org/licenses/>.
#

require 'digest'
require 'fileutils'
require 'json'
require 'stringio'
require 'tempfile'
require 'time'

require 'bundler/audit/database'
require 'bundler/audit/scanner'
require 'bundler/audit/cli/formats'

module Bundler
  module Audit
    #
    # A release-pipeline oriented entry point which keeps the advisory
    # database update, the scan and the report delivery as separate,
    # individually auditable steps.
    #
    # Unlike the plain `bundle-audit check --update` command, an update
    # failure never downgrades into a "no vulnerabilities found" result:
    # the scan continues against the last trusted database revision while
    # the failure is recorded in the reconciliation manifest, and any
    # problem while writing the new report aborts the run before an
    # existing report is touched.
    #
    class ReleaseTask

      # Base class for all release task failures.
      class Failure < RuntimeError
      end

      # Raised when no usable advisory database is available.
      class DatabaseUnavailable < Failure
      end

      # Raised when the lockfile cannot be found or read.
      class LockfileUnavailable < Failure
      end

      # Raised when the requested report format is unknown.
      class UnknownFormat < Failure
      end

      # Raised when a report or manifest cannot be completely written.
      class DeliveryFailed < Failure
      end

      # Exit status used when the scan itself found vulnerabilities.
      EXIT_VULNERABLE = 1

      # Exit status used when an update, delivery or input problem made
      # the run inconclusive. Distinct from {EXIT_VULNERABLE} so that an
      # infrastructure failure is never read as a clean or dirty scan.
      EXIT_INCONCLUSIVE = 3

      # @return [String] path to the advisory database directory
      attr_reader :database_path

      # @return [String] project directory containing the lockfile
      attr_reader :root

      # @return [String] name of the lockfile within {#root}
      attr_reader :gemfile_lock

      # @return [String] bundler-audit configuration file name
      attr_reader :config

      # @return [:auto, true, false, nil] update mode
      #
      # `:auto` updates when the database is a git repository and skips
      # otherwise, `true` requires an update, `false`/`nil` never updates.
      attr_reader :update

      # @return [Array<String>] advisory identifiers to ignore
      attr_reader :ignore

      # @return [String] report format (`json`, `text`, `junit`, ...)
      attr_reader :format

      # @return [String, nil] destination path of the report
      attr_reader :output

      # @return [String, nil] destination path of the manifest
      attr_reader :manifest_path

      # @return [IO] stream used for human-readable progress messages
      attr_reader :stdout

      # @return [IO] stream used for warning messages
      attr_reader :stderr

      #
      # @param [Hash] options
      #   Task configuration.
      #
      # @option options [String] :database
      #   Path to the advisory database. Defaults to
      #   {Database::DEFAULT_PATH}.
      #
      # @option options [String] :root
      #   Project directory. Defaults to the current directory.
      #
      # @option options [String] :gemfile_lock
      #   Lockfile name within `:root`. Defaults to `Gemfile.lock`.
      #
      # @option options [String] :config
      #   bundler-audit config file name. Defaults to `.bundler-audit.yml`.
      #
      # @option options [Symbol, Boolean, nil] :update
      #   Update mode, see {#update}.
      #
      # @option options [Array<String>] :ignore
      #   Advisory identifiers to ignore.
      #
      # @option options [String] :format
      #   Report format. Defaults to `json`.
      #
      # @option options [String] :output
      #   Report destination path. When omitted the report is rendered to
      #   `:stdout` and no report artifact is delivered.
      #
      # @option options [String] :manifest
      #   Manifest destination path. Defaults to `<output>.manifest.json`
      #   next to `:output`, or `audit-manifest.json` in `:root` when the
      #   report is streamed.
      #
      def initialize(options={})
        @database_path = options.fetch(:database, Database::DEFAULT_PATH)
        @root          = File.expand_path(options.fetch(:root, Dir.pwd))
        @gemfile_lock  = options.fetch(:gemfile_lock, 'Gemfile.lock')
        @config        = options.fetch(:config, '.bundler-audit.yml')
        @update        = options.fetch(:update, :auto)
        @ignore        = options.fetch(:ignore, [])
        @format        = options.fetch(:format, 'json')
        @output        = options[:output]
        @manifest_path = options[:manifest] || default_manifest_path
        @stdout        = options.fetch(:stdout, $stdout)
        @stderr        = options.fetch(:stderr, $stderr)
      end

      #
      # Performs the full release scan and returns the reconciliation
      # manifest.
      #
      # @return [Hash{Symbol => Object}]
      #   The manifest that was (or will be) delivered.
      #
      # @raise [DatabaseUnavailable, LockfileUnavailable, UnknownFormat,
      #         DeliveryFailed]
      #   The run could not produce a trustworthy report.
      #
      def run
        ensure_database!
        before_identity = database_identity

        update_record = perform_update
        after_identity = database_identity

        lockfile_record = fingerprint_lockfile
        report, scan_record = perform_scan

        delivery_record, delivery_failure = attempt_delivery(report)

        manifest = build_manifest(
          before_identity:   before_identity,
          update:            update_record,
          after_identity:    after_identity,
          lockfile:          lockfile_record,
          scan:              scan_record,
          delivery:          delivery_record
        )

        write_manifest(manifest)

        raise(delivery_failure) if delivery_failure

        manifest
      end

      #
      # Runs {#run} and maps the outcome onto the release pipeline exit
      # contract.
      #
      # @return [Integer]
      #   `0` for a clean scan, {EXIT_VULNERABLE} for findings and
      #   {EXIT_INCONCLUSIVE} for an inconclusive run.
      #
      def execute
        manifest = run

        if manifest[:scan][:vulnerable]
          EXIT_VULNERABLE
        else
          0
        end
      rescue Failure => error
        @stderr.puts("bundler-audit release scan inconclusive: #{error.message}")
        EXIT_INCONCLUSIVE
      end

      protected

      #
      # @return [String]
      #
      def default_manifest_path
        if @output
          "#{@output}.manifest.json"
        else
          File.join(@root, 'audit-manifest.json')
        end
      end

      #
      # Ensures a usable advisory database exists before anything else.
      #
      # @raise [DatabaseUnavailable]
      #
      def ensure_database!
        unless Database.exists?(@database_path)
          raise(DatabaseUnavailable,
                "advisory database not found at #{@database_path.inspect}")
        end
      end

      #
      # Captures the durable identity of the advisory database.
      #
      # @return [Hash{Symbol => Object}]
      #
      def database_identity
        database = Database.new(@database_path)

        {
          path:             @database_path,
          git:              database.git?,
          commit:           database.commit_id,
          last_updated_at:  database.last_updated_at && database.last_updated_at.utc.iso8601,
          advisory_count:   database.size
        }
      end

      #
      # Performs the optional update as an isolated step.
      #
      # @return [Hash{Symbol => Object}]
      #   A record describing what happened, including any failure.
      #
      def perform_update
        database = Database.new(@database_path)

        case @update
        when false, nil
          return { requested: false, performed: false, status: 'skipped' }
        when true
          unless database.git?
            raise(DatabaseUnavailable,
                  "update requested but #{@database_path.inspect} is not a git repository")
          end
        when :auto
          unless database.git?
            return { requested: true, performed: false, status: 'skipped',
                     reason: 'database is not a git repository' }
          end
        end

        begin
          update_database
          { requested: true, performed: true, status: 'updated' }
        rescue Database::UpdateFailed => error
          # The scan still runs against the revision recorded in
          # before/after identity; the failure must not look like a clean
          # bill of health.
          { requested: true, performed: false, status: 'update_failed',
            error: error.message }
        end
      end

      #
      # Runs the advisory database `git pull` with both file descriptors
      # redirected, so a failing or verbose git command never writes to the
      # pipeline's stdout/stderr. Mirrors {Database#update!} but raises
      # {Database::UpdateFailed} with the captured diagnostics on failure.
      #
      # @raise [Database::UpdateFailed]
      #
      def update_database
        diagnostics = nil
        success = Dir.chdir(@database_path) do
          ::Tempfile.create('bundler-audit-git') do |capture|
            pid = spawn('git', 'pull', '--quiet', 'origin', 'master',
                        out: capture.path, err: capture.path)
            _, process_status = Process.wait2(pid)
            capture.rewind
            diagnostics = capture.read
            process_status.success?
          end
        end

        unless success
          raise(Database::UpdateFailed,
                "failed to update #{@database_path.inspect}: " \
                "#{diagnostics.strip}")
        end

        true
      end

      #
      # @return [Hash{Symbol => Object}]
      #
      # @raise [LockfileUnavailable]
      #
      def fingerprint_lockfile
        path = File.join(@root, @gemfile_lock)

        unless File.file?(path)
          raise(LockfileUnavailable,
                "could not find #{@gemfile_lock.inspect} in #{@root.inspect}")
        end

        contents = File.binread(path)

        {
          path:      path,
          size:      contents.bytesize,
          sha256:    ::Digest::SHA256.hexdigest(contents),
          mtime_utc: File.mtime(path).utc.iso8601
        }
      rescue SystemCallError => error
        raise(LockfileUnavailable, "cannot read #{path.inspect}: #{error.message}")
      end

      #
      # @return [(Report, Hash{Symbol => Object})]
      #
      def perform_scan
        database = Database.new(@database_path)

        scanner =
          begin
            Scanner.new(@root, @gemfile_lock, database, @config)
          rescue Bundler::GemfileLockNotFound => error
            raise(LockfileUnavailable, error.message)
          end

        report = scanner.report(ignore: @ignore)

        [
          report,
          {
            vulnerable:        report.vulnerable?,
            result_count:      report.results.length,
            unpatched_gems:    report.unpatched_gems.length,
            insecure_sources:  report.insecure_sources.length,
            advisory_ids:      report.advisories.map(&:id).sort,
            report_version:    report.version,
            generated_at_utc:  report.created_at.utc.iso8601
          }
        ]
      end

      #
      # Delivers the report and converts a delivery failure into a manifest
      # record instead of dropping the whole audit trail. The failure is
      # re-raised by {#run} after the manifest has been written, so the run
      # still ends inconclusive and any previously delivered report stays
      # untouched.
      #
      # @return [(Hash{Symbol => Object}, DeliveryFailed, nil)]
      #
      def attempt_delivery(report)
        [deliver(report), nil]
      rescue DeliveryFailed => error
        [
          {
            mode:             'failed',
            intended_path:    @output ? File.expand_path(@output) : nil,
            status:           'delivery_failed',
            error:            error.message,
            report_delivered: false
          },
          error
        ]
      end

      #
      # Renders and atomically delivers the report.
      #
      # @return [Hash{Symbol => Object}]
      #
      # @raise [UnknownFormat, DeliveryFailed]
      #
      def deliver(report)
        renderer = load_renderer
        rendered = render_report(renderer, report)

        unless @output
          stdout.write(rendered)
          stdout.write("\n") unless rendered.end_with?("\n")
          return { mode: 'stdout', bytes: rendered.bytesize }
        end

        atomic_write(@output, rendered)

        {
          mode:     'file',
          path:     File.expand_path(@output),
          bytes:    rendered.bytesize,
          sha256:   ::Digest::SHA256.hexdigest(rendered)
        }
      end

      #
      # @return [Object]
      #
      # @raise [UnknownFormat]
      #
      def load_renderer
        CLI::Formats.load(@format)
      rescue CLI::Formats::FormatNotFound => error
        raise(UnknownFormat, error.message)
      end

      #
      # Formats are Thor modules relying on `say`/`options`; use a tiny
      # stand-alone renderer host so the release task stays decoupled from
      # the CLI.
      #
      # @return [String]
      #
      def render_report(renderer, report)
        host = RendererHost.new(renderer)
        io   = ::StringIO.new

        host.print_report(report, io)
        io.string
      end

      #
      # Writes the manifest atomically so consumers never observe a
      # half-written artifact.
      #
      # @raise [DeliveryFailed]
      #
      def write_manifest(manifest)
        rendered = ::JSON.pretty_generate(manifest)

        atomic_write(@manifest_path, rendered)
      rescue SystemCallError => error
        raise(DeliveryFailed,
              "failed to write manifest #{@manifest_path.inspect}: #{error.message}")
      end

      #
      # Writes `contents` to `path` via a same-directory temp file and an
      # atomic rename. An existing file is left untouched on failure.
      #
      # @raise [DeliveryFailed]
      #
      def atomic_write(path, contents)
        destination = File.expand_path(path)
        ::FileUtils.mkdir_p(File.dirname(destination))

        temp = ::Tempfile.new(File.basename(path), File.dirname(destination))

        begin
          temp.binmode
          temp.write(contents)
          temp.flush
          temp.fsync
          temp.close
          File.chmod(0o644, temp.path)
          File.rename(temp.path, destination)
        rescue SystemCallError => error
          File.unlink(temp.path) if File.exist?(temp.path)
          raise(DeliveryFailed,
                "failed to write #{path.inspect}: #{error.message}")
        ensure
          temp.close unless temp.closed?
        end
      end

      #
      # @return [Hash{Symbol => Object}]
      #
      def build_manifest(before_identity:, update:, after_identity:,
                         lockfile:, scan:, delivery:)
        {
          schema:           'bundler-audit.release-manifest/v1',
          generated_at_utc: ::Time.now.utc.iso8601,
          tool:             { name: 'bundler-audit', version: VERSION },
          advisory_database: {
            before:        before_identity,
            update:        update,
            after:         after_identity,
            identity_changed: before_identity[:commit] != after_identity[:commit]
          },
          lockfile:         lockfile,
          scan:             scan,
          delivery:         delivery.merge(
            manifest_path: File.expand_path(@manifest_path)
          )
        }
      end

      #
      # Minimal host for the Thor-based report format modules. The text and
      # junit formats write through Thor's `say`, which itself writes to
      # `$stdout`; the formats temporarily rebind `$stdout` to the target
      # IO, so this host only needs to provide the Thor surface they call.
      #
      class RendererHost
        # Minimal stand-in for Thor's option accessor.
        class Options
          def quiet?
            true
          end

          def verbose?
            false
          end
        end

        def initialize(format_module)
          @options = Options.new
          extend(format_module)
        end

        # Formats call `options.quiet?` / `options.verbose?`.
        attr_reader :options

        # Thor `say` compatibility used by the text/junit formats.
        def say(message=nil, *color)
          $stdout.puts(message)
        end

        # Thor `print_wrapped` compatibility (only reached in verbose mode,
        # which the release renderer never enables).
        def print_wrapped(message, options={})
          $stdout.puts(message)
        end
      end

    end
  end
end
