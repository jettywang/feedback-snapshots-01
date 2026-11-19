require 'set'

# Brakeman::ScanCoverage records how much of the application was actually
# analyzed during a scan.
#
# A scan can finish with zero warnings for two very different reasons:
#
#   * every in-scope file was analyzed and no check found anything, or
#   * parts of the application were never analyzed (parse failures, excluded
#     paths, template handlers Brakeman cannot compile, checks turned off).
#
# This class collects the second category in one place so machine readable
# reports, human readable summaries, and exit code decisions all rely on the
# same completeness contract instead of treating "zero warnings" as "clean".
class Brakeman::ScanCoverage
  # Reasons a single input was not fully analyzed.
  PARSE_ERROR = :parse_error
  PROCESSING_ERROR = :processing_error
  EXCLUDED_PATH = :excluded_path
  UNSUPPORTED_TEMPLATE = :unsupported_template
  DISABLED_CHECK = :disabled_check

  attr_reader :errors, :excluded_paths, :unsupported_templates, :disabled_checks,
              :scanned_ruby_paths, :scanned_template_paths, :options

  def initialize(options = {})
    @options = options
    @errors = []
    @excluded_paths = Set.new
    @unsupported_templates = Set.new
    @disabled_checks = Set.new
    @scanned_ruby_paths = Set.new
    @scanned_template_paths = Set.new
  end

  # Record the file lists the scanner actually attempted to parse. These are
  # the real scan inputs after path filtering, not the whole project tree.
  def record_scan_inputs(ruby_paths, template_paths)
    @scanned_ruby_paths.merge(Array(ruby_paths).map { |p| relative(p) })
    @scanned_template_paths.merge(Array(template_paths).map { |p| relative(p) })
    self
  end

  # Record a parse or processing failure. The entry keeps its original error
  # structure (exception/error/backtrace) so existing error reports stay
  # intact, plus the affected file and a coverage reason.
  def record_error(error_entry)
    @errors << error_entry
    self
  end

  def record_errors(error_entries)
    error_entries.each { |e| record_error e }
    self
  end

  # Replace the whole error set. Used when a tracker re-syncs coverage with
  # its authoritative error list (e.g. after a rescan).
  def replace_errors(error_entries)
    @errors.replace(Array(error_entries))
    self
  end

  def record_excluded_path(path, reason)
    @excluded_paths << {
      :reason => EXCLUDED_PATH,
      :path => relative(path),
      :detail => reason
    }
    self
  end

  def record_unsupported_template(path, handler_or_message)
    message = handler_or_message.to_s
    @unsupported_templates << {
      :reason => UNSUPPORTED_TEMPLATE,
      :path => relative(path),
      :handler => message
    }
    self
  end

  # Drop coverage limitations attached to a rescanned path.
  def clear_path(path)
    target = relative(path)
    @unsupported_templates.delete_if { |entry| entry[:path] == target }
    @excluded_paths.delete_if { |entry| entry[:path] == target }
    self
  end

  def record_disabled_check(check_name, reason)
    @disabled_checks << {
      :reason => DISABLED_CHECK,
      :check => check_name.to_s,
      :detail => reason
    }
    self
  end

  # A scan is only complete when there is no gap between what the caller asked
  # to scan and what Brakeman was able to analyze.
  def complete?
    @errors.empty? &&
      @excluded_paths.empty? &&
      @unsupported_templates.empty? &&
      @disabled_checks.empty?
  end

  def incomplete?
    !complete?
  end

  # Grouped reasons for incompleteness. Empty categories are omitted so a
  # complete scan serializes to an empty limitations hash.
  def limitations
    limitations = {}
    limitations[:errors] = @errors.dup unless @errors.empty?
    limitations[:excluded_paths] = @excluded_paths.to_a unless @excluded_paths.empty?
    limitations[:unsupported_templates] = @unsupported_templates.to_a unless @unsupported_templates.empty?
    limitations[:disabled_checks] = @disabled_checks.to_a unless @disabled_checks.empty?
    limitations
  end

  def to_h
    {
      :complete => complete?,
      :scanned_ruby_files => @scanned_ruby_paths.length,
      :scanned_template_files => @scanned_template_paths.length,
      :limitations => limitations
    }
  end

  private

  def relative(path)
    return nil if path.nil?

    path = path.relative if path.respond_to?(:relative)
    path.to_s
  end
end
