require 'thread'
require 'brakeman/differ'

#Collects up results from running different checks.
#
#Checks can be added with +Check.add(check_class)+
#
#All .rb files in checks/ will be loaded.
class Brakeman::Checks
  @checks = []
  @optional_checks = []

  attr_reader :warnings, :controller_warnings, :model_warnings, :template_warnings, :checks_run

  #Add a check. This will call +_klass_.new+ when running tests
  def self.add klass
    @checks << klass unless @checks.include? klass
  end

  #Add an optional check
  def self.add_optional klass
    @optional_checks << klass unless @checks.include? klass
  end

  def self.checks
    @checks + @optional_checks
  end

  def self.optional_checks
    @optional_checks
  end

  def self.initialize_checks check_directory = ""
    #Load all files in check_directory
    Dir.glob(File.join(check_directory, "*.rb")).sort.each do |f|
      require f
    end
  end

  def self.missing_checks check_args
    check_args = check_args.to_a.map(&:to_s).to_set

    if check_args == Set['CheckNone']
      return []
    else
      loaded = self.checks.map { |name| name.to_s.gsub('Brakeman::', '') }.to_set
      missing = check_args - loaded

      unless missing.empty?
        return missing
      end
    end

    []
  end

  #No need to use this directly.
  def initialize options = { }
    if options[:min_confidence]
      @min_confidence = options[:min_confidence]
    else
      @min_confidence = Brakeman.get_defaults[:min_confidence]
    end

    @warnings = []
    @template_warnings = []
    @model_warnings = []
    @controller_warnings = []
    @checks_run = []
    @suppressed_sinks = []
  end

  #Add Warning to list of warnings to report.
  #Warnings are split into four different arrays
  #for template, controller, model, and generic warnings.
  #
  #Will not add warnings which are below the minimum confidence level.
  def add_warning warning
    existing = find_existing_sink warning

    if existing
      existing.merge_sink! warning
      # A merged sink becomes visible if any discovery passed the confidence
      # filter, even when the first discovery did not.
      promote_sink(existing) if warning.confidence <= @min_confidence
      return existing
    end

    if warning.confidence > @min_confidence
      @suppressed_sinks << warning
    else
      case warning.warning_set
      when :template
        @template_warnings << warning
      when :warning
        @warnings << warning
      when :controller
        @controller_warnings << warning
      when :model
        @model_warnings << warning
      else
        raise "Unknown warning: #{warning.warning_set}"
      end
    end
  end

  #Return a hash of arrays of new and fixed warnings
  #
  #    diff = checks.diff old_checks
  #    diff[:fixed]  # [...]
  #    diff[:new]    # [...]
  def diff other_checks
    my_warnings = self.all_warnings
    other_warnings = other_checks.all_warnings
    Brakeman::Differ.new(my_warnings, other_warnings).diff
  end

  #Return an array of all warnings found.
  def all_warnings
    @warnings + @template_warnings + @controller_warnings + @model_warnings
  end

  # Warnings removed by the confidence filter still count as discovered sinks
  # for merging (so a reportable path is not duplicated by a weak path).
  def all_discovered_warnings
    all_warnings + @suppressed_sinks
  end

  # Assign stable occurrence numbers and disambiguated fingerprints.
  #
  # * `occurrence` is line-independent, so a formatting move keeps the same id.
  # * Members of a legacy-fingerprint collision all receive a suffix, so no
  #   single old exemption can attach to an arbitrarily chosen call.
  #
  # Ordering is by source position, which keeps ids stable across runs.
  def finalize_warnings
    # Only reported warnings participate in identity numbering.  Suppressed
    # discoveries are used for merging but must not shift the occurrence of a
    # visible warning when confidence thresholds change.
    warnings = all_warnings

    # Occurrence is line-independent: a formatting move keeps the same ordinal,
    # while two real instances of the same structure get different ordinals.
    warnings.group_by(&:sink_move_key).each_value do |group|
      group.sort_by { |w| [w.line || 0, w.file.to_s, w.method.to_s, w.code.to_s] }.each_with_index do |warning, index|
        warning.occurrence = index
      end
    end

    # The legacy fingerprint cannot distinguish identical calls on different
    # lines.  Disambiguate every member of a colliding group, including the
    # first, so an old exemption cannot silently attach to a newly added call.
    warnings.group_by(&:legacy_fingerprint).each_value do |group|
      next if group.length < 2

      group.sort_by { |w| [w.line || 0, w.method.to_s, w.file.to_s, w.code.to_s] }.each_with_index do |warning, index|
        warning.collision_suffix = index
      end
    end

    all_warnings
  end

  #Run all the checks on the given Tracker.
  #Returns a new instance of Checks with the results.
  def self.run_checks(tracker)
    checks = self.checks_to_run(tracker)
    check_runner = self.new :min_confidence => tracker.options[:min_confidence]
    self.actually_run_checks(checks, check_runner, tracker)
  end

  def self.actually_run_checks(checks, check_runner, tracker)
    threads = [] # Results for parallel
    results = [] # Results for sequential
    parallel = tracker.options[:parallel_checks]
    error_mutex = Mutex.new

    message = if parallel
      "Running #{checks.length} checks in parallel"
    else
      "Running #{checks.length} checks"
    end

    Brakeman.process_step(message) do
      checks.each do |c|
        check_name = get_check_name c
        Brakeman.debug " - #{check_name}"

        if parallel
          threads << Thread.new do
            self.run_a_check(c, error_mutex, tracker)
          end
        else
          results << self.run_a_check(c, error_mutex, tracker)
        end

        #Maintain list of which checks were run
        #mainly for reporting purposes
        check_runner.checks_run << check_name[5..-1]
      end

      threads.each { |t| t.join }

      if parallel
        threads.each do |thread|
          thread.value.each do |warning|
            check_runner.add_warning warning
          end
        end
      else
        results.each do |warnings|
          warnings.each do |warning|
            check_runner.add_warning warning
          end
        end
      end
    end

    check_runner.finalize_warnings
    check_runner
  end

  private

  # Merge discoveries for the same physical sink within one discovery scope.
  # Template sinks are additionally merged across render paths when their
  # template-file/line/ordinal match; the ordinal keeps distinct outputs on one
  # line separate while still aligning copies seen through different paths.
  def find_existing_sink warning
    exact = all_discovered_warnings.find do |existing|
      existing.discovery_scope == warning.discovery_scope &&
        existing.sink_instance_key == warning.sink_instance_key
    end
    return exact if exact

    # Template sinks are aggregated across render paths by their position in
    # the template, not by the resolved call structure.
    return nil unless warning.warning_set == :template

    all_discovered_warnings.find do |existing|
      existing.template_mergeable?(warning) &&
        existing.discovery_scope != warning.discovery_scope
    end
  end

  # Move a previously suppressed warning into its report bucket.
  def promote_sink warning
    @suppressed_sinks.delete warning

    case warning.warning_set
    when :template
      @template_warnings << warning unless @template_warnings.include?(warning)
    when :warning
      @warnings << warning unless @warnings.include?(warning)
    when :controller
      @controller_warnings << warning unless @controller_warnings.include?(warning)
    when :model
      @model_warnings << warning unless @model_warnings.include?(warning)
    else
      raise "Unknown warning: #{warning.warning_set}"
    end
  end

  def self.get_check_name check_class
    check_class.to_s.split("::").last
  end

  def self.checks_to_run tracker
    to_run = if tracker.options[:run_all_checks] or tracker.options[:run_checks]
               @checks + @optional_checks
             else
               @checks.dup
             end.to_set

    if enabled_checks = tracker.options[:enable_checks]
      @optional_checks.each do |c|
        if enabled_checks.include? self.get_check_name(c)
          to_run << c
        end
      end
    end

    self.filter_checks to_run, tracker
  end

  def self.filter_checks checks, tracker
    skipped = tracker.options[:skip_checks]
    explicit = tracker.options[:run_checks]
    enabled = tracker.options[:enable_checks] || []

    checks.reject do |c|
      check_name = self.get_check_name(c)

      skipped.include? check_name or
        (explicit and not explicit.include? check_name and not enabled.include? check_name)
    end
  end

  def self.run_a_check klass, mutex, tracker
    check = klass.new(tracker)

    begin
      check.run_check
    rescue => e
      mutex.synchronize do
        tracker.error e
      end
    end

    check.warnings
  end
end

#Load all files in checks/ directory
Dir.glob("#{File.expand_path(File.dirname(__FILE__))}/checks/*.rb").sort.each do |f|
  require f.match(/(brakeman\/checks\/.*)\.rb$/)[0]
end
