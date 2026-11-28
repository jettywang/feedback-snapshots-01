require 'bundler/audit/advisory'
require 'bundler/audit/correlation'
require 'bundler/audit/results/insecure_source'
require 'bundler/audit/results/unpatched_gem'

module SpecSupport
  #
  # A tiny in-memory advisory database backed by YAML fixtures, used by the
  # correlation specs so they can run without cloning ruby-advisory-db.
  #
  class StaticDatabase
    attr_reader :path

    def initialize(path)
      @path = path
    end

    def advisories_for(name,&block)
      path = File.join(@path,'gems',name,'*.yml')

      Dir.glob(path).each do |advisory_path|
        block.call(Bundler::Audit::Advisory.load(advisory_path))
      end
    end

    def check_gem(gem,&block)
      advisories_for(gem.name) do |advisory|
        block.call(advisory) if advisory.vulnerable?(gem.version)
      end
    end
  end
end

module SpecSupport
  #
  # Renders a report in all three built-in formats and returns their text.
  #
  # @param [Bundler::Audit::Report] report
  #
  # @return [Hash{String => String}]
  #
  def self.render_all(report,options={})
    require 'bundler/audit/cli'
    require 'bundler/audit/cli/formats/text'
    require 'bundler/audit/cli/formats/json'
    require 'bundler/audit/cli/formats/junit'
    require 'stringio'

    formats = {
      'text'  => Bundler::Audit::CLI::Formats::Text,
      'json'  => Bundler::Audit::CLI::Formats::JSON,
      'junit' => Bundler::Audit::CLI::Formats::Junit
    }

    formats.each_with_object({}) do |(name,format),outputs|
      output = StringIO.new
      cli    = Bundler::Audit::CLI.new([],options)

      cli.extend(format)
      cli.print_report(report,output)

      outputs[name] = output.string
    end
  end

  #
  # Extracts correlation IDs from the text format output.
  #
  # @param [String] text
  #
  # @return [Array<String>]
  #
  def self.text_correlation_ids(text)
    text.scan(/^Correlation ID: (.+)$/).map(&:first)
  end

  #
  # Extracts correlation IDs (testcase ids) from the JUnit XML output.
  #
  # @param [String] xml
  #
  # @return [Array<String>]
  #
  def self.junit_correlation_ids(xml)
    xml.scan(/<testcase id="(BA-[A-Z]{3}-[0-9a-f]+)"/).map(&:first)
  end

  #
  # Extracts correlation IDs from the JSON output.
  #
  # @param [String] json
  #
  # @return [Array<String>]
  #
  def self.json_correlation_ids(json)
    require 'json'

    parsed = ::JSON.parse(json)
    parsed['results'].map { |result| result['correlation_id'] }
  end

  #
  # Cross-checks three rendered artifacts and returns a Hash describing the
  # comparison. This is deliberately independent of how an artifact build
  # orders findings or how many fields it carries.
  #
  # @param [String] text
  # @param [String] json
  # @param [String] junit
  #
  # @return [Hash{Symbol => Object}]
  #
  def self.cross_check(text,json,junit)
    sets = {
      'text'  => text_correlation_ids(text),
      'json'  => json_correlation_ids(json),
      'junit' => junit_correlation_ids(junit)
    }

    reference = sets['json']

    duplicates = sets.each_with_object({}) do |(name,ids),result|
      result[name] = duplicates(ids)
    end

    missing = sets.each_with_object({}) do |(name,ids),result|
      result[name] = (reference - ids) + (ids - reference)
    end

    {
      sets:       sets,
      duplicates: duplicates,
      missing:    missing,
      consistent: duplicates.values.all?(&:empty?) &&
                  missing.values.all?(&:empty?)
    }
  end

  #
  # @param [Array<String>] ids
  #
  # @return [Array<String>]
  #
  def self.duplicates(ids)
    ids.select { |id| ids.count(id) > 1 }.uniq
  end
end

