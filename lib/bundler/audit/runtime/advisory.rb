require 'date'
require 'yaml'

module Bundler
  module Audit
    module Runtime
      #
      # A Ruby interpreter advisory loaded from the `rubies/` tree of the
      # ruby-advisory-db.
      #
      # Runtime advisories are separate from gem advisories. A gem called
      # `ruby` (or `jruby`) is never treated as the interpreter, and the
      # runtime check only reads `rubies/#{engine}/*.yml`.
      #
      class Advisory

        # The `rubies/` directory of the advisory database.
        #
        # @return [String]
        attr_reader :path

        # The advisory identifier derived from the file name.
        #
        # @return [String]
        attr_reader :id

        # The engine the advisory applies to.
        #
        # @return [String, nil]
        attr_reader :engine

        # The advisory URL.
        #
        # @return [String, nil]
        attr_reader :url

        # The advisory title.
        #
        # @return [String, nil]
        attr_reader :title

        # The disclosure date.
        #
        # @return [Date, nil]
        attr_reader :date

        # The advisory description.
        #
        # @return [String, nil]
        attr_reader :description

        # The CVSSv2 score.
        #
        # @return [Float, nil]
        attr_reader :cvss_v2

        # The CVSSv3 score.
        #
        # @return [Float, nil]
        attr_reader :cvss_v3

        # The CVE number (without the `CVE-` prefix).
        #
        # @return [String, nil]
        attr_reader :cve

        # The OSVDB number.
        #
        # @return [Integer, nil]
        attr_reader :osvdb

        # The parsed unaffected version requirements.
        #
        # @return [Array<Gem::Requirement>]
        attr_reader :unaffected_versions

        # The parsed patched version requirements.
        #
        # @return [Array<Gem::Requirement>]
        attr_reader :patched_versions

        # Version requirement strings which could not be parsed.
        #
        # @return [Array<String>]
        attr_reader :invalid_requirements

        #
        # Loads a runtime advisory from a YAML file.
        #
        # @param [String] path
        #
        # @return [Advisory]
        #
        def self.load(path)
          data = File.open(path) do |yaml|
                   if Psych::VERSION >= '3.1.0'
                     YAML.safe_load(yaml, permitted_classes: [Date])
                   else
                     # XXX: psych < 3.1.0 YAML.safe_load calling convention
                     YAML.safe_load(yaml, [Date])
                   end
                 end

          unless data.kind_of?(Hash)
            raise(Error,"runtime advisory data in #{path.inspect} was not a Hash")
          end

          new(data,path: path)
        end

        #
        # Initializes a runtime advisory.
        #
        # @param [Hash] data
        #
        # @param [String] path
        #
        def initialize(data,path:)
          @path  = path
          @id    = File.basename(path).sub(/\.yml\z/,'')
          @engine= Target.normalize_engine(data['engine'])
          @url   = data['url']
          @title = data['title']
          @date  = data['date']
          @description = data['description']
          @cvss_v2 = data['cvss_v2']
          @cvss_v3 = data['cvss_v3']
          @cve     = data['cve']
          @osvdb   = data['osvdb']

          @invalid_requirements = []

          @unaffected_versions = parse_requirements(data['unaffected_versions'])
          @patched_versions    = parse_requirements(data['patched_versions'])
        end

        #
        # The CVE identifier.
        #
        # @return [String, nil]
        #
        def cve_id
          "CVE-#{cve}" if cve
        end

        #
        # The OSVDB identifier.
        #
        # @return [String, nil]
        #
        def osvdb_id
          "OSVDB-#{osvdb}" if osvdb
        end

        #
        # All identifiers for the advisory.
        #
        # @return [Array<String>]
        #
        def identifiers
          [cve_id, osvdb_id].compact
        end

        #
        # The criticality based on the CVSS score.
        #
        # @return [:none, :low, :medium, :high, :critical, nil]
        #
        def criticality
          if cvss_v3
            case cvss_v3
            when 0.0       then :none
            when 0.1..3.9  then :low
            when 4.0..6.9  then :medium
            when 7.0..8.9  then :high
            when 9.0..10.0 then :critical
            end
          elsif cvss_v2
            case cvss_v2
            when 0.0..3.9  then :low
            when 4.0..6.9  then :medium
            when 7.0..10.0 then :high
            end
          end
        end

        #
        # Determines whether the advisory can be evaluated for a version.
        #
        # An advisory with neither `patched_versions` nor
        # `unaffected_versions` provides no usable evidence and must not be
        # reported as a vulnerability.
        #
        # @return [Boolean]
        #
        def evaluable?
          !patched_versions.empty? || !unaffected_versions.empty?
        end

        #
        # Checks whether a version is explicitly unaffected.
        #
        # @param [Gem::Version, nil] version
        #
        # @return [Boolean]
        #
        def unaffected?(version)
          return false if version.nil?

          unaffected_versions.any? { |req| req.satisfied_by?(version) }
        end

        #
        # Checks whether a version is affected.
        #
        # @param [Gem::Version, nil] version
        #
        # @return [Boolean, :unknown]
        #   `:unknown` when the version is missing or the advisory has no
        #   usable version data.
        #
        def affected?(version)
          return :unknown if version.nil?
          return :unknown unless evaluable?

          unless unaffected_versions.empty?
            return false if unaffected_versions.any? { |req| req.satisfied_by?(version) }
          end

          return false if patched_versions.any? { |req| req.satisfied_by?(version) }

          # Without any patched versions there is no evidence that an
          # unmatched version is affected. An advisory which only lists
          # unaffected versions stays unknown for every other version.
          return :unknown if patched_versions.empty?

          true
        end

        #
        # Compares advisories by identifier.
        #
        # @param [Advisory] other
        #
        # @return [Boolean]
        #
        def ==(other)
          other.kind_of?(Advisory) && id == other.id && path == other.path
        end

        #
        # Converts the advisory to a Hash.
        #
        # @return [Hash{Symbol => Object}]
        #
        def to_h
          {
            path:        @path,
            id:          @id,
            engine:      @engine,
            url:         @url,
            title:       @title,
            date:        @date,
            description: @description,
            cvss_v2:     @cvss_v2,
            cvss_v3:     @cvss_v3,
            cve:         @cve,
            osvdb:       @osvdb,
            criticality: criticality,
            unaffected_versions: @unaffected_versions.map(&:to_s),
            patched_versions:    @patched_versions.map(&:to_s)
          }
        end

        #
        # @return [String]
        #
        def to_s
          id
        end

        private

        def parse_requirements(versions)
          Array(versions).map do |version|
            begin
              Gem::Requirement.new(*version.split(', '))
            rescue Gem::Requirement::BadRequirementError, ArgumentError
              @invalid_requirements << version
              nil
            end
          end.compact
        end

      end
    end
  end
end
