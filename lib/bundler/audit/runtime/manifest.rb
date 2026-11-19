require 'date'
require 'yaml'

module Bundler
  module Audit
    module Runtime
      #
      # A deployment manifest which explicitly describes the Ruby interpreter
      # used by the deployed application.
      #
      # The manifest is the only supported way for the CLI to learn about the
      # deployment runtime. The scanning host's own Ruby is never consulted.
      #
      # Example:
      #
      #     ruby:
      #       engine: jruby
      #       version: 2.5.0
      #       patchlevel: 0
      #       engine_version: 9.2.9.0
      #     source: deploy/Procfile
      #
      class Manifest

        # The explicitly described deployment target.
        #
        # @return [Target]
        attr_reader :target

        # The path the manifest was loaded from.
        #
        # @return [String]
        attr_reader :path

        # Notes raised while interpreting the manifest.
        #
        # @return [Array<Hash>]
        attr_reader :notes

        # The parsed manifest data.
        #
        # @return [Hash]
        attr_reader :data

        #
        # Loads a deployment manifest from a YAML file.
        #
        # @param [String] path
        #
        # @raise [Error]
        #   The file is missing, is not YAML, or does not contain a `ruby`
        #   section.
        #
        # @return [Manifest]
        #
        def self.load(path)
          unless File.file?(path)
            raise(Error,"deployment manifest #{path.inspect} does not exist")
          end

          data = load_yaml(path)

          unless data.kind_of?(Hash)
            raise(Error,"deployment manifest #{path.inspect} is not a Hash")
          end

          new(data,path: path)
        end

        #
        # Initializes a deployment manifest from parsed data.
        #
        # @param [Hash] data
        #
        # @param [String, nil] path
        #
        # @raise [Error]
        #   The `ruby` section is missing or not a Hash.
        #
        def initialize(data,path: nil)
          @data = data || {}
          @path = path

          unless @data.kind_of?(Hash)
            raise(Error,"deployment manifest is not a Hash")
          end

          ruby = @data['ruby'] || @data[:ruby]

          if ruby.nil?
            raise(Error,"deployment manifest #{@path ? @path.inspect : ''} has no `ruby` section".strip)
          end

          unless ruby.kind_of?(Hash)
            raise(Error,"deployment manifest #{@path ? @path.inspect : ''} `ruby` section is not a Hash".strip)
          end

          ruby = symbolize_keys(ruby)

          patchlevel = ruby[:patchlevel]
          patchlevel = ruby[:patch_level] if patchlevel.nil?

          @notes  = []
          @target = Target.new(
            engine:         ruby[:engine],
            version:        ruby[:version] || ruby[:ruby_version],
            patchlevel:     patchlevel,
            engine_version: ruby[:engine_version],
            source:         @path,
            raw:            ruby
          )

          unless @target.known_engine?
            if @target.engine.nil?
              @notes << {code: :manifest_missing_engine,
                         message: "deployment manifest does not specify an engine"}
            else
              @notes << {code: :manifest_unknown_engine,
                         message: "deployment manifest specifies unknown engine #{@target.engine.inspect}"}
            end
          end

          if @target.version.nil? && @target.engine_version.nil?
            @notes << {code: :manifest_missing_version,
                       message: "deployment manifest does not specify a usable version"}
          end

          @notes.concat(@target.notes)
        end

        #
        # The vendor specific `source` field, if the manifest names one.
        #
        # @return [String, nil]
        #
        def source
          value = @data['source'] || @data[:source]
          value && value.to_s
        end

        #
        # @return [Hash{Symbol => Object}]
        #
        def to_h
          {
            path:   @path,
            ruby:   @target.to_h,
            notes:  @notes
          }
        end

        #
        # @return [String]
        #
        def to_s
          @path || '(inline manifest)'
        end

        private

        def self.load_yaml(path)
          File.open(path) do |yaml|
            if Psych::VERSION >= '3.1.0'
              YAML.safe_load(yaml, permitted_classes: [Date])
            else
              # XXX: psych < 3.1.0 YAML.safe_load calling convention
              YAML.safe_load(yaml, [Date])
            end
          end
        end

        def symbolize_keys(hash)
          hash.each_with_object({}) do |(key,value),new_hash|
            new_hash[key.to_s.downcase.to_sym] = value
          end
        end

      end
    end
  end
end
