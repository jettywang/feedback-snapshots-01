require 'rubygems'

module Bundler
  module Audit
    module Runtime
      #
      # An explicitly supplied interpreter which is expected to run the
      # deployed application.
      #
      # A target keeps the Ruby compatibility version ({#version}), the
      # engine's own version ({#engine_version}) and the patchlevel separate.
      # This matters for JRuby where `ruby 2.5.0p0 (jruby 9.2.9.0)` means a
      # Ruby 2.5.0 compatibility version and a JRuby 9.2.9.0 engine version.
      #
      class Target

        # Recognized engine names and their aliases.
        ENGINE_ALIASES = {
          'ruby'        => 'ruby',
          'mri'         => 'ruby',
          'cruby'       => 'ruby',
          'jruby'       => 'jruby',
          'rbx'         => 'rbx',
          'rubinius'    => 'rbx',
          'truffleruby' => 'truffleruby',
          'truffle'     => 'truffleruby'
        }

        # The normalized engine name (`"ruby"`, `"jruby"`, ...).
        #
        # @return [String, nil]
        attr_reader :engine

        # The Ruby compatibility version, as a {Gem::Version}.
        #
        # @return [Gem::Version, nil]
        attr_reader :version

        # The patchlevel, if known.
        #
        # @return [Integer, nil]
        attr_reader :patchlevel

        # The engine's own version (for example the JRuby version).
        #
        # @return [Gem::Version, nil]
        attr_reader :engine_version

        # Where the target information came from (for example a manifest
        # path).
        #
        # @return [String, nil]
        attr_reader :source

        # The original manifest data.
        #
        # @return [Hash]
        attr_reader :raw

        # The original, unparsable version string, if any.
        #
        # @return [String, nil]
        attr_reader :invalid_version

        # The original, unparsable engine version string, if any.
        #
        # @return [String, nil]
        attr_reader :invalid_engine_version

        #
        # Normalizes an engine name.
        #
        # @param [String, Symbol, nil] engine
        #
        # @return [String, nil]
        #
        def self.normalize_engine(engine)
          return nil if engine.nil?

          name = engine.to_s.strip.downcase
          return nil if name.empty?

          ENGINE_ALIASES.fetch(name,name)
        end

        #
        # Initializes a runtime target.
        #
        # @param [String, Symbol, nil] engine
        #
        # @param [String, Gem::Version, nil] version
        #
        # @param [Integer, String, nil] patchlevel
        #
        # @param [String, Gem::Version, nil] engine_version
        #
        # @param [String, nil] source
        #
        # @param [Hash, nil] raw
        #
        def initialize(engine: nil, version: nil, patchlevel: nil,
                       engine_version: nil, source: nil, raw: nil)
          @engine = self.class.normalize_engine(engine)
          @raw    = raw || {}
          @source = source

          version,patchlevel = self.class.split_patchlevel(version,patchlevel)

          @version        = self.class.parse_version(version)
          @patchlevel     = self.class.parse_patchlevel(patchlevel)
          @engine_version = self.class.parse_version(engine_version)

          unless version.nil? || @version
            @invalid_version = version.to_s
          end

          unless engine_version.nil? || @engine_version
            @invalid_engine_version = engine_version.to_s
          end

          if @engine_version.nil? && (inferred = self.class.infer_engine_version(@engine,@version))
            @engine_version = inferred
            @engine_version_inferred = true

            # A single version supplied for a non-MRI engine which is
            # unambiguously an engine version is not a Ruby compatibility
            # version. Keep the engine version and leave the compatibility
            # version unknown instead of misreporting it.
            if @engine != 'ruby'
              @version = nil
            end
          end
        end

        #
        # Determines whether the engine is a recognized Ruby implementation.
        #
        # @return [Boolean]
        #
        def known_engine?
          !@engine.nil? && ENGINE_ALIASES.value?(@engine)
        end

        #
        # Determines whether this is an MRI (CRuby) target.
        #
        # @return [Boolean]
        #
        def mri?
          @engine == 'ruby'
        end

        #
        # The Ruby compatibility version.
        #
        # For MRI this is also the interpreter version. For JRuby this is the
        # Ruby version emulated by the engine.
        #
        # @return [Gem::Version, nil]
        #
        def compatibility_version
          @version
        end

        #
        # The version which runtime advisories apply to.
        #
        # For MRI this is the Ruby version without the patchlevel, which is
        # kept separately. Individual advisories which use four component
        # versions combine the two via {#effective_mri_version}. For JRuby
        # this is the JRuby version, not the Ruby compatibility version.
        #
        # @return [Gem::Version, nil]
        #
        def evaluation_version
          if mri?
            @version
          else
            @engine_version
          end
        end

        #
        # The version including an MRI patchlevel where one is known.
        #
        # Older MRI advisories use four component versions such as
        # `1.8.7.249`, where the final component is the patchlevel.
        #
        # @return [Gem::Version, nil]
        #
        def effective_mri_version
          return @version unless mri?

          if @version && @patchlevel && @patchlevel >= 0 &&
             @version.segments.length == 3 && !@version.prerelease?
            begin
              Gem::Version.new("#{@version}.#{@patchlevel}")
            rescue ArgumentError
              @version
            end
          else
            @version
          end
        end

        #
        # Determines whether a patchlevel was supplied.
        #
        # @return [Boolean]
        #
        def patchlevel?
          !@patchlevel.nil?
        end

        #
        # Determines whether an engine version was supplied explicitly or
        # unambiguously inferred.
        #
        # @return [Boolean]
        #
        def engine_version?
          !@engine_version.nil?
        end

        #
        # Determines whether the engine version was inferred by
        # {Target} rather than supplied by the caller.
        #
        # @return [Boolean]
        #
        def inferred_engine_version?
          @engine_version_inferred == true
        end

        #
        # Any notes about interpretation of the target data.
        #
        # @return [Array<Hash>]
        #
        def notes
          notes = []

          if @invalid_version
            notes << {
              code: :invalid_target_version,
              message: "target version #{@invalid_version.inspect} is not a Gem::Version"
            }
          end

          if @invalid_engine_version
            notes << {
              code: :invalid_target_engine_version,
              message: "target engine version #{@invalid_engine_version.inspect} is not a Gem::Version"
            }
          end

          if mri? && @version && !patchlevel?
            notes << {
              code: :missing_target_patchlevel,
              message: "target patchlevel is missing; four component MRI advisories cannot be evaluated"
            }
          end

          if inferred_engine_version?
            notes << {
              code: :inferred_engine_version,
              message: "engine version #{@engine_version} was inferred from the target version"
            }
          end

          if !mri? && !@engine.nil? && @engine_version.nil?
            notes << {
              code: :missing_target_engine_version,
              message: "target #{@engine} engine version is missing; runtime advisories cannot be evaluated"
            }
          end

          return notes
        end

        #
        # Converts the target to a Hash.
        #
        # @return [Hash{Symbol => Object}]
        #
        def to_h
          {
            engine:         @engine,
            version:        @version && @version.to_s,
            patchlevel:     @patchlevel,
            engine_version: @engine_version && @engine_version.to_s,
            source:         @source
          }
        end

        #
        # @return [String]
        #
        def to_s
          if mri?
            if @version.nil?
              "ruby"
            elsif @patchlevel
              "ruby #{@version}p#{@patchlevel}"
            else
              "ruby #{@version}"
            end
          elsif @engine_version
            "#{@engine} #{@engine_version}"
          else
            @engine.to_s
          end
        end

        #
        # @param [Object] value
        #
        # @return [Gem::Version, nil]
        #
        def self.parse_version(value)
          return nil if value.nil?
          return value if value.kind_of?(Gem::Version)

          string = value.to_s.strip
          return nil if string.empty?
          return nil unless Gem::Version.correct?(string)

          Gem::Version.new(string)
        rescue ArgumentError
          nil
        end

        #
        # @param [Object] value
        #
        # @return [Integer, nil]
        #
        def self.parse_patchlevel(value)
          return nil if value.nil?
          return value if value.kind_of?(Integer)

          string = value.to_s.strip
          return nil unless string =~ /\A-?\d+\z/

          string.to_i
        end

        #
        # Splits a combined `2.5.0p53` version into separate values.
        #
        # @param [Object] version
        # @param [Integer, String, nil] patchlevel
        #
        # @return [Array<(Object, Object)>]
        #
        def self.split_patchlevel(version,patchlevel)
          return [version,patchlevel] if patchlevel || version.nil?
          return [version,patchlevel] if version.kind_of?(Gem::Version)

          if version.to_s.strip =~ /\A(.+?)p(-?\d+)\z/
            [$1,$2]
          else
            [version,patchlevel]
          end
        end

        #
        # Infers an engine version for engines where callers commonly supply
        # only one version.
        #
        # Only unambiguous values are inferred. For example JRuby 9.x is an
        # engine version, while JRuby 2.5.0 could be either the emulated Ruby
        # version or a missing engine version and is therefore left unknown.
        #
        # @param [String, nil] engine
        # @param [Gem::Version, nil] version
        #
        # @return [Gem::Version, nil]
        #
        def self.infer_engine_version(engine,version)
          return nil if engine.nil? || version.nil?

          if engine == 'jruby'
            segments = version.segments

            if segments.first.to_i >= 9 || segments.length >= 4
              version
            elsif segments[0].to_i == 1 && ![8,9].include?(segments[1].to_i)
              version
            end
          elsif engine == 'rbx' || engine == 'truffleruby'
            version
          end
        end

      end
    end
  end
end
