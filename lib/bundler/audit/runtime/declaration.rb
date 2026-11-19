require 'rubygems'

module Bundler
  module Audit
    module Runtime
      #
      # The Ruby interpreter declaration recorded in a `Gemfile.lock`
      # (`RUBY VERSION`).
      #
      # The declaration is evidence about the intended environment, but it is
      # not the deployment target. It is parsed separately so callers can
      # compare it against the explicitly supplied {Target}.
      #
      class Declaration

        # The normalized engine name.
        #
        # @return [String, nil]
        attr_reader :engine

        # The Ruby compatibility version.
        #
        # @return [Gem::Version, nil]
        attr_reader :version

        # The declared patchlevel.
        #
        # @return [Integer, nil]
        attr_reader :patchlevel

        # The declared engine version.
        #
        # @return [Gem::Version, nil]
        attr_reader :engine_version

        # The lock file (and section) the declaration was read from.
        #
        # @return [String, nil]
        attr_reader :source

        # The original declaration string.
        #
        # @return [String, nil]
        attr_reader :raw

        #
        # Parses the `RUBY VERSION` string from a lock file.
        #
        # @param [String, nil] string
        #
        # @param [String, nil] source
        #
        # @return [Declaration, nil]
        #   `nil` when the lock file has no `RUBY VERSION` section.
        #
        def self.parse(string,source: nil)
          return nil if string.nil?

          string = string.to_s.strip
          return nil if string.empty?

          new(string,source: source)
        end

        #
        # Parses the `ruby_version` value returned by a
        # `Bundler::LockfileParser`.
        #
        # Bundler 1.x returns `nil`; Bundler 2.x and later return the raw
        # string. Bundler objects are accepted as well for compatibility with
        # callers which construct `Bundler::RubyVersion` themselves.
        #
        # @param [Object, nil] value
        #
        # @param [String, nil] source
        #
        # @return [Declaration, nil]
        #
        def self.from_lockfile(value,source: 'Gemfile.lock')
          if value.respond_to?(:engine) && value.respond_to?(:versions)
            versions = Array(value.versions)
            engine_versions = Array(value.engine_versions)

            # Bundler::RubyVersion#to_s omits the patchlevel, so build the
            # raw declaration ourselves rather than losing it in the report.
            return new_from_parts(
              engine:         value.engine,
              version:        versions.first,
              patchlevel:     value.patchlevel,
              engine_version: (engine_versions.first unless engine_versions == versions),
              source:         source
            )
          end

          parse(value,source: source)
        end

        #
        # Extracts the `RUBY VERSION` section from lock file text.
        #
        # @param [String] text
        #
        # @param [String, nil] source
        #
        # @return [Declaration, nil]
        #
        def self.from_lockfile_text(text,source: 'Gemfile.lock')
          return nil if text.nil?

          section = nil
          in_ruby_section = false

          text.to_s.each_line do |line|
            line = line.chomp

            if line.strip == 'RUBY VERSION'
              in_ruby_section = true
              next
            end

            if in_ruby_section
              if line.strip.empty?
                break
              end

              section ||= line.strip
            end
          end

          parse(section,source: source)
        end

        #
        # Initializes a declaration.
        #
        # @param [String] raw
        #
        # @param [String, nil] source
        #
        def initialize(raw,source: nil)
          @raw    = raw
          @source = source

          engine,version,patchlevel,engine_version = self.class.split(raw)

          @engine         = Target.normalize_engine(engine)
          @version        = Target.parse_version(version)
          @patchlevel     = Target.parse_patchlevel(patchlevel)
          @engine_version = Target.parse_version(engine_version)

          @invalid_version = version.to_s unless version.nil? || @version

          unless engine_version.nil? || @engine_version
            @invalid_engine_version = engine_version.to_s
          end

          if @engine_version.nil? && (inferred = Target.infer_engine_version(@engine,@version))
            @engine_version = inferred
            @engine_version_inferred = true

            if @engine != 'ruby'
              @version = nil
            end
          end
        end

        #
        # Builds a declaration from already separated parts.
        #
        # @return [Declaration]
        #
        def self.new_from_parts(engine: nil, version: nil, patchlevel: nil,
                                engine_version: nil, source: nil, raw: nil)
          raw ||= begin
            normalized_engine = Target.normalize_engine(engine) || 'ruby'
            version_string    = [version, ("p#{patchlevel}" if patchlevel)].compact.join

            if normalized_engine == 'ruby'
              "ruby #{version_string}"
            else
              "ruby #{version_string} (#{normalized_engine} #{engine_version})"
            end
          end

          declaration = allocate
          declaration.send(:initialize_from_parts, engine, version, patchlevel,
                            engine_version, source, raw)
          declaration
        end

        #
        # Determines whether the declaration names a known engine.
        #
        # @return [Boolean]
        #
        def known_engine?
          !@engine.nil? && Target::ENGINE_ALIASES.value?(@engine)
        end

        #
        # The version runtime advisories should be evaluated against when the
        # declaration itself is used as a target.
        #
        # @return [Gem::Version, nil]
        #
        def evaluation_version
          if engine == 'ruby'
            @version
          else
            @engine_version
          end
        end

        #
        # @return [Gem::Version, nil]
        #
        def effective_mri_version
          return @version unless engine == 'ruby'

          if @version && @patchlevel && @patchlevel >= 0 &&
             @version.segments.length == 3 && !@version.prerelease?
            Gem::Version.new("#{@version}.#{@patchlevel}")
          else
            @version
          end
        rescue ArgumentError
          @version
        end

        #
        # Returns notes about missing or invalid declaration fields.
        #
        # @return [Array<Hash>]
        #
        def notes
          notes = []

          if @engine.nil?
            notes << {code: :declaration_missing_engine,
                      message: "lock file Ruby declaration does not name an engine"}
          elsif !known_engine?
            notes << {code: :declaration_unknown_engine,
                      message: "lock file Ruby declaration names unknown engine #{@engine.inspect}"}
          end

          if @invalid_version
            notes << {code: :invalid_declaration_version,
                      message: "lock file Ruby version #{@invalid_version.inspect} is not a Gem::Version"}
          end

          if @invalid_engine_version
            notes << {code: :invalid_declaration_engine_version,
                      message: "lock file engine version #{@invalid_engine_version.inspect} is not a Gem::Version"}
          end

          if engine == 'ruby' && @version && !@patchlevel
            notes << {code: :missing_declared_patchlevel,
                      message: "lock file Ruby declaration has no patchlevel"}
          end

          if @engine_version_inferred
            notes << {code: :inferred_declaration_engine_version,
                      message: "engine version #{@engine_version} was inferred from the declared version"}
          end

          return notes
        end

        #
        # Compares the declaration with an explicit deployment target.
        #
        # Differences are recorded as notes; the target remains authoritative
        # for the assessment.
        #
        # @param [Target] target
        #
        # @return [Array<Hash>]
        #
        def differences(target)
          notes = []

          if @engine && target.engine && @engine != target.engine
            notes << {
              code: :engine_mismatch,
              message: "lock file declares engine #{@engine}, deployment target is #{target.engine}"
            }
          end

          if @engine && target.engine && @engine == target.engine
            if @version && target.version && @version != target.version
              notes << {
                code: :version_mismatch,
                message: "lock file declares Ruby #{@version}, deployment target is #{target.version}"
              }
            end

            if @patchlevel && target.patchlevel && @patchlevel != target.patchlevel
              notes << {
                code: :patchlevel_mismatch,
                message: "lock file declares patchlevel #{@patchlevel}, deployment target is #{target.patchlevel}"
              }
            end

            if @engine_version && target.engine_version && @engine_version != target.engine_version
              notes << {
                code: :engine_version_mismatch,
                message: "lock file declares #{@engine} #{@engine_version}, deployment target is #{target.engine_version}"
              }
            end
          end

          return notes
        end

        #
        # Converts the declaration to a Hash.
        #
        # @return [Hash{Symbol => Object}]
        #
        def to_h
          {
            engine:         @engine,
            version:        @version && @version.to_s,
            patchlevel:     @patchlevel,
            engine_version: @engine_version && @engine_version.to_s,
            source:         @source,
            raw:            @raw
          }
        end

        #
        # @return [String]
        #
        def to_s
          @raw.to_s
        end

        #
        # Splits common `RUBY VERSION` forms.
        #
        # Supported forms:
        #
        #     ruby 3.1.4p53
        #     ruby 3.1.4
        #     ruby 2.5.0p0 (jruby 9.2.9.0)
        #     jruby 9.2.9.0
        #     truffleruby 24.0.0
        #
        # @param [String] raw
        #
        # @return [Array<(String, String, String, String)>]
        #
        def self.split(raw)
          string = raw.to_s.strip

          if string =~ /\A([A-Za-z][\w-]*)\s+(\S+)(?:\s+\(([\w-]+)\s+(\S+)\))?\z/
            engine         = $1
            version        = $2
            inner_engine   = $3
            engine_version = $4

            # `ruby 2.5.0p0 (jruby 9.2.9.0)` uses the first token as the
            # compatibility version and the parenthesized token as the real
            # engine and engine version.
            if inner_engine
              engine = inner_engine
            elsif engine.downcase != 'ruby' && !['jruby','rbx','rubinius','truffleruby','mri','cruby'].include?(engine.downcase)
              # Unknown leading token: keep it as the engine, with no version
              # assumptions.
            end

            patchlevel = nil
            if version =~ /\A(.+?)p(-?\d+)\z/
              version    = $1
              patchlevel = $2
            end

            # A non-MRI declaration without a parenthesized engine block is
            # an engine version, not a Ruby compatibility version.
            if inner_engine.nil? && engine.downcase != 'ruby'
              engine_version = version
              version        = nil
            end

            return [engine,version,patchlevel,engine_version]
          end

          [nil,string,nil,nil]
        end

        private

        def initialize_from_parts(engine,version,patchlevel,engine_version,source,raw)
          @raw            = raw
          @source         = source
          @engine         = Target.normalize_engine(engine)
          @version        = Target.parse_version(version)
          @patchlevel     = Target.parse_patchlevel(patchlevel)
          @engine_version = Target.parse_version(engine_version)

          @invalid_version = version.to_s unless version.nil? || @version
          @invalid_engine_version = engine_version.to_s unless engine_version.nil? || @engine_version
        end

      end
    end
  end
end
