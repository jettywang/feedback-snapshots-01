module Bundler
  module Audit
    module Runtime
      #
      # The runtime advisories from an advisory database.
      #
      # Only the `rubies/` tree is read. Gem advisories from `gems/` are
      # deliberately ignored, even when a gem shares a name with an engine.
      #
      class AdvisorySet

        # The `rubies/` directory.
        #
        # @return [String]
        attr_reader :path

        # Advisories which could not be loaded.
        #
        # @return [Array<Hash>]
        attr_reader :load_errors

        #
        # Initializes the advisory set.
        #
        # @param [String] path
        #   The advisory database root (the directory containing `rubies/`).
        #
        def initialize(path)
          @path        = File.join(path,'rubies')
          @load_errors = []
        end

        #
        # Determines whether the database has a `rubies/` tree.
        #
        # @return [Boolean]
        #
        def exist?
          File.directory?(@path)
        end

        #
        # Enumerates over every runtime advisory.
        #
        # @yield [advisory]
        #
        # @return [Enumerator]
        #
        def each
          return enum_for(__method__) unless block_given?

          each_advisory_path do |path|
            begin
              yield Advisory.load(path)
            rescue => error
              @load_errors << {path: path, error: "#{error.class}: #{error.message}"}
            end
          end

          return self
        end

        #
        # The runtime advisories which apply to an engine.
        #
        # @param [String, nil] engine
        #
        # @return [Array<Advisory>]
        #
        def advisories_for(engine)
          return [] if engine.nil?

          engine = Target.normalize_engine(engine)
          return [] if engine.nil?

          advisories = []

          each_advisory_path_for(engine) do |path|
            begin
              advisory = Advisory.load(path)

              # A directory name is not enough. The advisory itself must name
              # the same engine, otherwise conflicting evidence is ignored.
              advisories << advisory if advisory.engine == engine
            rescue => error
              @load_errors << {path: path, error: "#{error.class}: #{error.message}"}
            end
          end

          advisories
        end

        #
        # Advisories which name an engine but are stored under a different
        # engine directory.
        #
        # The storage location and the advisory body disagree. The caller is
        # expected to treat these as conflicting evidence instead of silently
        # selecting either the directory or the body.
        #
        # @param [String, nil] engine
        #
        # @return [Array<Hash>]
        #
        def misplaced_advisories(engine)
          engine = Target.normalize_engine(engine)
          return [] if engine.nil?

          misplaced = []

          each_advisory_path do |path|
            directory = File.basename(File.dirname(path))

            next if directory == engine

            begin
              advisory = Advisory.load(path)

              if advisory.engine == engine
                misplaced << {
                  path:     path,
                  id:       advisory.id,
                  declared: directory,
                  advisory: advisory
                }
              end
            rescue => error
              @load_errors << {path: path, error: "#{error.class}: #{error.message}"}
            end
          end

          misplaced
        end

        #
        # The number of runtime advisories.
        #
        # @return [Integer]
        #
        def size
          each_advisory_path.count
        end

        #
        # @return [String]
        #
        def to_s
          @path
        end

        protected

        def each_advisory_path(&block)
          Dir.glob(File.join(@path,'*','*.yml'),&block)
        end

        def each_advisory_path_for(engine,&block)
          Dir.glob(File.join(@path,engine,'*.yml'),&block)
        end

      end
    end
  end
end
