# frozen-string-literal: true

require 'find'
require 'uri'

class Roda
  module RodaPlugins
    # The hash_public_cache plugin builds on top of the hash_public plugin and
    # adds the ability to store the digests for the public files in a json file,
    # and load that file at startup, which avoids the need for the process to
    # read the public file in order to compute the digest.
    #
    # Examples:
    #
    #   # Load the plugin. Options given will be passed to public and hash_public.
    #   plugin :hash_public_cache, "path/to/cache_file.json"
    #
    #   # When rebuilding the cache:
    #   #
    #   # * Scan the public directory for files, calculate the digest on each.
    #   # * Write the hash public cache to a file.
    #   #
    #   # This is split into separate steps in case you want to modify the cache
    #   # manually after the scan.
    #   scan_hash_public_cache_dir
    #   dump_hash_public_cache_file
    #
    #   # To load the cache at application startup (if the file exists):
    #   load_hash_public_cache_file
    #
    # For deployments that prepare a new set of content-hashed static files in
    # a separate directory and publish it by switching directories, the plugin
    # can verify the complete candidate manifest before changing anything:
    #
    #   # Verify a manifest (relative path => content digest) against a
    #   # candidate directory.  This does not modify the active release.
    #   verify_hash_public_cache(manifest, root: candidate_dir)
    #
    #   # Build and verify a manifest for a candidate directory, then switch
    #   # both the served root and the digest cache.  Returns true on success.
    #   publish_hash_public_cache(candidate_dir)
    #
    # A manifest entry only verifies if it is a relative path that resolves to
    # a readable regular file inside the candidate root.  Symbolic links that
    # resolve outside the root, unreadable files, and entries whose content
    # digest does not match are rejected.  If verification fails, or if any
    # file cannot be read while building the candidate manifest, the previous
    # release remains active and false is returned.
    #
    # Building a candidate manifest never modifies the active cache, and
    # writing a cache file uses a temporary file plus rename.  A failure while
    # generating a new release therefore cannot replace the previous cache
    # file or change the content served under the previous release's paths.
    module HashPublicCache
      # Characters that separate path segments.
      SPLIT = Regexp.union(*[File::SEPARATOR, File::ALT_SEPARATOR].compact)

      # Use the same URI parser as the public plugin to unescape paths.
      PARSER = defined?(::URI::RFC2396_PARSER) ? ::URI::RFC2396_PARSER : ::URI::DEFAULT_PARSER
      private_constant :SPLIT, :PARSER

      # Keys accepted for the path and digest in a manifest entry hash.
      PATH_KEYS = ['path', :path].freeze
      DIGEST_KEYS = ['digest', :digest, 'hash', :hash].freeze
      private_constant :PATH_KEYS, :DIGEST_KEYS

      def self.load_dependencies(app, _cache_file, opts = OPTS)
        app.plugin :_json
        app.plugin :hash_public, **opts
      end

      # Specify the location of the hash public cache file.
      #
      # The options given are passed as keyword arguments to the hash_public plugin.
      def self.configure(app, cache_file, opts = OPTS)
        app.opts[:hash_public_cache_file] = cache_file
        # Mutable state for the installed release.  This is a plain hash so
        # that it can still be updated after the Roda class is frozen, unlike
        # the frozen options hash.
        app.opts[:hash_public_release_state] ||= {}
      end

      module ClassMethods
        RodaPlugins.opt_attr_reader(self, :hash_public_cache_file)

        # Mutable state for the installed release.
        def hash_public_release_state
          opts[:hash_public_release_state]
        end

        # The active digest cache used by hash_path.  For an unfrozen
        # application the options hash remains the source of truth for
        # backwards compatibility.  For a frozen application, the options
        # hash cannot be changed, so the release state is used instead.
        def hash_public_cache
          state = hash_public_release_state
          if opts.frozen?
            state[:cache] || super
          else
            opts[:hash_public_cache] || state[:cache] || super
          end
        end

        # The currently installed release generation.  A generation bundles
        # the release manifest, served root, and Rack::Files server, and is
        # replaced by a single reference assignment.  Requests capture one
        # generation, so the manifest and the files they are checked against
        # always belong to the same release.
        def hash_public_generation
          hash_public_release_state[:current]
        end

        # The digest of each path in the currently published release, or nil
        # if no verified release has been installed.  Requests are only served
        # when both the path and the requested digest are present in this
        # manifest.  This is kept separate from the digest cache used by
        # +hash_path+, so generating a path for a file that is not part of the
        # published release does not make that file externally readable.
        def hash_public_release
          if generation = hash_public_generation
            generation[:release]
          end
        end

        # Whether requests are restricted to the installed release manifest.
        def hash_public_cache_enforced?
          !hash_public_release.nil?
        end

        # The served root for the installed release, when it differs from the
        # root configured at load time.
        def public_root
          if generation = hash_public_generation
            generation[:root]
          else
            super
          end
        end

        # The Rack::Files server for the installed release, when its root
        # differs from the root configured at load time.
        def public_server
          if generation = hash_public_generation
            generation[:server]
          else
            super
          end
        end

        # Load the hash public cache file, if it exists. This replaces the hash
        # public cache with the values from the file.
        #
        # If the +root+ keyword argument is given, or +verify+ is true, the
        # cache file is only installed if every entry names a readable regular
        # file below the root whose current content digest matches the entry.
        # When +root+ is given and differs from the current public root, the
        # served root is switched along with the cache.  The root defaults to
        # the public root.  If reading, parsing, or verification fails, the
        # active release is left unchanged and false is returned.
        def load_hash_public_cache_file(root: nil, verify: false)
          file = hash_public_cache_file
          return false unless File.file?(file)

          manifest = json_parser.call(::File.read(file))

          if verify || root
            install_hash_public_cache(manifest, root: root || public_root)
          else
            # Preserve the historical behavior of installing the file contents
            # without verifying them.  Use +verify+ or +root+ to require a
            # complete, matching candidate release.
            cache = {}
            manifest.each do |path, digest|
              cache[path] = digest.to_s.freeze
            end
            _install_hash_public_cache(cache)

            # An unverified load restores the historical behavior, where the
            # configured public root is served and the cache only supplies
            # digests for hash_path.  Any previously published generation is
            # retired so requests are not served from a stale manifest.
            hash_public_release_state[:current] = nil
            true
          end
        rescue StandardError
          # simplecov:disable
          # A missing, partially written, or invalid cache file must not
          # replace the release that is already being served.
          false
          # simplecov:enable
        end

        # Verify that every entry in the given manifest names a readable
        # regular file below +root+.  A manifest can be a hash of relative
        # path to expected content digest, or an array of paths or entry
        # hashes.  Returns true only if all entries verify.  This does not
        # modify the active release.
        def verify_hash_public_cache(manifest, root: public_root)
          !_hash_public_manifest_cache(manifest, root).nil?
        end

        # Verify the cache file against +root+ without installing it.
        def verify_hash_public_cache_file(file = hash_public_cache_file, root: public_root)
          return false unless File.file?(file)

          verify_hash_public_cache(json_parser.call(::File.read(file)), root: root)
        rescue StandardError
          # simplecov:disable
          false
          # simplecov:enable
        end

        # Verify that a complete manifest can be built for +root+, without
        # modifying the active release.
        def verify_hash_public_cache_dir(root = public_root)
          !build_hash_public_cache(root).nil?
        end

        # Build a cache (relative path to content digest) for every regular
        # file below +root+, without modifying the active cache.  Returns nil
        # if the directory cannot be scanned, any file cannot be read, or a
        # file resolves outside the root through a symbolic link.
        def build_hash_public_cache(root = public_root)
          root = ::File.expand_path(root)
          return unless ::File.directory?(root)

          real_root = ::File.realpath(root)
          cache = {}
          prefix = real_root.end_with?(::File::SEPARATOR) ? real_root : "#{real_root}#{::File::SEPARATOR}"

          # Traverse the real path so a release directory reached through a
          # symbolic link (a common atomic deployment layout) is fully scanned.
          Find.find(real_root) do |file|
            next unless ::File.file?(file)

            path = file.start_with?(prefix) ? file[prefix.length..-1] : nil
            return unless path && !path.empty?

            path = path.tr(::File::ALT_SEPARATOR, '/') if ::File::ALT_SEPARATOR
            path = _hash_public_cache_key(path)
            return unless path

            return unless _hash_public_inside_root?(file, real_root)

            cache[path] = _hash_path_digest(file)
          rescue SystemCallError, RodaError
            # simplecov:disable
            # A file that cannot be read (including a path that resolves
            # outside the root) makes the candidate manifest incomplete.
            return
            # simplecov:enable
          end

          # An empty release directory is treated as an incomplete candidate.
          cache unless cache.empty?
        rescue SystemCallError, RodaError
          # simplecov:disable
          nil
          # simplecov:enable
        end

        # Install the given manifest only if every entry verifies against
        # +root+.  The active cache is replaced as a single reference
        # assignment, so a request that already obtained the previous cache
        # is not affected.  Returns true if the release was installed.
        def install_hash_public_cache(manifest, root: public_root)
          root = root.nil? ? public_root : ::File.expand_path(root)
          cache = _hash_public_manifest_cache(manifest, root)
          return false unless cache

          _activate_hash_public_cache(cache, root)
          true
        end

        # Build a fresh manifest for every regular file below +root+, verify
        # the complete candidate, and then switch both the served root and the
        # digest cache.
        #
        # This is the deployment entry point for publishing a new set of
        # content-hashed static files: the previous release remains active
        # unless the complete candidate manifest can be built and verified.
        # If +manifest+ is given, it is verified against +root+ and used as
        # the set of paths that may be served; otherwise the manifest is built
        # from the directory contents.  Returns true if the new release was
        # installed, false otherwise.
        def publish_hash_public_cache(root = public_root, manifest: nil)
          root = root.nil? ? public_root : ::File.expand_path(root)
          cache = if manifest
            _hash_public_manifest_cache(manifest, root)
          else
            build_hash_public_cache(root)
          end
          return false unless cache

          _activate_hash_public_cache(cache, root)
        end

        # Verify a candidate release without switching to it.  This is the
        # release gate: it reports whether the candidate directory and
        # manifest are complete and consistent while the previous release
        # continues to be served.
        def verify_hash_public_release(root = public_root, manifest: nil)
          root = root.nil? ? public_root : ::File.expand_path(root)
          cache = if manifest
            _hash_public_manifest_cache(manifest, root)
          else
            build_hash_public_cache(root)
          end
          !cache.nil?
        end

        # Scan the public directory for files, computing the hash public digest
        # for each. This will not rescan files that already have digest values.
        # If a block is given, it will only calculate the digest for the file
        # if the block returns truthy.
        #
        # The scan is performed on a copy of the active cache. The active cache
        # is only replaced after the scan completes successfully, so an error
        # reading a file leaves the previous cache active.  Returns true if the
        # cache was installed, false otherwise.
        def scan_hash_public_cache_dir
          root = public_root
          return false unless ::File.directory?(root)

          real_root = ::File.realpath(root)
          cache = hash_public_cache.dup
          prefix = real_root.end_with?(::File::SEPARATOR) ? real_root : "#{real_root}#{::File::SEPARATOR}"

          Find.find(real_root) do |file|
            next unless ::File.file?(file)

            path = file.start_with?(prefix) ? file[prefix.length..-1] : nil
            return false unless path && !path.empty?

            path = path.tr(::File::ALT_SEPARATOR, '/') if ::File::ALT_SEPARATOR
            path = _hash_public_cache_key(path)
            return false unless path

            next if cache[path]
            next if block_given? && !yield(path)

            return false unless _hash_public_inside_root?(file, real_root)

            cache[path] = _hash_path_digest(file)
          end

          _install_hash_public_cache(cache)
          true
        rescue SystemCallError, RodaError
          # simplecov:disable
          false
          # simplecov:enable
        end

        # Write the current hash public cache to the cache file.
        #
        # The file is written to a temporary file in the same directory and
        # renamed into place, so readers never observe a partially written
        # manifest and a failure during generation does not replace the
        # previous cache file.
        def dump_hash_public_cache_file
          file = hash_public_cache_file
          tmp_file = "#{file}.tmp.#{$$}.#{Thread.current.object_id}"

          begin
            ::File.open(tmp_file, 'wb') do |f|
              f.write(json_serializer.call(hash_public_cache))
              f.flush
              begin
                f.fsync
              rescue NotImplementedError, SystemCallError
                # simplecov:disable
                # Not all file systems support fsync.
                # simplecov:enable
              end
            end
            ::File.rename(tmp_file, file)
          ensure
            begin
              ::File.unlink(tmp_file) if ::File.exist?(tmp_file)
            rescue SystemCallError
              # simplecov:disable
              # Another process may have already removed it.
              # simplecov:enable
            end
          end

          nil
        end

        private

        # Switch the served root and the digest cache together.  A new
        # generation is built first and then installed with one reference
        # assignment, so requests never observe a mix of the previous
        # manifest and the new files.
        def _activate_hash_public_cache(cache, root)
          state = hash_public_release_state
          return false unless state

          root = ::File.expand_path(root)

          hash_public_mutex.synchronize do
            files = defined?(::Rack::Files) ? ::Rack::Files : ::Rack::File
            server = files.new(root, public_headers, public_default_mime)

            # Keep a frozen snapshot for request authorization.  The mutable
            # cache may still receive digests for paths generated by
            # hash_path, but those paths must not become part of the
            # published release by side effect.
            release = {}
            cache.each do |path, digest|
              release[path] = digest
            end

            _install_hash_public_cache_without_lock(cache)
            state[:current] = {
              :release => release.freeze,
              :root => root,
              :server => server,
            }.freeze
          end

          true
        end

        # Build a fresh, frozen cache from a manifest, verifying every entry.
        # Returns nil if the manifest is not a non-empty hash or array, or if
        # any entry is invalid, unreadable, outside the root, or has a digest
        # that does not match the file content.
        def _hash_public_manifest_cache(manifest, root)
          entries = case manifest
          when Hash
            manifest
          when Array
            manifest.each_with_object({}) do |entry, hash|
              case entry
              when Hash
                path = _hash_public_entry_value(entry, PATH_KEYS)
                return if path.nil?
                digest = _hash_public_entry_value(entry, DIGEST_KEYS)
                hash[path] = digest
              else
                hash[entry] = nil
              end
            end
          else
            return
          end

          return if entries.empty?

          root = ::File.expand_path(root)
          return unless ::File.directory?(root)

          real_root = ::File.realpath(root)
          cache = {}

          entries.each do |path, expected|
            path = _hash_public_cache_key(path)
            return unless path

            file = ::File.join(root, path)
            return unless ::File.file?(file) && ::File.readable?(file)
            return unless _hash_public_inside_root?(file, real_root)

            digest = _hash_path_digest(file)
            if expected && !_hash_public_digest_match?(file, digest, expected)
              return
            end

            cache[path] = digest
          end

          cache
        rescue SystemCallError
          # simplecov:disable
          nil
          # simplecov:enable
        end

        def _hash_public_entry_value(entry, keys)
          keys.each do |key|
            return entry[key] if entry.key?(key)
          end
          nil
        end

        # Return whether the file resolves to a location inside the real root.
        def _hash_public_inside_root?(file, real_root)
          real_file = ::File.realpath(file)
          prefix = real_root.end_with?(::File::SEPARATOR) ? real_root : "#{real_root}#{::File::SEPARATOR}"
          real_file == real_root || real_file.start_with?(prefix)
        rescue SystemCallError
          # simplecov:disable
          false
          # simplecov:enable
        end

        # Return whether the file matches the expected digest.  Accepts both
        # the URL-safe base64 digest generated by hash_public and a hexadecimal
        # SHA256 digest.
        def _hash_public_digest_match?(file, actual, expected)
          expected = expected.to_s
          return true if actual == expected

          if hash_public_length && expected.start_with?(actual) && expected.length > actual.length
            return true
          end

          if expected =~ /\A[0-9a-fA-F]{64}\z/
            return true if HashPublic::Digest::SHA256.file(file).hexdigest.downcase == expected.downcase
          end

          false
        rescue SystemCallError
          # simplecov:disable
          false
          # simplecov:enable
        end

        # Return the canonical form of a relative path for use as a cache key,
        # or nil if the path is not a safe relative path.  This mirrors the
        # path handling used by the public plugin when serving files.
        def _hash_public_cache_key(path)
          return if path.nil?
          path = path.to_s
          return if path.empty? || path.include?("\0")
          return if path.start_with?('/', '\\') || path =~ /\A[A-Za-z]:/

          segments = path.split(SPLIT)
          return if segments.any?{|segment| segment.empty? || segment == '.' || segment == '..'}

          segments.join('/')
        end

        # Atomically replace the active cache.  When the application is frozen,
        # the options hash cannot be updated, so fall back to replacing the
        # contents of the existing cache object.
        def _install_hash_public_cache(cache)
          new_cache = {}
          cache.each do |path, digest|
            new_cache[path] = digest.freeze
          end

          hash_public_mutex.synchronize do
            _install_hash_public_cache_without_lock(new_cache)
          end

          nil
        end

        def _install_hash_public_cache_without_lock(cache)
          # Keep the active cache in the release state so it can be replaced
          # atomically even when the application is frozen and the options
          # hash can no longer be modified.  The options hash is updated for
          # backwards compatibility when it is still mutable.
          state = hash_public_release_state
          state[:cache] = cache
          opts[:hash_public_cache] = cache unless opts.frozen?
          nil
        end
      end

      module RequestMethods
        # Serve files from the public directory only if the requested digest
        # matches the installed release manifest for the requested path.
        # This keeps previous content-hashed addresses from resolving to the
        # new content after a release switch, and prevents files that are not
        # part of the installed release from being served.
        def hash_public
          generation = roda_class.hash_public_generation
          return super unless generation

          release = generation[:release]

          if is_get?
            on roda_class.hash_public_prefix, String do |digest|
              path = public_path_segments(PARSER.unescape(real_remaining_path)).join('/')
              return unless release[path] == digest

              # Serve only from the generation captured for this request, even
              # if another thread publishes a new release concurrently.  The
              # generation binds the server to the same root as the manifest.
              public_serve_with(generation[:server])
            end
          end
        end
      end
    end

    register_plugin(:hash_public_cache, HashPublicCache)
  end
end
