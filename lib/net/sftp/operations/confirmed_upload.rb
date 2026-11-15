require 'digest'
require 'pathname'
require 'securerandom'
require 'net/sftp/constants'
require 'net/sftp/response'
require 'net/sftp/errors'

module Net; module SFTP; module Operations

  # Uploads a file to a staging path and moves it to its final path only after
  # the server acknowledges every WRITE, the CLOSE, and (when requested) a
  # verification step. Unlike #upload!, it does not collapse those events into
  # a single "delivered" claim.
  #
  #   result = sftp.confirmed_upload!("/local/file", "/remote/file")
  #   if result.published?
  #     notify_business(result.notification)
  #   else
  #     alert_business(result.notification)
  #   end
  #
  # It is important not to read more into the steps than the protocol gives:
  #
  # * A WRITE STATUS OK means the server accepted that chunk at the SFTP
  #   layer. It does not mean the bytes reached stable storage, and a failed
  #   write can occur after earlier writes were already accepted.
  # * CLOSE STATUS OK means the handle was closed. It does not fsync data or
  #   the containing directory.
  # * fsync@openssh.com, when advertised, asks the server to fsync(2) the file
  #   before the handle is closed. It says nothing about the parent directory
  #   entry, so directory-entry durability remains unknown.
  # * A read-back digest confirms what the server returned through SFTP, not
  #   what is on disk after a crash.
  # * posix-rename@openssh.com gives rename(2)-style replacement of the final
  #   path. Its atomicity with respect to other clients is a server property;
  #   durability of the new directory entry is still unknown.
  #
  # When a capability is missing, the result degrades to the facts that were
  # confirmed. If the final path is not switched, the staging file is retained
  # by default so it can be inspected or retried.
  #
  # Options:
  #
  # * <tt>:staging_path</tt> - use this path instead of a random hidden
  #   sibling of +remote+. The file is opened exclusively.
  # * <tt>:read_size</tt> - bytes per WRITE request (default 32,000).
  # * <tt>:verify</tt> - +:size+ (default), +:readback+ (SHA-256 of the bytes
  #   read back through SFTP), or +:none+.
  # * <tt>:preserve</tt> - copy permissions and times from a local file.
  # * <tt>:cleanup</tt> - +:on_failure+ to remove the staging file when
  #   publishing does not happen. The default is +:retain+.
  # * <tt>:progress</tt> - a callable or an object with +on_put+.
  class ConfirmedUpload
    DEFAULT_READ_SIZE = 32_000
    POSIX_RENAME_EXTENSION = "posix-rename@openssh.com".freeze
    FSYNC_EXTENSION = "fsync@openssh.com".freeze

    # The source of the upload (a path or an IO object)
    attr_reader :local

    # The final remote path
    attr_reader :remote

    # The remote path used before the final rename
    attr_reader :staging_path

    # The options supplied at construction
    attr_reader :options

    # The Net::SFTP session used by this operation
    attr_reader :sftp

    def initialize(sftp, local, remote, options={}, &progress)
      local = local.to_path if local.is_a?(Pathname)
      remote = remote.to_path if remote.is_a?(Pathname)

      @sftp = sftp
      @local = local
      @remote = remote
      @options = options
      @progress = progress || options[:progress]
      @staging_path = options[:staging_path]
      @read_size = positive_option(:read_size, DEFAULT_READ_SIZE)
      @verify = (options[:verify] || :size).to_sym
      unless [:size, :readback, :none].include?(@verify)
        raise ArgumentError, ":verify must be :size, :readback or :none"
      end

      @cleanup = (options[:cleanup] || :retain).to_sym
      unless [:retain, :on_failure].include?(@cleanup)
        raise ArgumentError, ":cleanup must be :retain or :on_failure"
      end
    end

    # Runs the flow and returns the operation. Inspect #result afterwards.
    # Status failures are recorded in the result instead of raised, because
    # the caller needs to know whether the final path changed.
    def wait
      @result = run
      self
    end

    # The result of the flow. Raises if #wait has not been called.
    def result
      @result || raise("call #wait before inspecting the result")
    end

    # A snapshot of the facts the client could observe. It is deliberately
    # not a single "delivered" boolean.
    class Result
      # :failed, :partial, :staged, :published or :unknown
      attr_reader :state

      # :confirmed, :failed, :unknown or :not_attempted
      attr_reader :open, :close

      # :confirmed, :failed, :unsupported, :unknown or :not_attempted
      attr_reader :rename

      # :confirmed, :failed, :fsync_unsupported, :unknown or :not_attempted
      attr_reader :fsync

      # :not_requested, :size_confirmed, :digest_confirmed, :mismatch,
      # :failed or :not_attempted
      attr_reader :verification

      # :confirmed or :not_observed. This is an observable SSH authentication
      # hint, not a per-operation authorization proof.
      attr_reader :ssh_authentication

      # :file_data_flushed, :fsync_failed, :fsync_unsupported,
      # :not_confirmed or :unknown
      attr_reader :durability

      # Always :unknown: this flow never fsyncs the containing directory.
      attr_reader :directory_entry_durability

      # :renamed, :retained, :removed, :failed, :not_attempted or :unknown
      attr_reader :staging_cleanup

      # The final and staging paths.
      attr_reader :remote, :staging_path

      # Bytes read from the source and bytes acknowledged by WRITE STATUS OK.
      attr_reader :bytes_from_source, :bytes_confirmed

      # The source size when it was known before reading (a file's stat size
      # or an IO's size), otherwise nil.
      attr_reader :source_size

      # WRITE requests sent and WRITE STATUS OK replies received.
      attr_reader :writes_sent, :writes_confirmed

      # SHA-256 of the source and of the read-back staging content when
      # +:readback+ verification was used.
      attr_reader :source_digest, :remote_digest

      # The exceptions for each stage, when there was one.
      attr_reader :source_error, :open_error, :write_error, :fsync_error,
                  :close_error, :verify_error, :rename_error

      def initialize(fields={})
        fields.each { |name, value| instance_variable_set("@#{name}", value) }
        @state ||= :failed
        @open ||= :not_attempted
        @fsync ||= :not_attempted
        @close ||= :not_attempted
        @rename ||= :not_attempted
        @verification ||= :not_attempted
        @ssh_authentication ||= :not_observed
        @durability ||= :unknown
        @directory_entry_durability = :unknown
        @staging_cleanup ||= :not_attempted
        @writes_sent ||= 0
        @writes_confirmed ||= 0
        @bytes_from_source ||= 0
        @bytes_confirmed ||= 0
      end

      # The final path was switched after a successful close and verification.
      # This is a fact about the remote namespace, not about crash durability.
      def published?
        state == :published
      end

      # The content was checked against the source (size or digest).
      def verified?
        [:size_confirmed, :digest_confirmed].include?(verification)
      end

      # Every WRITE sent was acknowledged, the acknowledged byte count equals
      # the number of bytes read from the source, and the source was read to
      # its known end.
      def all_writes_confirmed?
        writes_sent == writes_confirmed &&
          bytes_from_source == bytes_confirmed &&
          (source_size.nil? || bytes_from_source == source_size)
      end

      # All writes acknowledged, CLOSE confirmed, and verification succeeded.
      # This does not imply that the final path was switched; see #published?.
      def content_confirmed?
        all_writes_confirmed? && close == :confirmed && verified?
      end

      # The server confirmed fsync@openssh.com for the file data. The
      # directory entry was not fsynced.
      def file_data_flushed?
        fsync == :confirmed
      end

      # A business-facing sentence that states the confirmed facts and their
      # limits. It is safe to send this only after #wait has returned.
      def notification
        facts = "#{bytes_confirmed}/#{bytes_from_source} bytes acknowledged, " \
                "close #{close}, verification #{verification}, " \
                "rename #{rename}, fsync #{fsync}"

        case state
        when :published
          suffix = if file_data_flushed?
            "server fsynced the file data; the directory entry durability is unknown"
          else
            "file data durability is not confirmed"
          end
          "published at #{remote} (#{facts}); #{suffix}"
        when :staged
          retained = verified? ? "verified staging file" : "staging file"
          case staging_cleanup
          when :retained
            "not published; #{retained} retained at #{staging_path} (#{facts})"
          when :removed
            "not published; staging file removed (#{facts})"
          when :failed
            "not published; staging cleanup failed (#{facts})"
          else
            "not published; final path not switched (#{facts})"
          end
        when :partial
          suffix = staging_cleanup == :retained ? "; staging file retained at #{staging_path}" : ""
          "not published; transfer incomplete (#{facts})#{suffix}"
        when :unknown
          "outcome unknown; the final path may or may not have changed (#{facts})"
        else
          "not published; the transfer failed (#{facts})"
        end
      end

      # The facts as a hash, suitable for logs or a queue payload.
      def to_h
        {
          state: state,
          remote: remote,
          staging_path: staging_path,
          bytes_from_source: bytes_from_source,
          bytes_confirmed: bytes_confirmed,
          writes_sent: writes_sent,
          writes_confirmed: writes_confirmed,
          source_size: source_size,
          open: open,
          fsync: fsync,
          close: close,
          verification: verification,
          rename: rename,
          ssh_authentication: ssh_authentication,
          durability: durability,
          directory_entry_durability: directory_entry_durability,
          staging_cleanup: staging_cleanup,
          source_digest: source_digest,
          remote_digest: remote_digest,
          errors: {
            source: error_text(source_error),
            open: error_text(open_error),
            write: error_text(write_error),
            fsync: error_text(fsync_error),
            close: error_text(close_error),
            verify: error_text(verify_error),
            rename: error_text(rename_error)
          }.reject { |_name, value| value.nil? }
        }
      end

      private

        def error_text(error)
          error && "#{error.class}: #{error.message}"
        end
    end

    private

      def positive_option(name, default)
        value = (options[name] || default).to_i
        raise ArgumentError, ":#{name} must be positive" unless value > 0

        value
      end

      def run
        fields = {
          remote: remote,
          staging_path: staging_path || fresh_staging_path,
          ssh_authentication: ssh_authentication_evidence,
          fsync: extension?(FSYNC_EXTENSION) ? :not_attempted : :fsync_unsupported,
          rename: extension?(POSIX_RENAME_EXTENSION) ? :not_attempted : :unsupported,
          staging_cleanup: :not_attempted,
          bytes_from_source: 0,
          bytes_confirmed: 0,
          writes_sent: 0,
          writes_confirmed: 0
        }
        @staging_path = fields[:staging_path]

        source = open_source(fields)
        return Result.new(fields) unless source

        handle = open_staging(fields)
        unless handle
          close_source(source)
          return Result.new(fields)
        end

        begin
          write_source(source, handle, fields)
        ensure
          close_source(source)
        end

        if fields[:write_error] && session_lost?(fields[:write_error])
          return Result.new(fields.merge(
            state: fields[:bytes_confirmed] > 0 ? :partial : :failed,
            close: :not_attempted,
            staging_cleanup: :unknown,
            durability: :unknown
          ))
        end

        fsync_confirmed = transfer_failed?(fields) ? false : fsync_file(handle, fields)
        close_confirmed = close_handle(handle, fields)

        if transfer_failed?(fields)
          fields[:state] = fields[:bytes_confirmed] > 0 ? :partial : :failed
          fields[:durability] = fsync_confirmed ? :file_data_flushed : :unknown
          cleanup_staging(fields)
          return Result.new(fields)
        end

        if fields[:fsync] == :unknown
          fields[:state] = :partial
          fields[:durability] = :unknown
          cleanup_staging(fields)
          return Result.new(fields)
        end

        if fields[:fsync] == :failed
          fields[:state] = :partial
          fields[:durability] = :fsync_failed
          cleanup_staging(fields)
          return Result.new(fields)
        end

        unless close_confirmed
          fields[:state] = :partial
          fields[:durability] = fields[:close] == :unknown ? :unknown :
            (fsync_confirmed ? :file_data_flushed : :unknown)
          cleanup_staging(fields)
          return Result.new(fields)
        end

        verify_staging(fields)
        if [:failed, :mismatch].include?(fields[:verification])
          fields[:state] = :partial
          fields[:durability] = fsync_confirmed ? :file_data_flushed : :unknown
          cleanup_staging(fields)
          return Result.new(fields)
        end

        fields[:state] = :staged
        fields[:durability] = fsync_confirmed ? :file_data_flushed : :fsync_unsupported

        if fields[:rename] == :unsupported
          fields[:state] = :staged
          return Result.new(fields)
        end

        begin
          sftp.posix_rename!(@staging_path, remote)
          fields[:rename] = :confirmed
          fields[:state] = :published
          fields[:staging_cleanup] = :renamed
        rescue Net::SFTP::StatusException => error
          fields[:rename] = :failed
          fields[:rename_error] = error
          fields[:state] = :staged
        rescue Net::SFTP::SessionClosedError => error
          fields[:rename] = :failed
          fields[:rename_error] = error
          fields[:state] = :unknown
          fields[:staging_cleanup] = :unknown
          fields[:durability] = :unknown
        end

        Result.new(fields)
      end

      def open_source(fields)
        if local.respond_to?(:read)
          if local.respond_to?(:size)
            position = local.respond_to?(:pos) ? local.pos : 0
            fields[:source_size] = local.size - position
          end
          local
        else
          file = ::File.open(local, "rb")
          fields[:source_size] = file.stat.size
          file
        end
      rescue IOError, SystemCallError => error
        fields[:source_error] = error
        fields[:state] = :failed
        nil
      end

      def close_source(source)
        source.close unless source.equal?(local)
      rescue IOError, SystemCallError
        nil
      end

      def open_staging(fields)
        mode = ::IO::WRONLY | ::IO::CREAT | ::IO::EXCL
        handle = sftp.open!(@staging_path, mode, source_attributes)
        fields[:open] = :confirmed
        fields[:staging_cleanup] = :retained
        handle
      rescue Net::SFTP::StatusException => error
        fields[:open] = :failed
        fields[:open_error] = error
        fields[:state] = :failed
        nil
      rescue Net::SFTP::SessionClosedError => error
        fields[:open] = :failed
        fields[:open_error] = error
        fields[:state] = :failed
        nil
      end

      def write_source(source, handle, fields)
        digest = Digest::SHA256.new if @verify == :readback
        offset = 0

        loop do
          begin
            chunk = source.read(@read_size)
          rescue IOError, SystemCallError => error
            fields[:source_error] = error
            break
          end
          break if chunk.nil? || chunk.empty?

          digest << chunk if digest
          fields[:bytes_from_source] += chunk.bytesize
          fields[:writes_sent] += 1
          progress(:put, offset, chunk)

          begin
            sftp.write!(handle, offset, chunk)
            fields[:bytes_confirmed] += chunk.bytesize
            fields[:writes_confirmed] += 1
            offset += chunk.bytesize
          rescue Net::SFTP::StatusException => error
            fields[:write_error] = error
            break
          rescue Net::SFTP::SessionClosedError => error
            fields[:write_error] = error
            break
          end
        end

        fields[:source_digest] = digest.hexdigest if digest
      end

      def fsync_file(handle, fields)
        return false if fields[:fsync] == :fsync_unsupported

        sftp.fsync!(handle)
        fields[:fsync] = :confirmed
        true
      rescue Net::SFTP::StatusException => error
        fields[:fsync] = :failed
        fields[:fsync_error] = error
        false
      rescue Net::SFTP::SessionClosedError => error
        fields[:fsync] = :unknown
        fields[:fsync_error] = error
        false
      end

      def close_handle(handle, fields)
        sftp.close!(handle)
        fields[:close] = :confirmed
        true
      rescue Net::SFTP::StatusException => error
        fields[:close] = :failed
        fields[:close_error] = error
        false
      rescue Net::SFTP::SessionClosedError => error
        fields[:close] = :unknown
        fields[:close_error] = error
        false
      end

      def verify_staging(fields)
        case @verify
        when :none
          fields[:verification] = :not_requested
        when :size
          begin
            attrs = sftp.stat!(@staging_path)
            expected = fields[:source_size] || fields[:bytes_from_source]
            if attrs.size == expected
              fields[:verification] = :size_confirmed
            else
              fields[:verification] = :mismatch
              fields[:verify_error] = "expected #{expected} bytes, " \
                                      "server reports #{attrs.size.inspect}"
            end
          rescue Net::SFTP::StatusException, Net::SFTP::SessionClosedError => error
            fields[:verification] = :failed
            fields[:verify_error] = error
          end
        when :readback
          begin
            read_handle = sftp.open!(@staging_path, "r")
            begin
              digest = Digest::SHA256.new
              offset = 0
              while (chunk = sftp.read!(read_handle, offset, @read_size))
                digest << chunk
                offset += chunk.bytesize
              end
            ensure
              sftp.close!(read_handle)
            end

            fields[:remote_digest] = digest.hexdigest
            if fields[:remote_digest] == fields[:source_digest] &&
               offset == fields[:bytes_from_source] &&
               (fields[:source_size].nil? || offset == fields[:source_size])
              fields[:verification] = :digest_confirmed
            else
              fields[:verification] = :mismatch
              fields[:verify_error] = "read-back content did not match the source"
            end
          rescue Net::SFTP::StatusException, Net::SFTP::SessionClosedError,
                 IOError, SystemCallError => error
            fields[:verification] = :failed
            fields[:verify_error] = error
          end
        end
      end

      def cleanup_staging(fields)
        return unless @cleanup == :on_failure
        return if @staging_path.nil?

        sftp.remove!(@staging_path)
        fields[:staging_cleanup] = :removed
      rescue Net::SFTP::StatusException, Net::SFTP::SessionClosedError
        fields[:staging_cleanup] = :failed
      end

      def source_attributes
        return {} if local.respond_to?(:read)

        stat = ::File.stat(local)
        attributes = { :permissions => stat.mode & 0777 }
        attributes[:atime] = stat.atime.to_i if options[:preserve]
        attributes[:mtime] = stat.mtime.to_i if options[:preserve]
        attributes
      rescue IOError, SystemCallError
        {}
      end

      def fresh_staging_path
        dir = ::File.dirname(remote)
        base = ::File.basename(remote)
        ::File.join(dir, ".#{base}.net-sftp-#{SecureRandom.hex(16)}.part")
      end

      def extension?(name)
        sftp.respond_to?(:extension?) ? sftp.extension?(name) : sftp.extensions.key?(name)
      end

      def session_lost?(error)
        error.is_a?(Net::SFTP::SessionClosedError)
      end

      def transfer_failed?(fields)
        fields[:write_error] || fields[:source_error]
      end

      def ssh_authentication_evidence
        connection = sftp.respond_to?(:session) ? sftp.session : nil
        transport = connection.respond_to?(:transport) ? connection.transport : nil
        socket = transport.respond_to?(:socket) ? transport.socket : nil
        hints = socket.respond_to?(:hints) ? socket.hints : nil
        hints && hints[:authenticated] ? :confirmed : :not_observed
      rescue StandardError
        :not_observed
      end

      def progress(event, offset, data)
        return unless @progress
        if @progress.respond_to?(:on_put)
          @progress.on_put(self, nil, offset, data)
        elsif @progress.respond_to?(:call)
          @progress.call(event, self, nil, offset, data)
        end
      end
  end

end; end; end
