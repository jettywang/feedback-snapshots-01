# Native-allocation and call bookkeeping for the offline GSSAPI stand-in.
#
# Every buffer the stand-in hands to the transport is registered here with an
# owner. Contract specs use the registry to prove that mechanism-allocated
# memory is released exactly once, that caller-supplied buffers are never
# released, and that no IOV payload is read before the GSS call that fills it
# or after it has been freed.
module GSSAPI
  module Standin
    Allocation = Struct.new(
      :descriptor_addr, :buffer_addr, :purpose, :size, :created_at, :released_at,
      keyword_init: true
    )
    ReleaseEvent = Struct.new(:descriptor_addr, :buffer_addr, :purpose, :at, keyword_init: true)
    ReadEvent = Struct.new(:descriptor_addr, :at, :released, :before_call, keyword_init: true)
    Context = Struct.new(:service)

    DEFAULT_CONFIG = {
      header_length: 32,
      padding_length: 5,
      wrap_major: 0,
      wrap_minor: 0,
      wrap_conf_state: 1,
      unwrap_major: 0,
      unwrap_minor: 0,
      unwrap_conf_state: 1,
      residual: 'STALE-PLAINTEXT-FROM-A-PREVIOUS-MESSAGE'
    }.freeze

    class << self
      attr_reader :config, :wrap_calls, :unwrap_calls, :allocations,
                  :release_events, :read_events, :violations, :services,
                  :caller_buffers

      def reset!
        @config = DEFAULT_CONFIG.dup
        @wrap_calls = []
        @unwrap_calls = []
        @allocations = []
        @caller_buffers = []
        @release_events = []
        @read_events = []
        @violations = []
        @services = []
        @called_descriptors = []
        @sequence = 0
        @phase = :idle
      end

      def configure(**overrides)
        unknown = overrides.keys - DEFAULT_CONFIG.keys
        raise ArgumentError, "unknown stand-in config: #{unknown.inspect}" unless unknown.empty?

        @config.merge!(overrides)
      end

      def wrap_iov(min_stat, _context, conf_req, qop, conf_state, iov, iov_count)
        descriptors = descriptors_for(iov, iov_count)
        record_call(descriptors)
        requested = descriptors.map { |desc| desc[:type] }
        @phase = :wrap

        data = descriptors[1][:buffer].value.to_s
        record = {
          iov_count: iov_count,
          types: requested,
          data: data,
          conf_req: conf_req,
          qop: qop,
          descriptor_addrs: descriptors.map { |desc| desc[:buffer].pointer.address },
          status: nil
        }
        @wrap_calls << record

        if config[:wrap_major] != GSSAPI::LibGSSAPI::GSS_S_COMPLETE
          min_stat.write_uint32(config[:wrap_minor])
          conf_state.write_uint32(0)
          record[:status] = config[:wrap_major]
          return finish_call(config[:wrap_major])
        end

        header = build_header(data.bytesize, config[:padding_length], config[:header_length])
        allocate(descriptors[0], header, :request_header)
        overwrite_caller_buffer(descriptors[1], protect_bytes(data))
        apply_padding(descriptors[2], config[:padding_length])

        conf_state.write_uint32(config[:wrap_conf_state])
        min_stat.write_uint32(config[:wrap_minor])
        record[:status] = GSSAPI::LibGSSAPI::GSS_S_COMPLETE
        record[:header_length] = header.bytesize
        record[:padding_length] = config[:padding_length]
        finish_call(GSSAPI::LibGSSAPI::GSS_S_COMPLETE)
      end

      def unwrap_iov(min_stat, _context, conf_state, qop_state, iov, iov_count)
        descriptors = descriptors_for(iov, iov_count)
        record_call(descriptors)
        requested = descriptors.map { |desc| desc[:type] }
        @phase = :unwrap

        header = descriptors[0][:buffer].value.to_s
        data = descriptors[1][:buffer].value.to_s
        record = {
          iov_count: iov_count,
          types: requested,
          header: header,
          data: data,
          descriptor_addrs: descriptors.map { |desc| desc[:buffer].pointer.address },
          status: nil
        }
        @unwrap_calls << record

        if config[:unwrap_major] != GSSAPI::LibGSSAPI::GSS_S_COMPLETE ||
           config[:unwrap_conf_state] == 0
          return fail_unwrap(min_stat, conf_state, qop_state, descriptors, record)
        end

        # The response header is caller-supplied input; only the plaintext
        # data buffer is written.
        overwrite_caller_buffer(descriptors[1], plaintext_from(header, data))
        conf_state.write_uint32(1)
        qop_state.write_uint32(0)
        min_stat.write_uint32(config[:unwrap_minor])
        record[:status] = GSSAPI::LibGSSAPI::GSS_S_COMPLETE
        finish_call(GSSAPI::LibGSSAPI::GSS_S_COMPLETE)
      end

      def release_buffer(min_stat, buffer_pointer)
        descriptor_addr = buffer_pointer.address
        allocation = @allocations.reverse.find do |candidate|
          candidate.descriptor_addr == descriptor_addr && candidate.released_at.nil?
        end

        unless allocation
          @violations << "gss_release_buffer on unowned or already released descriptor 0x#{descriptor_addr.to_s(16)}"
          min_stat.write_uint32(0)
          return GSSAPI::LibGSSAPI::GSS_S_COMPLETE
        end

        if allocation.created_at > @sequence
          @violations << "gss_release_buffer before the owning gss_* call returned"
        end

        allocation.released_at = tick
        @release_events << ReleaseEvent.new(
          descriptor_addr: descriptor_addr,
          buffer_addr: allocation.buffer_addr,
          purpose: allocation.purpose,
          at: allocation.released_at
        )

        descriptor = GSSAPI::LibGSSAPI::UnManagedGssBufferDesc.new(buffer_pointer)
        descriptor[:length] = 0
        descriptor[:value] = FFI::Pointer::NULL
        min_stat.write_uint32(0)
        GSSAPI::LibGSSAPI::GSS_S_COMPLETE
      end

      # Records caller-owned native buffers. The transport assigns these
      # (message data, response header, response payload) before GSS runs.
      def note_caller_write(descriptor)
        return unless @phase == :idle

        addr = descriptor.pointer.address
        return if @caller_buffers.any? { |entry| entry.descriptor_addr == addr }

        @caller_buffers << Allocation.new(
          descriptor_addr: addr,
          buffer_addr: descriptor[:value].address,
          purpose: :caller_data,
          size: descriptor[:length],
          created_at: tick,
          released_at: nil
        )
      end

      # Called from the stand-in buffer's #value reader. Reads made while the
      # stand-in itself is inside a call are ignored; reads by the transport
      # after a call returns are what the contract cares about.
      def note_read(descriptor)
        return unless @phase == :idle

        descriptor_addr = descriptor.pointer.address
        released = @allocations.any? do |allocation|
          allocation.descriptor_addr == descriptor_addr && !allocation.released_at.nil?
        end
        before_call = !@called_descriptors.include?(descriptor_addr)
        @read_events << ReadEvent.new(
          descriptor_addr: descriptor_addr,
          at: tick,
          released: released,
          before_call: before_call
        )
        @violations << "read from released IOV buffer 0x#{descriptor_addr.to_s(16)}" if released
        @violations << "read from IOV buffer 0x#{descriptor_addr.to_s(16)} before its gss_* call" if before_call
      end

      def record_init(service)
        @services << service
      end

      def complete_context(_context, in_token)
        in_token.nil? ? 'client-initial-context-token' : true
      end

      # Builds a server-side token with the same header layout used on the
      # request path, optionally with padding the transport must account for.
      def protect(plaintext, padding: 0)
        header = build_header(plaintext.bytesize, padding, config[:header_length])
        token = [header.bytesize].pack('V') + header + protect_bytes(plaintext)
        token += ("\xAA" * padding) if padding > 0
        token
      end

      private

      def record_call(descriptors)
        @called_descriptors = descriptors.map { |desc| desc[:buffer].pointer.address }
      end

      def finish_call(status)
        @phase = :idle
        status
      end

      def fail_unwrap(min_stat, conf_state, qop_state, descriptors, record)
        min_stat.write_uint32(config[:unwrap_minor])
        conf_state.write_uint32(0)
        qop_state.write_uint32(0)
        # Deliberately leave stale bytes in the data descriptor. A variant that
        # returns the buffer without honouring the status or conf_state exposes
        # this text instead of raising.
        overwrite_caller_buffer(descriptors[1], config[:residual])
        record[:status] = config[:unwrap_major]
        finish_call(config[:unwrap_major])
      end

      def tick
        @sequence += 1
      end

      def descriptors_for(iov, count)
        size = GSSAPI::LibGSSAPI::GssIOVBufferDesc.size
        base = iov.address
        (0...count).map do |index|
          GSSAPI::LibGSSAPI::GssIOVBufferDesc.new(FFI::Pointer.new(base + (size * index)))
        end
      end

      def build_header(data_length, padding_length, header_length)
        if header_length < 8
          raise ArgumentError, 'stand-in header length must be at least 8 bytes'
        end

        [data_length, padding_length].pack('VV') + ("H" * (header_length - 8))
      end

      def plaintext_from(header, data)
        data_length, padding_length = header.unpack('VV')
        expected = data_length + padding_length
        if data.bytesize != expected
          @violations << "response data length #{data.bytesize} does not match header length #{expected}"
        end
        protect_bytes(data).byteslice(0, data_length).to_s
      end

      def protect_bytes(bytes)
        bytes.to_s.bytes.map { |byte| byte ^ 0x5A }.pack('C*')
      end

      def allocate(descriptor, bytes, purpose)
        buffer = FFI::MemoryPointer.from_string(bytes)
        descriptor[:buffer][:length] = bytes.bytesize
        descriptor[:buffer][:value] = buffer
        descriptor[:type] = descriptor[:type] | GSSAPI::LibGSSAPI::GSS_IOV_BUFFER_FLAG_ALLOCATED
        @allocations << Allocation.new(
          descriptor_addr: descriptor[:buffer].pointer.address,
          buffer_addr: buffer.address,
          purpose: purpose,
          size: bytes.bytesize,
          created_at: tick,
          released_at: nil
        )
      end

      # Writes into the caller's existing native buffer where possible, which
      # preserves the caller-owns-DATA relationship real GSS uses.
      def overwrite_caller_buffer(descriptor, bytes)
        buffer = descriptor[:buffer]
        if buffer[:value].nil? || buffer[:value].null? || bytes.bytesize > buffer[:length]
          buffer[:value] = FFI::MemoryPointer.from_string(bytes)
        else
          buffer[:value].put_bytes(0, bytes.to_s)
        end
        buffer[:length] = bytes.bytesize
      end

      def apply_padding(descriptor, padding_length)
        return if padding_length <= 0

        allocate(descriptor, "\xAA" * padding_length, :request_padding)
      end
    end
  end
end

GSSAPI::Standin.reset!
