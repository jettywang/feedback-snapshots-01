# Controlled GSSAPI stand-in for offline Kerberos IOV contract tests.
#
# This file is loaded in place of the real gssapi gem (see
# tests/spec/support/gssapi_standin.rb). It never contacts a KDC and does not
# implement real cryptography. What it models precisely is the FFI calling
# convention the transport depends on: which IOV buffer types the caller
# declares, which native buffers the mechanism allocates, how lengths are
# reported, and who releases what.
require 'ffi'
require_relative 'standin_support/state'

module GSSAPI
  class GssApiError < StandardError; end

  module LibGSSAPI
    extend FFI::Library
    FFI::add_typedef(:uint32, :OM_uint32)

    GSS_IOV_BUFFER_TYPE_DATA      = 1
    GSS_IOV_BUFFER_TYPE_HEADER    = 2
    GSS_IOV_BUFFER_TYPE_TRAILER   = 7
    GSS_IOV_BUFFER_TYPE_PADDING   = 9
    GSS_IOV_BUFFER_TYPE_MASK      = 0xF

    GSS_IOV_BUFFER_FLAG_ALLOCATE  = 0x00010000
    GSS_IOV_BUFFER_FLAG_ALLOCATED = 0x00020000
    GSS_IOV_BUFFER_FLAG_MASK      = 0xFFFF0000

    GSS_C_QOP_DEFAULT = 0
    GSS_S_COMPLETE    = 0

    class UnManagedGssBufferDesc < FFI::Struct
      layout :length, :OM_uint32, :value, :pointer

      def length
        self[:length]
      end

      def value
        return nil if self[:length] == 0
        return nil if self[:value].nil? || self[:value].null?

        GSSAPI::Standin.note_read(self)
        self[:value].read_string(self[:length])
      end

      def value=(val)
        if val.nil?
          self[:length] = 0
          self[:value] = FFI::Pointer::NULL
        else
          bytes = val.to_s
          buffer = FFI::MemoryPointer.from_string(bytes)
          self[:length] = bytes.bytesize
          self[:value] = buffer
          GSSAPI::Standin.note_caller_write(self)
        end
      end
    end

    class GssIOVBufferDesc < FFI::Struct
      layout :type, :OM_uint32, :buffer, UnManagedGssBufferDesc
    end

    class << self
      # The IOV bindings the transport calls. They take the IOV array pointer
      # and count exactly as the real FFI bindings do.
      def gss_wrap_iov(min_stat, context, conf_req, qop, conf_state, iov, iov_count)
        GSSAPI::Standin.wrap_iov(min_stat, context, conf_req, qop, conf_state, iov, iov_count)
      end

      def gss_unwrap_iov(min_stat, context, conf_state, qop_state, iov, iov_count)
        GSSAPI::Standin.unwrap_iov(min_stat, context, conf_state, qop_state, iov, iov_count)
      end

      def gss_release_buffer(min_stat, buffer)
        GSSAPI::Standin.release_buffer(min_stat, buffer)
      end
    end
  end

  class Simple
    attr_reader :context

    def initialize(host_name, service_name = nil, _keytab = nil)
      @host = host_name
      @service = service_name || "host@#{host_name}"
      @context = GSSAPI::Standin::Context.new(@service)
      GSSAPI::Standin.record_init(@service)
    end

    def init_context(in_token = nil)
      GSSAPI::Standin.complete_context(@context, in_token)
    end
  end
end
