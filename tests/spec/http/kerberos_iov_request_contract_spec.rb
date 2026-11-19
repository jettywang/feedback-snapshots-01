require 'winrm/http/transport'
require_relative '../support/gssapi_standin'
require_relative '../support/kerberos_iov_contract_helper'

# Offline contract tests for the request side of Kerberos message protection.
#
# These specs drive the real WinRM::HTTP::HttpGSSAPI transport and observe the
# HTTP request it builds. GSSAPI is replaced by a controlled stand-in that
# records every IOV descriptor, length, and native allocation, so the contract
# can be checked without a Kerberos realm.
describe WinRM::HTTP::HttpGSSAPI do
  include KerberosIovContract

  include_context 'kerberos IOV transport'

  describe 'IOV buffer contract on the request path' do
    it 'declares header/data/padding buffers with the mechanism allocating header and padding' do
      transport.send_request(message)

      expect(GSSAPI::Standin.wrap_calls.length).to eq(1)
      call = GSSAPI::Standin.wrap_calls.first
      expect(call[:iov_count]).to eq(3)
      expect(call[:types].map { |type| type & 0xF }).to eq([2, 1, 9])
      expect(call[:types][0] & 0xFFFF0000).to eq(0x00010000)
      expect(call[:types][1] & 0xFFFF0000).to eq(0)
      expect(call[:types][2] & 0xFFFF0000).to eq(0x00010000)
      expect(call[:conf_req]).to eq(1)
      expect(call[:data]).to eq(message.b)
    end

    it 'reports the original message length and padding to the server' do
      GSSAPI::Standin.configure(padding_length: 7, header_length: 24)
      transport.send_request(message)

      request = http_client.requests.last
      expect(request[:headers]['Content-Type']).to include('application/HTTP-Kerberos-session-encrypted')
      expected_length = message.bytesize + 7
      expect(posted_body(request)).to include(
        "OriginalContent: type=application/soap+xml;charset=UTF-8;Length=#{expected_length}"
      )

      header_len, header, data = request_token(request)
      expect(header_len).to eq(24)
      expect(header.unpack1('V')).to eq(message.bytesize)
      expect(header.unpack('VV')[1]).to eq(7)
      expect(data.bytesize).to eq(message.bytesize + 7)
    end

    it 'offsets each IOV descriptor by exactly one struct size' do
      transport.send_request(message)

      addresses = GSSAPI::Standin.wrap_calls.first[:descriptor_addrs]
      size = GSSAPI::LibGSSAPI::GssIOVBufferDesc.size
      expect(addresses[1] - addresses[0]).to eq(size)
      expect(addresses[2] - addresses[1]).to eq(size)
    end
  end

  describe 'wire length encoding' do
    it 'writes the header length as a fixed little-endian uint32' do
      GSSAPI::Standin.configure(header_length: 61)
      transport.send_request(message)

      payload = encrypted_payload(http_client.requests.last)
      expect(payload.unpack('C4')).to eq([61, 0, 0, 0])
      expect(payload.byteslice(0, 4).unpack1('V')).to eq(61)
    end

    it 'pins the encoding in source rather than relying on the host byte order' do
      source = File.read(File.expand_path('../../../lib/winrm/http/transport.rb', __dir__))

      # On a little-endian host `pack('L')` would pass the runtime assertion
      # above, so also require the explicit little-endian directive.
      expect(source).to include("token = [header_len].pack('V')")
      expect(source).to include("body.unpack1('V')")
      expect(source).not_to match(/\[header_len\]\.pack\('L'\)/)
      expect(source).not_to match(/body\.unpack1\('L'\)/)
    end

    it 'parses the response length prefix as little-endian data' do
      GSSAPI::Standin.configure(header_length: 12)
      result = transport.send_request(message)

      expect(result).to be_a(REXML::Document)
      expect(GSSAPI::Standin.unwrap_calls.first[:header].bytesize).to eq(12)
      expect(GSSAPI::Standin.violations).to be_empty
    end
  end

  describe 'native allocation ownership' do
    it 'releases every mechanism-allocated header and padding buffer exactly once' do
      GSSAPI::Standin.configure(header_length: 20, padding_length: 3)
      transport.send_request(message)

      wrap_allocs = GSSAPI::Standin.allocations.select { |a| %i[request_header request_padding].include?(a.purpose) }
      expect(wrap_allocs.map(&:purpose)).to contain_exactly(:request_header, :request_padding)
      expect(wrap_allocs.map { |a| a.released_at.nil? }).to eq([false, false])

      released = GSSAPI::Standin.release_events.map(&:descriptor_addr)
      expect(released).to match_array(wrap_allocs.map(&:descriptor_addr))
      expect(released.length).to eq(released.uniq.length)
      expect(GSSAPI::Standin.violations).to be_empty
    end

    it 'releases each mechanism buffer only after its bytes were copied out' do
      GSSAPI::Standin.configure(header_length: 20, padding_length: 3)
      transport.send_request(message)

      released_purposes = GSSAPI::Standin.release_events.map(&:purpose)
      expect(released_purposes).to contain_exactly(:request_header, :request_padding)

      GSSAPI::Standin.allocations.each do |allocation|
        next if allocation.released_at.nil?

        reads = GSSAPI::Standin.read_events.select do |event|
          event.descriptor_addr == allocation.descriptor_addr
        end
        # The buffer must actually have been copied out, and that copy must
        # precede the release; freeing first would read freed native memory.
        expect(reads).not_to be_empty
        expect(reads.map(&:at)).to all(be < allocation.released_at)
      end
    end

    it 'never releases caller-supplied data buffers' do
      transport.send_request(message)

      caller_addrs = GSSAPI::Standin.caller_buffers.map(&:descriptor_addr)
      expect(caller_addrs).not_to be_empty
      released = GSSAPI::Standin.release_events.map(&:descriptor_addr)
      expect(released & caller_addrs).to be_empty
      expect(GSSAPI::Standin.violations).to be_empty
    end

    it 'does not consume IOV payload before the GSS call supplies it' do
      transport.send_request(message)

      expect(GSSAPI::Standin.read_events.select(&:before_call)).to be_empty
      expect(GSSAPI::Standin.read_events.select(&:released)).to be_empty
    end
  end

  describe 'non-zero padding and header sizes' do
    [0, 1, 7, 13].each do |padding|
      it "round-trips with padding=#{padding}" do
        GSSAPI::Standin.configure(padding_length: padding, header_length: 24)
        expect(transport.send_request(message)).to be_a(REXML::Document)
        expect(GSSAPI::Standin.violations).to be_empty
      end
    end

    [8, 12, 40, 64].each do |header_length|
      it "round-trips with header_length=#{header_length}" do
        GSSAPI::Standin.configure(header_length: header_length)
        transport.send_request(message)
        expect(GSSAPI::Standin.violations).to be_empty
      end
    end
  end
end
