require 'winrm/http/transport'
require_relative '../support/gssapi_standin'
require_relative '../support/kerberos_iov_contract_helper'

# Offline contract tests for Kerberos message-protection failures and for the
# mutation guard rails that prove the contract has teeth.
#
# Each variant copies the library to a scratch tree, applies one deliberate
# defect, and reruns both contract specs in a child process. Every variant
# must fail the child run.
describe WinRM::HTTP::HttpGSSAPI do
  include KerberosIovContract

  include_context 'kerberos IOV transport'

  describe 'failure handling' do
    it 'raises and reports major/minor status when gss_unwrap_iov fails' do
      GSSAPI::Standin.configure(unwrap_major: 0x9_0000, unwrap_minor: 42)

      expect { transport.send_request(message) }.to raise_error(WinRM::WinRMKerberosError) do |error|
        expect(error.major_status).to eq(0x9_0000)
        expect(error.minor_status).to eq(42)
        expect(error.message).to include('gss_unwrap_iov')
      end

      # A failed unwrap produces no mechanism-owned buffers, so the
      # caller-supplied response header/data must not be released.
      unwrap_addrs = GSSAPI::Standin.unwrap_calls.first[:descriptor_addrs]
      expect(GSSAPI::Standin.release_events.map(&:descriptor_addr) & unwrap_addrs).to be_empty
      expect(GSSAPI::Standin.allocations.select { |a| a.released_at.nil? }).to be_empty
      expect(GSSAPI::Standin.violations).to be_empty
    end

    it 'does not return residual bytes left in the data buffer after a failed unwrap' do
      GSSAPI::Standin.configure(unwrap_major: 0x8_0000, unwrap_minor: 7, residual: 'STALE-PLAINTEXT')

      error = begin
        transport.send_request(message)
        nil
      rescue WinRM::WinRMKerberosError => e
        e
      end

      expect(error).not_to be_nil
      expect(error.message).not_to include('STALE-PLAINTEXT')
      expect(GSSAPI::Standin.allocations.select { |a| a.released_at.nil? }).to be_empty
    end

    it 'refuses a successful unwrap that did not establish confidentiality' do
      GSSAPI::Standin.configure(unwrap_major: 0, unwrap_conf_state: 0, residual: 'UNPROTECTED-BYTES')

      expect { transport.send_request(message) }.to raise_error(WinRM::WinRMKerberosError, /confidentiality/) do |error|
        expect(error.message).not_to include('UNPROTECTED-BYTES')
      end
    end

    it 'raises when gss_wrap_iov fails and does not post a request' do
      GSSAPI::Standin.configure(wrap_major: 0x8_0000, wrap_minor: 3)

      expect { transport.send_request(message) }.to raise_error(WinRM::WinRMKerberosError, /gss_wrap_iov/) do |error|
        expect(error.major_status).to eq(0x8_0000)
        expect(error.minor_status).to eq(3)
      end
      expect(http_client.requests.length).to eq(1) # only the auth handshake
    end

    context 'when the token header length overruns the body' do
      let(:responder_body) do
        "RAW:--Encrypted Boundary\r\nContent-Type: application/octet-stream\r\n" \
          "\x20\x00\x00\x00short--Encrypted Boundary--\r\n"
      end

      it 'raises before calling GSS and never exposes the truncated bytes' do
        expect { transport.send_request(message) }.to raise_error(WinRM::WinRMKerberosError, /header/)
        expect(GSSAPI::Standin.unwrap_calls).to be_empty
      end
    end

    context 'when the token is shorter than its own length prefix' do
      let(:responder_body) do
        "RAW:--Encrypted Boundary\r\nContent-Type: application/octet-stream\r\nabc--Encrypted Boundary--\r\n"
      end

      it 'raises instead of decoding a host-order length' do
        expect { transport.send_request(message) }.to raise_error(WinRM::WinRMKerberosError, /too short/)
      end
    end
  end

  # Guard rails that prove the contract tests have teeth.
  describe 'variant detection', variants: true do
    let(:root) { File.expand_path('../../..', __dir__) }
    let(:scratch) { Dir.mktmpdir('winrm-gss-variant') }

    after { FileUtils.remove_entry(scratch) }

    it 'fails when the GSS unwrap status is ignored' do
      output, status = KerberosIovContract::VariantTree.new(root, scratch).build do |path|
        rewrite_transport(path) do |source|
          source
            .sub("assert_gss_success!('gss_unwrap_iov', maj_stat, min_stat)", '# status ignored')
            .sub("assert_confidentiality!('gss_unwrap_iov', conf_state)", '# confidentiality ignored')
        end
      end
      expect(status).not_to be_success, "variant unexpectedly passed:\n#{output}"
      expect(output).to include('WinRMKerberosError')
    end

    it 'fails when the response buffer is published before unwrap succeeds' do
      output, status = KerberosIovContract::VariantTree.new(root, scratch).build do |path|
        rewrite_transport(path) do |source|
          source.sub(
            "        begin\n          maj_stat = GSSAPI::LibGSSAPI.gss_unwrap_iov(",
            "        premature = iovs[1][:buffer].value.to_s\n" \
            "        begin\n          maj_stat = GSSAPI::LibGSSAPI.gss_unwrap_iov("
          )
        end
      end
      expect(status).not_to be_success, "variant unexpectedly passed:\n#{output}"
    end

    it 'fails when the token length is packed in host byte order' do
      output, status = KerberosIovContract::VariantTree.new(root, scratch).build do |path|
        rewrite_transport(path) { |source| source.sub("[header_len].pack('V')", "[header_len].pack('L')") }
      end
      expect(status).not_to be_success, "variant unexpectedly passed:\n#{output}"
      expect(output).to include('pins the encoding in source')
    end

    it 'fails when IOV buffers are released before their bytes are published' do
      output, status = KerberosIovContract::VariantTree.new(root, scratch).build do |path|
        rewrite_transport(path) do |source|
          source.sub(
            "          assert_confidentiality!('gss_wrap_iov', conf_state)\n",
            "          assert_confidentiality!('gss_wrap_iov', conf_state)\n" \
            "          release_iov(iovs)\n"
          )
        end
      end
      expect(status).not_to be_success, "variant unexpectedly passed:\n#{output}"
    end

    it 'fails when a mechanism allocation is leaked' do
      output, status = KerberosIovContract::VariantTree.new(root, scratch).build do |path|
        rewrite_transport(path) { |source| source.sub('          release_iov(iovs)', '          iovs') }
      end
      expect(status).not_to be_success, "variant unexpectedly passed:\n#{output}"
    end
  end
end
