require 'winrm/http/response_handler'

describe 'response handler', unit: true do
  %w[v1 v2 omi].each do |winrm_version|
    context "winrm_version #{winrm_version}" do
      let(:soap_fault) { stubbed_response("soap_fault_#{winrm_version}.xml") }
      let(:open_shell) { stubbed_response("open_shell_#{winrm_version}.xml") }

      describe "successful 200 #{winrm_version} response" do
        it 'returns an xml doc' do
          handler = WinRM::ResponseHandler.new(open_shell, 200)
          xml_doc = handler.parse_to_xml
          expect(xml_doc).to be_instance_of(REXML::Document)
          expect(xml_doc.to_s).to eq(REXML::Document.new(open_shell).to_s)
        end
      end

      describe "failed 500 #{winrm_version} response" do
        it 'raises a WinRMHTTPTransportError' do
          handler = WinRM::ResponseHandler.new('', 500)
          expect { handler.parse_to_xml }.to raise_error(WinRM::WinRMHTTPTransportError)
        end
      end

      describe "failed 401 #{winrm_version} response" do
        it 'raises a WinRMAuthorizationError' do
          handler = WinRM::ResponseHandler.new('', 401)
          expect { handler.parse_to_xml }.to raise_error(WinRM::WinRMAuthorizationError)
        end
      end

      describe "failed 400 #{winrm_version} response" do
        it 'raises a WinRMWSManFault' do
          handler = WinRM::ResponseHandler.new(soap_fault, 400)
          begin
            handler.parse_to_xml
          # PowerShell
          rescue WinRM::WinRMWSManFault => e
            expect(e.fault_code).to eq('2150858778')
            expect(e.fault_description).to include(
              'The specified class does not exist in the given namespace'
            )
          # OMI
          rescue WinRM::WinRMSoapFault => e
            expect(e.code).to eq('SOAP-ENV:Receiver')
            expect(e.subcode).to eq('wsman:InternalError')
            expect(e.reason).to eq(
              'get-instance: instance name parameter is missing'
            )
          end
        end
      end
    end
  end

  describe 'failed 500 WMI error response' do
    let(:wmi_error) { stubbed_response('wmi_error_v2.xml') }

    it 'raises a WinRMWMIError' do
      handler = WinRM::ResponseHandler.new(wmi_error, 500)
      begin
        handler.parse_to_xml
      rescue WinRM::WinRMWMIError => e
        expect(e.error_code).to eq('2150859173')
        expect(e.error).to include('The WS-Management service cannot process the request.')
      end
    end
  end

  describe 'bounded parsing of untrusted SOAP bodies' do
    let(:billion_laughs) do
      defs = %Q{<!ENTITY e0 "ab">\n}
      1.upto(8) do |i|
        defs += %Q{<!ENTITY e#{i} "#{Array.new(5) { "&e#{i - 1};" }.join}">\n}
      end
      %Q{<!DOCTYPE r [\n#{defs}]><r>&e8;</r>}
    end
    let(:deeply_nested) do
      "<Envelope>#{'<a>' * 300}x#{'</a>' * 300}</Envelope>"
    end
    let(:oversized) { "<Envelope>#{'a' * 600_000}</Envelope>" }
    let(:malformed_namespace) { %q{<Envelope xmlns:1="bad"><Body/></Envelope>} }
    let(:truncated) { '<Envelope><Body>' }

    shared_examples 'a bounded SOAP rejection' do
      it 'raises a WinRMHTTPTransportError rather than returning output' do
        handler = WinRM::ResponseHandler.new(payload, 200)
        expect { handler.parse_to_xml }.to raise_error(
          WinRM::WinRMHTTPTransportError
        ) do |error|
          expect(error.message).to include('Unable to parse WinRM response')
          # The bounded-parser reason is preserved but the raw hostile body is
          # not handed back as normal output.
          expect(error.message).not_to include(payload)
        end
      end

      it 'does not surface a raw REXML or stack error to the caller' do
        handler = WinRM::ResponseHandler.new(payload, 200)
        begin
          handler.parse_to_xml
          raise 'expected a rejection'
        rescue WinRM::WinRMHTTPTransportError
          # expected: low-level parser/stack errors are normalized away
        end
      end
    end

    it_behaves_like 'a bounded SOAP rejection' do
      let(:payload) { billion_laughs }
    end
    it_behaves_like 'a bounded SOAP rejection' do
      let(:payload) { deeply_nested }
    end
    it_behaves_like 'a bounded SOAP rejection' do
      let(:payload) { oversized }
    end
    it_behaves_like 'a bounded SOAP rejection' do
      let(:payload) { malformed_namespace }
    end
    it_behaves_like 'a bounded SOAP rejection' do
      let(:payload) { truncated }
    end

    it 'rejects the same hostile body with a non-200 status before fault XPath work' do
      handler = WinRM::ResponseHandler.new(deeply_nested, 500)
      expect { handler.parse_to_xml }.to raise_error(WinRM::WinRMHTTPTransportError)
    end

    it 'still parses a small well-formed 200 body' do
      benign = '<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope"><Body/></Envelope>'
      handler = WinRM::ResponseHandler.new(benign, 200)
      expect(handler.parse_to_xml).to be_instance_of(REXML::Document)
    end
  end
end
