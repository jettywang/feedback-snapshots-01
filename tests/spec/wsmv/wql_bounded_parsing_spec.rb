require 'winrm/wsmv/wql_query'
require 'winrm/wsmv/wql_pull'

describe 'WQL response bounded parsing', unit: true do
  let(:benign_enumerate) do
    '<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope">' \
      '<Body><EnumerateResponse>' \
      '<Items><Win32_OperatingSystem><Caption>Windows</Caption>' \
      '</Win32_OperatingSystem></Items></EnumerateResponse></Body></Envelope>'
  end

  let(:benign_pull) do
    '<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope">' \
      '<Body><PullResponse><EnumerationContext/>' \
      '<Items><x><v>1</v></x></Items></PullResponse></Body></Envelope>'
  end

  let(:deeply_nested) do
    '<Envelope><Body>' + ('<a>' * 300) + 'x' + ('</a>' * 300) + '</Body></Envelope>'
  end

  let(:oversized) do
    "<Envelope><Body><S>#{'a' * 600_000}</S></Body></Envelope>"
  end

  let(:malformed_namespace) { %q{<Envelope xmlns:1="bad"><Body/></Envelope>} }

  describe WinRM::WSMV::WqlPull do
    subject { described_class.new(default_connection_opts, 'root/cimv2', 'ctx') }

    it 'parses a small well-formed pull response' do
      result = subject.process_response(benign_pull)
      expect(result[:pull_response]).not_to be_nil
    end

    it 'validates through SafeXML before Nori parses' do
      expect(WinRM::SafeXML).to receive(:validate!)
        .with(benign_pull, 'WinRM WQL pull response').and_call_original
      subject.process_response(benign_pull)
    end

    [
      :deeply_nested,
      :oversized,
      :malformed_namespace
    ].each do |payload_name|
      it "rejects a #{payload_name} pull response with a bounded parse error" do
        expect { subject.process_response(send(payload_name)) }
          .to raise_error(WinRM::WinRMXMLParseError)
      end
    end
  end

  describe WinRM::WSMV::WqlQuery do
    let(:transport) { double('transport') }

    subject do
      described_class.new(transport, default_connection_opts, 'SELECT * FROM Win32')
    end

    it 'validates the enumerate response through SafeXML before Nori parses' do
      expect(WinRM::SafeXML).to receive(:validate!)
        .with(benign_enumerate, 'WinRM WQL enumerate response').and_call_original
      subject.process_response(benign_enumerate)
    end

    it 'rejects a hostile enumerate response before any enumeration work' do
      expect { subject.process_response(deeply_nested) }
        .to raise_error(WinRM::WinRMXMLParseError)
      expect(transport).not_to receive(:send_request)
    end

    it 'still processes a small well-formed enumerate response' do
      result = subject.process_response(benign_enumerate)
      expect(result).to include(:win32_operating_system)
    end
  end
end
