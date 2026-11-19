require 'winrm/http/transport'

describe WinRM::HTTP::HttpTransport, unit: true do
  let(:logger) { Logger.new(IO::NULL) }
  let(:options) { { logger: logger, receive_timeout: 10, user_agent: 'rspec' } }

  let(:request_message) do
    <<~XML
      <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
                  xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">
        <s:Header><a:MessageID>uuid:REQUEST-ID</a:MessageID></s:Header>
        <s:Body/>
      </s:Envelope>
    XML
  end

  def response_document(relates_to)
    header = relates_to ? "<a:RelatesTo>#{relates_to}</a:RelatesTo>" : ''
    REXML::Document.new(<<~XML)
      <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
                  xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">
        <s:Header>#{header}</s:Header>
        <s:Body/>
      </s:Envelope>
    XML
  end

  subject { described_class.new('http://localhost:5985/wsman', options) }

  describe '#correlate' do
    it 'accepts a response whose RelatesTo matches the request MessageID' do
      doc = response_document('uuid:REQUEST-ID')
      expect(subject.send(:correlate, doc, request_message)).to be(doc)
    end

    it 'rejects a mismatched RelatesTo before another remote operation' do
      expect do
        subject.send(:correlate, response_document('uuid:ATTACKER'), request_message)
      end.to raise_error(WinRM::WinRMResponseCorrelationError)
    end

    it 'ignores an addressing-namespace shadow RelatesTo from another namespace' do
      doc = REXML::Document.new(<<~XML)
        <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
                    xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
                    xmlns:e="http://evil.example/not-winrm">
          <s:Header>
            <e:RelatesTo>uuid:ATTACKER</e:RelatesTo>
            <a:RelatesTo>uuid:REQUEST-ID</a:RelatesTo>
          </s:Header>
          <s:Body/>
        </s:Envelope>
      XML
      expect(subject.send(:correlate, doc, request_message)).to be(doc)
    end

    context 'lenient (default) mode' do
      it 'tolerates a missing RelatesTo for legacy endpoints' do
        doc = response_document(nil)
        expect(subject.send(:correlate, doc, request_message)).to be(doc)
      end
    end

    context 'strict mode' do
      let(:options) { super().merge(strict_response_correlation: true) }

      it 'rejects a missing RelatesTo' do
        expect do
          subject.send(:correlate, response_document(nil), request_message)
        end.to raise_error(WinRM::WinRMResponseCorrelationError)
      end

      it 'still accepts a matching RelatesTo' do
        doc = response_document('uuid:REQUEST-ID')
        expect(subject.send(:correlate, doc, request_message)).to be(doc)
      end
    end
  end
end
