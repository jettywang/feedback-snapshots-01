require 'stringio'
require 'winrm/http/transport'

describe WinRM::HTTP::HttpTransport, unit: true do
  let(:log_io) { StringIO.new }
  let(:logger) { Logger.new(log_io, level: :debug) }

  subject do
    described_class.new(
      'http://localhost:5985/wsman',
      logger: logger,
      receive_timeout: 10,
      user_agent: 'rspec'
    )
  end

  let(:benign_soap) do
    '<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope"><Body>' \
      '<Stream Name="stdout">aGVsbG8=</Stream></Body></Envelope>'
  end

  let(:billion_laughs) do
    defs = %Q{<!ENTITY e0 "ab">\n}
    1.upto(8) do |i|
      defs += %Q{<!ENTITY e#{i} "#{Array.new(5) { "&e#{i - 1};" }.join}">\n}
    end
    %Q{<!DOCTYPE r [\n#{defs}]><r>&e8;</r>}
  end

  let(:deeply_nested) { "<r>#{'<a>' * 300}x#{'</a>' * 300}</r>" }
  let(:malformed) { '<Envelope><Body>' }

  describe '#log_soap_message (the error-logging XML entry point)' do
    it 'pretty-prints a small well-formed message at debug level' do
      subject.send(:log_soap_message, benign_soap)
      expect(log_io.string).to include('Envelope')
    end

    it 'is a no-op below debug level (no parsing work at all)' do
      quiet = Logger.new(log_io, level: :info)
      transport = described_class.new(
        'http://localhost:5985/wsman',
        logger: quiet,
        receive_timeout: 10,
        user_agent: 'rspec'
      )
      expect(WinRM::SafeXML).not_to receive(:parse)
      transport.send(:log_soap_message, billion_laughs)
      expect(log_io.string).to be_empty
    end

    shared_examples 'a bounded log rejection' do |payload_name|
      let(:payload) { send(payload_name) }

      it 'logs a bounded-parser notice without raising' do
        expect { subject.send(:log_soap_message, payload) }.not_to raise_error
        expect(log_io.string).to include("Couldn't log SOAP request/response")
        expect(log_io.string).to include('bounded parser')
      end

      it 'never echoes the rejected body into the log' do
        subject.send(:log_soap_message, payload)
        expect(log_io.string).not_to include(payload)
      end

      it 'parses the body exactly once through the bounded entry point' do
        calls = 0
        allow(WinRM::SafeXML).to receive(:parse).and_wrap_original do |original, *args|
          calls += 1
          original.call(*args)
        end
        subject.send(:log_soap_message, payload)
        expect(calls).to eq(1)
      end
    end

    context 'with an entity-expansion bomb' do
      include_examples 'a bounded log rejection', :billion_laughs
    end

    context 'with a deeply nested body' do
      include_examples 'a bounded log rejection', :deeply_nested
    end

    context 'with malformed markup' do
      include_examples 'a bounded log rejection', :malformed
    end

    it 'routes through the real SafeXML entry point, not a test double shortcut' do
      expect(WinRM::SafeXML).to receive(:parse)
        .with(benign_soap, 'WinRM SOAP log message').and_call_original
      subject.send(:log_soap_message, benign_soap)
    end
  end

  describe 'receiving a hostile response through #send_request' do
    # End-to-end guarantee for the "rejected body is not re-parsed" rule:
    # the same hostile body may reach the bounded parser at most twice (the
    # debug-log guard and the response handler), never repeatedly while the
    # rejection is recorded, and it is never returned as normal output.
    let(:hostile_response) do
      '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">' \
        "<s:Body>#{'<a>' * 300}x#{'</a>' * 300}</s:Body></s:Envelope>"
    end

    before do
      fake_body = Struct.new(:content).new(hostile_response)
      fake_response = Struct.new(:http_body, :status, :peer_cert)
                         .new(fake_body, 200, nil)
      subject.instance_variable_get(:@httpcli)
             .define_singleton_method(:post) { |*_args| fake_response }
    end

    it 'raises a transport error and bounds the number of parses of that body' do
      parses_of_body = 0
      allow(WinRM::SafeXML).to receive(:parse).and_wrap_original do |original, xml, *rest|
        parses_of_body += 1 if xml == hostile_response
        original.call(xml, *rest)
      end

      expect { subject.send_request('<r/>') }
        .to raise_error(WinRM::WinRMHTTPTransportError)
      expect(parses_of_body).to be <= 2
    end

    it 'never writes the rejected body to the log or returns it as output' do
      expect { subject.send_request('<r/>') }
        .to raise_error(WinRM::WinRMHTTPTransportError)
      expect(log_io.string).not_to include(hostile_response)
    end
  end
end
