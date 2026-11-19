require 'winrm/exceptions'
require 'winrm/http/transport_factory'

describe WinRM::HTTP::TransportFactory do
  describe '#create_transport' do
    before do
      # Stub construction only for this spec; redefining the class globally
      # would replace the real implementation for the whole test process.
      allow(WinRM::HTTP::HttpGSSAPI).to receive(:new).and_return(instance_double(WinRM::HTTP::HttpGSSAPI))
    end

    let(:transport) { :negotiate }
    let(:options) do
      {
        transport: transport,
        endpoint: 'endpoint',
        user: 'user'
      }
    end

    it 'creates a negotiate transport' do
      options[:transport] = :negotiate
      expect(subject.create_transport(options)).to be_a(WinRM::HTTP::HttpNegotiate)
    end

    it 'creates a plaintext transport' do
      options[:transport] = :plaintext
      expect(subject.create_transport(options)).to be_a(WinRM::HTTP::HttpPlaintext)
    end

    it 'creates a basic auth ssl transport' do
      options[:transport] = :ssl
      options[:basic_auth_only] = true
      expect(subject.create_transport(options)).to be_a(WinRM::HTTP::BasicAuthSSL)
    end

    it 'creates a client cert ssl transport' do
      options[:transport] = :ssl
      options[:client_cert] = 'cert'
      expect(subject.create_transport(options)).to be_a(WinRM::HTTP::ClientCertAuthSSL)
    end

    it 'creates a negotiate over ssl transport' do
      options[:transport] = :ssl
      expect(subject.create_transport(options)).to be_a(WinRM::HTTP::HttpNegotiate)
    end

    it 'creates a kerberos transport' do
      options[:transport] = :kerberos
      options[:realm] = 'EXAMPLE.TEST'
      expect(WinRM::HTTP::HttpGSSAPI).to receive(:new).with(
        options[:endpoint], options[:realm], options, nil
      )
      subject.create_transport(options)
    end

    it 'creates a transport from a stringified transport' do
      options[:transport] = 'negotiate'
      expect(subject.create_transport(options)).to be_a(WinRM::HTTP::HttpNegotiate)
    end

    it 'raises when transport type does not exist' do
      options[:transport] = :fancy
      expect { subject.create_transport(options) }.to raise_error(WinRM::InvalidTransportError)
    end
  end
end
