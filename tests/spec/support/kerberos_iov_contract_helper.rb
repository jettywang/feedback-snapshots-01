require 'base64'
require 'tmpdir'
require 'fileutils'
require 'English'

# Shared setup for the offline Kerberos IOV contract specs.
#
# The HTTP client here is a narrow stand-in for HTTPClient: it records the
# exact body and headers the transport posts and replays a WinRM
# session-encrypted response produced by the GSSAPI stand-in.
module KerberosIovContract
  # Records requests and serves either a protected response or a raw body.
  class RecordingHttpClient
    Response = Struct.new(:status, :http_body, :header, :peer_cert, keyword_init: true)
    Body = Struct.new(:content)
    SslConfig = Struct.new(:verify_mode, :client_cert)

    # HTTPClient exposes its auth stack through an ivar and the transport
    # prunes it with no_sspi_auth!, so this must be a real ivar.
    class WwwAuth
      def initialize
        @authenticator = []
      end
    end

    attr_reader :requests, :ssl_config, :www_auth

    def initialize(&responder)
      @responder = responder
      @requests = []
      @ssl_config = SslConfig.new(0, nil)
      @www_auth = WwwAuth.new
    end

    def post(endpoint, body, headers)
      @requests << { endpoint: endpoint, body: body, headers: headers }
      return auth_handshake_response if headers['Authorization']

      Response.new(status: 200, http_body: Body.new(response_body(body, headers)), header: {}, peer_cert: nil)
    end

    def receive_timeout=(_value); end
    def default_header=(_value); end

    private

    def auth_handshake_response
      token = Base64.strict_encode64('server-context-token')
      Response.new(
        status: 200,
        http_body: Body.new(''),
        header: { 'WWW-Authenticate' => ["Negotiate #{token}"] },
        peer_cert: nil
      )
    end

    # A responder returning "RAW:..." supplies the response body verbatim,
    # which lets a spec exercise malformed tokens end to end.
    def response_body(body, headers)
      text = @responder ? @responder.call(body, headers) : ''
      return text.delete_prefix('RAW:') if text.start_with?('RAW:')

      "--Encrypted Boundary\r\nContent-Type: application/octet-stream\r\n" \
        "#{GSSAPI::Standin.protect(text)}--Encrypted Boundary--\r\n"
    end
  end

  # Copies the library and contract specs into a scratch tree so a spec can
  # mutate the transport and run the suite against the altered copy.
  class VariantTree
    CONTRACT_SPECS = %w[
      kerberos_iov_request_contract_spec.rb
      kerberos_iov_failure_contract_spec.rb
    ].freeze

    def initialize(root, scratch)
      @root = root
      @scratch = scratch
    end

    def build
      copy_tree
      yield File.join(@scratch, 'lib', 'winrm', 'http', 'transport.rb')
      run
    end

    private

    def copy_tree
      FileUtils.mkdir_p(File.join(@scratch, 'tests', 'spec', 'http'))
      FileUtils.mkdir_p(File.join(@scratch, 'tests', 'spec', 'support'))
      FileUtils.cp_r(File.join(@root, 'lib', '.'), File.join(@scratch, 'lib'))
      FileUtils.cp(File.join(@root, 'tests', 'spec', 'spec_helper.rb'), File.join(@scratch, 'tests', 'spec'))
      FileUtils.cp(File.join(@root, 'tests', 'matchers.rb'), File.join(@scratch, 'tests'))
      FileUtils.cp_r(Dir.glob(File.join(@root, 'tests', 'spec', 'support', '*')),
                     File.join(@scratch, 'tests', 'spec', 'support'))
      CONTRACT_SPECS.each do |name|
        FileUtils.cp(
          File.join(@root, 'tests', 'spec', 'http', name),
          File.join(@scratch, 'tests', 'spec', 'http', name)
        )
      end
    end

    def run
      command = [
        RbConfig.ruby, File.join(@root, '.feedback', 'run.rb'), 'exec',
        'rspec', '-Ilib:tests/spec', '--require', './tests/spec/spec_helper.rb',
        *CONTRACT_SPECS.map { |name| File.join('tests', 'spec', 'http', name) },
        '--tag', '~variants', '--format', 'progress'
      ]
      output = IO.popen(command, chdir: @scratch, err: [:child, :out], &:read)
      [output, $CHILD_STATUS || $?]
    end
  end

  def rewrite_transport(path)
    source = File.read(path)
    mutated = yield(source)
    raise 'mutation did not apply' if mutated == source

    File.write(path, mutated)
  end
end

RSpec.shared_context 'kerberos IOV transport' do
  let(:endpoint) { 'http://winrm.example.test:5985/wsman' }
  let(:realm) { 'EXAMPLE.TEST' }
  let(:message) do
    '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">' \
      '<s:Body><p:Create xmlns:p="urn:x">shell</p:Create></s:Body></s:Envelope>'
  end
  let(:response_body) do
    '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">' \
      '<s:Body><p:CreateResponse xmlns:p="urn:x"><p:ShellId>abc</p:ShellId></p:CreateResponse></s:Body></s:Envelope>'
  end
  let(:options) do
    {
      user_agent: 'contract-test',
      receive_timeout: 30,
      no_ssl_peer_verification: true,
      logger: Logger.new(IO::NULL)
    }
  end

  subject(:transport) { described_class.new(endpoint, realm, options) }

  let(:responder_body) { response_body }
  let(:http_client) { KerberosIovContract::RecordingHttpClient.new { responder_body } }

  before do
    GSSAPI::Standin.reset!
    allow(HTTPClient).to receive(:new).and_return(http_client)
  end

  def posted_body(request)
    request[:body]
  end

  def encrypted_payload(request)
    request[:body][%r{Content-Type: application/octet-stream\r\n(.*)--Encrypted Boundary--}m, 1]
  end

  def request_token(request)
    payload = encrypted_payload(request)
    header_len = payload.unpack1('V')
    [
      header_len,
      payload.byteslice(4, header_len),
      payload.byteslice(4 + header_len, payload.bytesize).to_s
    ]
  end
end
