require 'helper'

describe OmniAuth::FailureReceipt do
  def build_receipt(message_key)
    described_class.new(:message_key => message_key, :error => nil, :phase => :request, :strategy_name => 'test')
  end

  it 'treats a Symbol message key as approved for the browser' do
    expect(build_receipt(:invalid_credentials).public_message_key).to eq(:invalid_credentials)
  end

  it 'replaces free text such as an exception message with the fallback key' do
    expect(build_receipt('secret details').public_message_key).to eq(:internal_error)
    expect(build_receipt(nil).public_message_key).to eq(:internal_error)
  end

  it 'generates a unique hexadecimal id per receipt' do
    ids = Array.new(3) { build_receipt(:oops).id }

    expect(ids.uniq.size).to eq(3)
    ids.each { |id| expect(id).to match(/\A[0-9a-f]{16}\z/) }
  end
end

describe 'egress-constrained failure receipts' do
  # A local strategy whose setup, request and callback phases all raise the
  # same error class, each with its own private placeholder text.
  class ReceiptBoom < StandardError; end

  RECEIPT_PRIVATE_TEXTS = {
    :setup => 'PRIVATE-SETUP-TEXT-9f8e7d',
    :request => 'PRIVATE-REQUEST-TEXT-6c5b4a',
    :callback => 'PRIVATE-CALLBACK-TEXT-3e2f1a'
  }.freeze

  class ReceiptStrategy
    include OmniAuth::Strategy

    option :name, 'receipt'

    def request_phase
      raise ReceiptBoom, RECEIPT_PRIVATE_TEXTS[:request]
    end

    def callback_phase
      raise ReceiptBoom, RECEIPT_PRIVATE_TEXTS[:callback]
    end
  end

  let(:app) { lambda { |_env| [404, {}, ['Awesome']] } }
  let(:log_io) { StringIO.new }
  let(:receipts) { [] }

  before do
    allow(OmniAuth.config).to receive(:logger).and_return(Logger.new(log_io))
    allow(OmniAuth.config).to receive(:on_failure_receipt).and_return(lambda { |receipt| receipts << receipt })
  end

  def failure_env(path)
    {
      'REQUEST_METHOD' => 'POST',
      'PATH_INFO' => path,
      'rack.session' => {},
      'rack.input' => StringIO.new('')
    }
  end

  def setup_failure
    lambda { |_env| raise ReceiptBoom, RECEIPT_PRIVATE_TEXTS[:setup] }
  end

  # Compares the actual Location, the page material, the public log, and
  # the controlled events: the receipt id must recover the original cause
  # while the private text must not be decodable from the browser side.
  def expect_egress_boundary(response, phase)
    status, headers, body = response
    private_text = RECEIPT_PRIVATE_TEXTS.fetch(phase)

    expect(status).to eq(302)

    location = headers['Location']
    query = Rack::Utils.parse_query(location.split('?', 2).last)
    expect(query['message']).to eq('internal_error')
    expect(query['strategy']).to eq('receipt')
    receipt_id = query['receipt']
    expect(receipt_id).to match(/\A[0-9a-f]{16}\z/)

    [location, body.to_enum(:each).to_a.join].each do |material|
      expect(material).not_to include(private_text)
      expect(material).not_to include(Rack::Utils.escape(private_text))
    end

    expect(log_io.string).to include("internal_error encountered. Receipt: #{receipt_id}")
    expect(log_io.string).not_to include(private_text)

    receipt = receipts.detect { |candidate| candidate.id == receipt_id }
    expect(receipt).not_to be_nil
    expect(receipt.phase).to eq(phase)
    expect(receipt.strategy_name).to eq('receipt')
    expect(receipt.error).to be_instance_of(ReceiptBoom)
    expect(receipt.error.message).to eq(private_text)
    expect(receipt.error.backtrace).not_to be_empty
  end

  it 'constrains a setup phase failure' do
    strategy = ReceiptStrategy.new(app, :setup => setup_failure)

    expect_egress_boundary(strategy.call(failure_env('/auth/receipt')), :setup)
  end

  it 'constrains a request phase failure' do
    expect_egress_boundary(ReceiptStrategy.new(app).call(failure_env('/auth/receipt')), :request)
  end

  it 'constrains a callback phase failure' do
    expect_egress_boundary(ReceiptStrategy.new(app).call(failure_env('/auth/receipt/callback')), :callback)
  end

  context 'with a custom on_failure that returns the default error page' do
    it 'hands the exception to the handler and still constrains the egress' do
      received = []
      custom_failure = lambda do |env|
        received << env['omniauth.error']
        OmniAuth::FailureEndpoint.call(env)
      end
      allow(OmniAuth.config).to receive(:on_failure).and_return(custom_failure)

      response = ReceiptStrategy.new(app).call(failure_env('/auth/receipt/callback'))

      expect(received.size).to eq(1)
      expect(received.first).to be_instance_of(ReceiptBoom)
      expect(received.first.message).to eq(RECEIPT_PRIVATE_TEXTS[:callback])
      expect_egress_boundary(response, :callback)
    end
  end

  it 'passes the on_failure response status through untouched' do
    allow(OmniAuth.config).to receive(:on_failure).and_return(lambda { |_env| [418, {}, ['teapot']] })

    response = ReceiptStrategy.new(app).call(failure_env('/auth/receipt'))

    expect(response[0]).to eq(418)
    expect(response[2]).to eq(['teapot'])
  end
end
