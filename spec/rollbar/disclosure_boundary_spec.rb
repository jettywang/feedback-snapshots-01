# frozen_string_literal: true

require 'spec_helper'
require 'rack/test'
require 'rollbar/middleware/rack'
require 'rollbar/item/backtrace'
require 'support/disclosure_boundary_fixtures'

# End-to-end disclosure-boundary checks for the exception formatter pipeline.
#
# A plain single-level exception never exercises nested causes nor frames that
# carry local variables, so it cannot show when request scrubbing happens
# relative to exception formatting. These specs drive a real two-level
# exception chain (an outer error wrapping an inner cause) raised inside a Rack
# application, where the request and the surviving stack frame hold sensitive
# values. The same report is inspected at the three representations it takes
# on the way out:
#
#   1. the constructed event   -> the Hash stored as Rollbar.last_report
#   2. the queued representation -> the object handed to the async handler
#   3. the actual outgoing body -> the JSON posted to the Rollbar endpoint
#
# Sensitive source values are tagged with distinct sentinels so any leak can
# be traced back to its origin: the request, the outer frame, or the inner
# cause. Shareable request fields use a separate, non-sensitive marker.
RSpec.describe 'Rollbar disclosure boundary', :reconfigure_notifier => true do
  include Rack::Test::Methods

  F = DisclosureBoundaryFixtures

  let(:async_handler) { F::CapturingAsyncHandler.new }
  let(:app) { Rollbar::Middleware::Rack.new(F::RaisingRackApp.new) }
  let(:async_mode) { false }

  let(:request_sentinel) { F::REQUEST_SENTINEL }
  let(:outer_sentinel) { F::OUTER_SENTINEL }
  let(:inner_sentinel) { F::INNER_SENTINEL }
  let(:scrub_marker) { F::SCRUB_MARKER }
  let(:shareable_key) { F::SHAREABLE_REQUEST_KEY }
  let(:shareable_value) { F::SHAREABLE_REQUEST_VALUE }

  before do
    Rollbar.configure do |config|
      config.access_token = test_access_token
      config.enabled = true
      config.framework = 'Rack'
      config.use_async = async_mode
      config.async_handler = async_handler
      config.async_json_payload = false
      config.transmit = true
      config.root = Rails.root
      config.locals = { :enabled => true }
      config.send_extra_frame_data = :all
      config.randomize_scrub_length = false
    end
  end

  def trigger_request
    post '/webhook',
         shareable_key => shareable_value,
         'password' => request_sentinel,
         'secret_token' => request_sentinel
  rescue F::OuterError
    # The Rack middleware re-raises after reporting; expected here.
  end

  # Builds a genuine two-level chain through Ruby's raise/rescue so
  # Exception#cause links the outer error to the inner cause.
  def build_nested_exception
    raise F::InnerCauseError, 'inner root cause'
  rescue F::InnerCauseError
    begin
      raise F::OuterError, 'outer failure while handling request'
    rescue F::OuterError => outer
      outer
    end
  end

  # Recursively searches a nested Hash/Array for an exact value or key.
  def deep_include?(structure, needle)
    case structure
    when Hash
      structure.any? { |key, value| key == needle || deep_include?(value, needle) }
    when Array
      structure.any? { |value| deep_include?(value, needle) }
    else
      structure == needle
    end
  end

  # Rollbar.last_report stores the inner data Hash, while the queued payload
  # and outgoing body keep the full { 'data' => ... } envelope. Normalize both.
  def data_from(payload)
    payload.key?('data') ? payload['data'] : payload
  end

  def chain_from(payload)
    body = data_from(payload)[:body]
    body[:trace_chain] || body['trace_chain']
  end

  def request_from(payload)
    data = data_from(payload)
    data[:request] || data['request']
  end

  # Frames defined in the raising fixture are the ones that can carry locals.
  def fixture_frames(chain)
    chain.flat_map do |trace|
      trace[:frames].select do |frame|
        frame[:filename].include?('disclosure_boundary_fixtures')
      end
    end
  end

  describe 'the constructed event (Rollbar.last_report)' do
    it 'preserves both exception types across the nested cause chain' do
      trigger_request

      chain = chain_from(Rollbar.last_report)

      expect(chain.map { |trace| trace[:exception][:class] }).to eq(
        ['DisclosureBoundaryFixtures::OuterError',
         'DisclosureBoundaryFixtures::InnerCauseError']
      )
    end

    it 'keeps the inner-cause message so the chain stays diagnosable' do
      trigger_request

      chain = chain_from(Rollbar.last_report)

      expect(chain[0][:exception][:message]).to eq('outer failure while handling request')
      expect(chain[1][:exception][:message]).to eq('inner root cause')
    end

    it 'keeps locatable frames for every level of the chain' do
      trigger_request

      chain_from(Rollbar.last_report).each do |trace|
        expect(trace[:frames]).to be_a(Array)
        expect(trace[:frames]).not_to be_empty
        trace[:frames].each do |frame|
          expect(frame[:filename]).to be_a(String)
          expect(frame[:lineno]).to be > 0
        end
      end
    end

    it 'captures frame locals and redacts sensitive ones at the source' do
      trigger_request

      frames = fixture_frames(chain_from(Rollbar.last_report))
      locals = frames.map { |frame| frame[:locals] }

      expect(deep_include?(locals, outer_sentinel)).to be(false)
      expect(deep_include?(locals, scrub_marker)).to be(true)
    end

    it 'does not leak the inner-cause secret into any frame channel' do
      trigger_request

      frames = fixture_frames(chain_from(Rollbar.last_report))

      expect(deep_include?(frames, inner_sentinel)).to be(false)
    end

    it 'constrains public request fields but keeps a shareable classification' do
      trigger_request

      request = request_from(Rollbar.last_report)

      expect(deep_include?(request, request_sentinel)).to be(false)
      expect(request[:POST]['password']).to eq(scrub_marker)
      expect(request[:POST]['secret_token']).to eq(scrub_marker)
      expect(request[:POST][shareable_key]).to eq(shareable_value)
    end
  end

  context 'when the report is queued and sent through the delayed path' do
    let(:async_mode) { true }

    describe 'the queued representation handed to the async handler' do
      it 'is the same report and never carries raw sensitive source values' do
        trigger_request

        queued = async_handler.queued_payload

        expect(queued).to be_a(Hash)
        expect(queued['data']).to be
        expect(deep_include?(queued, request_sentinel)).to be(false)
        expect(deep_include?(queued, outer_sentinel)).to be(false)
        expect(deep_include?(queued, inner_sentinel)).to be(false)
      end

      it 'retains the full exception chain and the shareable request category' do
        trigger_request

        chain = chain_from(async_handler.queued_payload)
        request = request_from(async_handler.queued_payload)

        expect(chain.length).to be(2)
        expect(chain[1][:exception][:class])
          .to eq('DisclosureBoundaryFixtures::InnerCauseError')
        expect(request[:POST][shareable_key]).to eq(shareable_value)
      end
    end

    describe 'the actual outgoing body' do
      it 'serializes a payload bounded by the same disclosure rules' do
        sent_body = nil
        stub = stub_request(:post, /api.rollbar.com/).to_return do |request|
          sent_body = request.body
          { :status => 200,
            :headers => { 'Content-Type' => 'application/json' },
            :body => { :err => 0 }.to_json }
        end

        trigger_request
        Rollbar.process_from_async_handler(async_handler.queued_payload)

        expect(stub).to have_been_requested
        parsed = JSON.parse(sent_body)

        expect(deep_include?(parsed, request_sentinel)).to be(false)
        expect(deep_include?(parsed, outer_sentinel)).to be(false)
        expect(deep_include?(parsed, inner_sentinel)).to be(false)

        classes = parsed.dig('data', 'body', 'trace_chain')
                        .map { |trace| trace.dig('exception', 'class') }
        expect(classes).to eq(
          ['DisclosureBoundaryFixtures::OuterError',
           'DisclosureBoundaryFixtures::InnerCauseError']
        )
        expect(parsed.dig('data', 'request', 'POST', shareable_key))
          .to eq(shareable_value)
      end
    end

    describe 'a formatter double that drops one inner-cause field' do
      it 'locates the dropped field from its source to its outgoing landing point' do
        sent_body = nil
        stub_request(:post, /api.rollbar.com/).to_return do |request|
          sent_body = request.body
          { :status => 200,
            :headers => { 'Content-Type' => 'application/json' },
            :body => { :err => 0 }.to_json }
        end

        trigger_request

        # Run the broken double over a real nested exception so it operates on
        # the genuine inner-cause source object rather than a hand-built hash.
        real_backtrace = Rollbar::Item::Backtrace.new(
          build_nested_exception,
          :message => nil,
          :extra => nil,
          :configuration => Rollbar.configuration
        )
        broken = F::BrokenInnerCauseBacktrace.new(real_backtrace).to_h

        # The defect is isolated to the inner-cause message; its class and the
        # outer level are untouched.
        expect(broken[:trace_chain][1][:exception]).not_to have_key(:message)
        expect(broken[:trace_chain][1][:exception][:class])
          .to eq('DisclosureBoundaryFixtures::InnerCauseError')
        expect(broken[:trace_chain][0][:exception][:message])
          .to eq('outer failure while handling request')

        # The normal pipeline still delivers the dropped field at the same
        # landing point, proving the gap belongs to the double, not transport.
        Rollbar.process_from_async_handler(async_handler.queued_payload)
        transmitted = JSON.parse(sent_body)
        inner = transmitted.dig('data', 'body', 'trace_chain', 1, 'exception')

        expect(inner['message']).to eq('inner root cause')
        expect(inner['class']).to eq('DisclosureBoundaryFixtures::InnerCauseError')
      end

      it 'normally preserves the chain and the shareable request category' do
        trigger_request

        chain = chain_from(async_handler.queued_payload)
        request = request_from(async_handler.queued_payload)

        expect(chain.length).to be(2)
        expect(chain.all? { |trace| trace[:exception].key?(:message) }).to be(true)
        expect(request[:POST][shareable_key]).to eq(shareable_value)
      end
    end
  end
end
