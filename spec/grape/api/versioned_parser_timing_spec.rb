# frozen_string_literal: true

require 'spec_helper'

describe 'versioned parser timing' do
  let(:events) { [] }

  let(:app) do
    recorder = events

    Class.new(Grape::API) do
      version 'v1', using: :accept_version_header do
        content_type :txt, 'text/plain'
        content_type :alpha, 'application/x-alpha'
        parser :alpha, ->(body, _env) {
          recorder << [:parser, 'v1']
          { 'parsed_by' => 'v1', 'body' => body }
        }

        post :items do
          recorder << [:endpoint, env[Grape::Env::API_VERSION]]
          status 202
          'v1'
        end
      end

      version 'v2', using: :accept_version_header do
        content_type :txt, 'text/plain'
        content_type :beta, 'application/x-beta'
        parser :beta, ->(body, _env) {
          recorder << [:parser, 'v2']
          { 'parsed_by' => 'v2', 'body' => body }
        }

        post :items do
          recorder << [:endpoint, env[Grape::Env::API_VERSION]]
          status 202
          'v2'
        end
      end
    end
  end

  def observing_input(body)
    recorder = events

    input_class = Class.new(StringIO) do
      define_method(:read) do |*args|
        recorder << :body_read
        super(*args)
      end
    end

    input_class.new(body)
  end

  def parser_events(version = nil)
    events.select do |event|
      event.is_a?(Array) && event.first == :parser && (version.nil? || event[1] == version)
    end
  end

  def call_with_input(version:, content_type:, body: 'payload')
    input = observing_input(body)
    env = Rack::MockRequest.env_for(
      '/items',
      method: Rack::POST,
      input:,
      'CONTENT_TYPE' => content_type,
      'CONTENT_LENGTH' => input.length.to_s,
      'HTTP_ACCEPT_VERSION' => version
    )
    [app.call(env), input]
  end

  it 'runs only the selected version parser after selecting its permission' do
    response, = call_with_input(version: 'v1', content_type: 'application/x-alpha')

    expect(response[0]).to eq(202)
    expect(events).to eq([:body_read, [:parser, 'v1'], [:endpoint, 'v1']])
    expect(parser_events('v1').size).to eq(1)
  end

  it 'does not read or parse a format the selected version does not support' do
    response, input = call_with_input(version: 'v1', content_type: 'application/x-beta')

    expect(response[0]).to eq(415)
    expect(events).to be_empty
    expect(parser_events).to be_empty
    expect(input.pos).to eq(0)
  end

  it 'does not run the declined candidate parser before the winning candidate' do
    response, = call_with_input(version: 'v2', content_type: 'application/x-beta')

    expect(response[0]).to eq(202)
    expect(events).to eq([:body_read, [:parser, 'v2'], [:endpoint, 'v2']])
    expect(parser_events('v1')).to be_empty
    expect(parser_events('v2').size).to eq(1)
  end

  it 'counts each parser once through Rack::Test in the allowed case' do
    post '/items', 'payload',
         'CONTENT_TYPE' => 'application/x-alpha',
         'HTTP_ACCEPT_VERSION' => 'v1'

    expect(last_response).to be_accepted
    expect(parser_events('v1').size).to eq(1)
    expect(parser_events('v2')).to be_empty
  end

  it 'answers 406 before parsing when format negotiation fails' do
    post '/items?format=unknown', 'payload',
         'CONTENT_TYPE' => 'application/x-alpha',
         'HTTP_ACCEPT_VERSION' => 'v1'

    expect(last_response.status).to eq(406)
    expect(parser_events).to be_empty
  end

  it 'answers 415 without either parser when the request format does not match the version' do
    post '/items', 'payload',
         'CONTENT_TYPE' => 'application/x-beta',
         'HTTP_ACCEPT_VERSION' => 'v1'

    expect(last_response.status).to eq(415)
    expect(parser_events).to be_empty
  end

  it 'lets the matching candidate own parsing after an earlier candidate cascades' do
    post '/items', 'payload',
         'CONTENT_TYPE' => 'application/x-beta',
         'HTTP_ACCEPT_VERSION' => 'v2'

    expect(last_response).to be_accepted
    expect(parser_events('v2').size).to eq(1)
    expect(parser_events('v1')).to be_empty
    expect(last_response.body).to eq('v2')
  end
end
