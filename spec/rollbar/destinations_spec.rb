require 'spec_helper'
require 'rollbar/destination'

describe 'Rollbar destinations' do
  let(:external_sender) { Rollbar::InMemorySender.new(:rollbar) }
  let(:oncall_sender) { Rollbar::InMemorySender.new(:oncall) }

  let(:request_data) do
    {
      :url => 'https://internal.example.com/secret',
      :headers => { 'Authorization' => 'token' },
      :user_ip => '10.0.0.1'
    }
  end

  let(:person_data) do
    { :id => 42, :username => 'alice' }
  end

  let(:extra_data) do
    { :account_id => 7, :public_tag => 'checkout' }
  end

  def configure_destinations
    Rollbar.configure do |config|
      config.access_token = test_access_token
      config.transmit = false # silence the default HTTP path in these examples

      config.add_destination(:rollbar, external_sender,
                             permitted_sections: :all)

      config.add_destination(:oncall, oncall_sender,
                             permitted_sections: %i[request extra])
    end
  end

  def report_error
    Rollbar.scoped(:request => request_data, :person => person_data) do
      begin
        raise StandardError, 'boom'
      rescue StandardError => e
        Rollbar.error(e, 'request failed', extra_data)
      end
    end
  end

  # Returns a deep-copied slice of a payload view with per-event values
  # (server pid and frame line numbers) normalized, so two payloads describing
  # the same error can be compared for representation stability.
  def stable_view(payload, comparable_keys)
    view = Rollbar::Util.deep_copy(payload['data'].slice(*comparable_keys))

    view[:server].delete(:pid) if view[:server]

    each_trace(view[:body]) do |trace|
      Array(trace[:frames]).each { |frame| frame.delete(:lineno) }
    end

    view
  end

  def each_trace(body)
    return unless body.is_a?(Hash)

    yield(body[:trace]) if body[:trace]
    Array(body[:trace_chain]).each { |trace| yield(trace) }
  end

  describe 'fan-out and correlation' do
    before do
      configure_destinations
      report_error
    end

    it 'sends one payload to every destination' do
      expect(external_sender.count).to be_eql(1)
      expect(oncall_sender.count).to be_eql(1)
    end

    it 'correlates both receipts with the same event through one uuid' do
      external_uuid = external_sender.last_payload['data'][:uuid]
      oncall_uuid = oncall_sender.last_payload['data'][:uuid]

      expect(external_uuid).not_to be_nil
      expect(oncall_uuid).to be_eql(external_uuid)
    end

    it 'reports the same error event to both destinations' do
      external_data = external_sender.last_payload['data']
      oncall_data = oncall_sender.last_payload['data']

      expect(external_data[:level]).to be_eql('error')
      expect(oncall_data[:level]).to be_eql('error')

      external_exception = external_data[:body][:trace][:exception]
      oncall_exception = oncall_data[:body][:trace][:exception]

      expect(oncall_exception[:class]).to be_eql(external_exception[:class])
      expect(oncall_exception[:message]).to be_eql(external_exception[:message])
    end
  end

  describe 'per-destination data scope' do
    before do
      configure_destinations
      report_error
    end

    it 'sends every permitted section to the external destination' do
      data = external_sender.last_payload['data']

      expect(data[:request]).to be_eql(request_data)
      expect(data[:person]).to be_eql(person_data)
      expect(data[:body][:trace][:extra]).to include(extra_data)
    end

    it 'sends request and extra but strips person from the internal desk' do
      data = oncall_sender.last_payload['data']

      expect(data[:request]).to be_eql(request_data)
      expect(data).not_to include(:person)
      expect(data[:body][:trace][:extra]).to include(extra_data)
    end

    it 'keeps the canonical payload untouched by the restricted view' do
      external_data = external_sender.last_payload['data']
      oncall_data = oncall_sender.last_payload['data']

      expect(external_data).to include(:person)
      expect(oncall_data).not_to include(:person)
    end

    it 'also strips extra from the message body when extra is denied' do
      Rollbar.clear_notifier!

      sender = Rollbar::InMemorySender.new(:stripped)

      Rollbar.configure do |config|
        config.access_token = test_access_token
        config.transmit = false
        config.add_destination(:stripped, sender,
                               permitted_sections: %i[request])
      end

      Rollbar.info('plain message', extra_data)

      message = sender.last_payload['data'][:body][:message]
      expect(message).not_to include(:extra)
    end
  end

  describe 'view isolation between destinations' do
    let(:rollbar_transform) do
      proc do |options|
        options[:payload]['data'][:rollbar_outlet] = 'rollbar-view'
      end
    end

    let(:oncall_transform) do
      proc do |options|
        options[:payload]['data'][:oncall_outlet] = 'oncall-view'
      end
    end

    before do
      Rollbar.configure do |config|
        config.access_token = test_access_token
        config.transmit = false

        config.add_destination(:rollbar, external_sender) do |dest|
          dest.add_transform(rollbar_transform)
        end

        config.add_destination(:oncall, oncall_sender) do |dest|
          dest.add_transform(oncall_transform)
        end
      end

      report_error
    end

    it 'applies each transform only to its own destination view' do
      expect(external_sender.last_payload['data'][:rollbar_outlet])
        .to be_eql('rollbar-view')
      expect(oncall_sender.last_payload['data'][:oncall_outlet])
        .to be_eql('oncall-view')
    end

    it 'never leaks a transform mutation into the other destination' do
      external_payload = external_sender.last_payload
      oncall_payload = oncall_sender.last_payload

      expect(external_payload['data']).not_to include(:oncall_outlet)
      expect(oncall_payload['data']).not_to include(:rollbar_outlet)
      expect(external_payload['data'][:uuid])
        .to be_eql(oncall_payload['data'][:uuid])
    end
  end

  describe 'transform ordering stability' do
    def build_with_order(first_tag, second_tag)
      external = Rollbar::InMemorySender.new(:external)
      oncall = Rollbar::InMemorySender.new(:oncall)

      Rollbar.clear_notifier!

      Rollbar.configure do |config|
        config.access_token = test_access_token
        config.transmit = false

        config.add_destination(:external, external) do |dest|
          dest.add_transform { |options| options[:payload]['data'][:tags] ||= [] }
          dest.add_transform do |options|
            options[:payload]['data'][:tags] << first_tag
          end
        end

        config.add_destination(:oncall, oncall) do |dest|
          dest.add_transform do |options|
            options[:payload]['data'][:internal_only] = 'incident-1234'
          end
          dest.add_transform do |options|
            options[:payload]['data'][:tags] ||= []
            options[:payload]['data'][:tags] << second_tag
          end
        end
      end

      report_error

      [external.last_payload, oncall.last_payload]
    end

    it 'keeps stable fields and the same event id when order is swapped' do
      first_external, first_oncall = build_with_order('a', 'b')

      second_external, second_oncall = build_with_order('b', 'a')

      expect(first_external['data'][:uuid])
        .to be_eql(first_oncall['data'][:uuid])
      expect(second_external['data'][:uuid])
        .to be_eql(second_oncall['data'][:uuid])

      # Fields that describe the error itself must be identical regardless of
      # transform/destination order. Timestamp, uuid, pid and frame line
      # numbers are intentionally normalized since they are per-event values,
      # not part of the representation ordering is supposed to affect.
      comparable_keys = %i[level environment language framework body
                           notifier server]

      first_external_view = stable_view(first_external, comparable_keys)
      second_external_view = stable_view(second_external, comparable_keys)
      expect(second_external_view).to be_eql(first_external_view)

      first_oncall_view = stable_view(first_oncall, comparable_keys)
      second_oncall_view = stable_view(second_oncall, comparable_keys)
      expect(second_oncall_view).to be_eql(first_oncall_view)
    end

    it 'keeps fabricated internal data only at the permitted destination' do
      external, oncall = build_with_order('a', 'b')

      expect(oncall['data']).to include(:internal_only)
      expect(external['data']).not_to include(:internal_only)
    end
  end

  describe 'existing filter configuration' do
    it 'still ignores the report before any destination runs' do
      Rollbar.configure do |config|
        config.access_token = test_access_token
        config.transmit = false
        config.use_exception_level_filters_default = true
        config.exception_level_filters = { 'StandardError' => 'ignore' }
        config.add_destination(:rollbar, external_sender)
        config.add_destination(:oncall, oncall_sender)
      end

      result = begin
        raise StandardError, 'filtered'
      rescue StandardError => e
        Rollbar.error(e)
      end

      expect(result).to be_eql('ignored')
      expect(external_sender.count).to be_eql(0)
      expect(oncall_sender.count).to be_eql(0)
    end

    it 'still runs the global transform and before_process hooks once' do
      seen_levels = []

      Rollbar.configure do |config|
        config.access_token = test_access_token
        config.transmit = false
        config.before_process = proc { |options| seen_levels << options[:level] }
        config.transform = proc { |options| options[:payload]['data'][:global] = true }
        config.add_destination(:rollbar, external_sender)
        config.add_destination(:oncall, oncall_sender)
      end

      report_error

      expect(seen_levels).to be_eql(['error'])
      expect(external_sender.count).to be_eql(1)
      expect(oncall_sender.count).to be_eql(1)
      expect(external_sender.last_payload['data'][:global]).to be(true)
      expect(oncall_sender.last_payload['data'][:global]).to be(true)
    end
  end

  describe 'disabled notifier' do
    it 'does not fan out when the notifier is disabled' do
      Rollbar.configure do |config|
        config.access_token = nil
        config.transmit = false
        config.add_destination(:rollbar, external_sender)
        config.add_destination(:oncall, oncall_sender)
      end

      result = Rollbar.error(StandardError.new('muted'))

      expect(result).to be_eql('disabled')
      expect(external_sender.count).to be_eql(0)
      expect(oncall_sender.count).to be_eql(0)
    end
  end
end
