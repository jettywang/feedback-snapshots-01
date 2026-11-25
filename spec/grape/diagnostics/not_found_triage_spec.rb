# frozen_string_literal: true

require_relative '../../../diagnostics/synthetic_mounts'

# Pins the three evidence classes behind the 404-triage convention in
# diagnostics/README.md: one external 404 for different internal stages,
# method-not-supported with its public Allow, and the authorized success.
RSpec.describe 'Diagnostics 404 triage' do
  def events_for(result, mount)
    result.events.select { |event| event[:mount] == mount }
  end

  describe 'one external 404, different internal stages' do
    it 'answers an unregistered path with 404 that never entered the identity middleware' do
      result = Diagnostics.call('GET', '/v1/nope', token: 'ops-alice')

      expect(result.status).to eq(404)
      expect(result.body).to eq('Not Found')
      expect(result.allow).to be_nil
      expect(result.headers['x-cascade']).to be_nil
      expect(events_for(result, 'ledger').map { |event| event[:event] }).to eq(%w[no_candidate])
      expect(events_for(result, 'reports').map { |event| event[:event] }).to eq(%w[no_candidate])
    end

    it 'answers a rejected version with the same 404, stopped at version negotiation' do
      result = Diagnostics.call('GET', '/reports?apiver=v9', token: 'ops-alice')

      expect(result.status).to eq(404)
      expect(result.body).to eq('Not Found')
      expect(events_for(result, 'reports').map { |event| event[:event] })
        .to eq(%w[candidate_matched entered allowed rejected])
      expect(result.terminal_stage).to eq('reports/version:rejected')
    end

    it 'answers a policy-hidden route with the same 404, stopped at the identity gate' do
      result = Diagnostics.call('GET', '/v1/ledger/hidden', token: 'ops-alice')

      expect(result.status).to eq(404)
      expect(result.body).to eq('Not Found')
      expect(events_for(result, 'ledger').map { |event| event[:event] })
        .to eq(%w[candidate_matched entered denied])
      # A denial carries no X-Cascade, so the second mount is never consulted.
      expect(events_for(result, 'reports')).to be_empty
    end
  end

  describe 'method not supported' do
    it 'answers 405 with a public Allow header, confirmed twice internally' do
      result = Diagnostics.call('POST', '/v1/ledger', token: 'ops-alice')

      expect(result.status).to eq(405)
      expect(result.allow).to eq('OPTIONS, GET, HEAD')
      expect(events_for(result, 'ledger').map { |event| event[:event] })
        .to include('allow_readable', 'method_not_allowed')
    end

    it 'answers auto-OPTIONS with 204 and the same Allow' do
      result = Diagnostics.call('OPTIONS', '/v1/ledger', token: 'ops-alice')

      expect(result.status).to eq(204)
      expect(result.allow).to eq('OPTIONS, GET, HEAD')
    end

    it 'suppresses Allow on a hidden path for an identity the policy hides it from' do
      result = Diagnostics.call('POST', '/v1/ledger/hidden', token: 'ops-alice')

      expect(result.status).to eq(404)
      expect(result.allow).to be_nil
      expect(result.terminal_stage).to eq('ledger/identity:denied')
    end

    it 'confirms Allow on a hidden path for the authorized identity' do
      result = Diagnostics.call('POST', '/v1/ledger/hidden', token: 'root-admin')

      expect(result.status).to eq(405)
      expect(result.allow).to eq('OPTIONS, GET, HEAD')
    end
  end

  describe 'authorized action success' do
    it 'answers the hidden route to the authorized identity' do
      result = Diagnostics.call('GET', '/v1/ledger/hidden', token: 'root-admin')

      expect(result.status).to eq(200)
      expect(result.body).to eq('{"ledger":"off-book"}')
      expect(result.terminal_stage).to eq('ledger/endpoint:executed')
    end

    it 'answers a public route through the cascade to the second mount' do
      result = Diagnostics.call('GET', '/reports?apiver=v2', token: 'ops-alice')

      expect(result.status).to eq(200)
      expect(events_for(result, 'ledger').map { |event| event[:event] }).to eq(%w[no_candidate])
      expect(result.terminal_stage).to eq('reports/endpoint:executed')
    end
  end
end
