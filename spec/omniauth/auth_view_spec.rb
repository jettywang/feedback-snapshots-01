require 'helper'

describe OmniAuth::AuthView do
  let(:auth) do
    OmniAuth::AuthHash.new(
      'provider' => 'local',
      'uid' => 'user-1',
      'info' => {
        'name' => 'Alice',
        'email' => 'alice@example.test',
        'roles' => ['admin', {'tenant' => 'acme'}]
      },
      'credentials' => {'token' => 'secret-token'},
      'extra' => {'raw' => {'label' => 'raw-label'}}
    )
  end

  it 'projects dotted fields and detaches nested hashes, arrays, and strings' do
    view = described_class.project(
      auth,
      :fields => ['provider', 'uid', 'info.name', 'info.roles'],
      :correlation_id => 'corr-1'
    )

    expect(view['provider']).to eq('local')
    expect(view['uid']).to eq('user-1')
    expect(view['info']['name']).to eq('Alice')
    expect(view['info']['roles']).to eq(['admin', {'tenant' => 'acme'}])
    expect(view.to_hash).not_to have_key('credentials')
    expect(view['info'].to_hash).not_to have_key('email')

    view['info']['name'] << ' mutated'
    view['info']['roles'][0] << '-mutated'
    view['info']['roles'][1]['tenant'] = 'mutated'

    expect(auth['info']['name']).to eq('Alice')
    expect(auth['info']['roles'][0]).to eq('admin')
    expect(auth['info']['roles'][1]['tenant']).to eq('acme')
  end

  it 'supports nested hash rules, the only alias, and a custom correlation key' do
    view = described_class.new(
      :only => [{'info' => [:name, :roles]}],
      :correlation_key => 'association_id'
    ).project(auth, :correlation_id => 'assoc-1')

    expect(view.to_hash.keys).to contain_exactly('info', 'association_id')
    expect(view['info']['name']).to eq('Alice')
    expect(view['info']['roles'][0]).to eq('admin')
    expect(view['info']['roles'][1]['tenant']).to eq('acme')
    expect(view['association_id']).to eq('assoc-1')
  end

  it 'maps a source path to a differently named target path' do
    view = described_class.new
      .map('extra.raw.label', 'summary.label')
      .add('uid')
      .project(auth, :correlation_id => 'corr-2')

    expect(view['summary']['label']).to eq('raw-label')
    expect(view['uid']).to eq('user-1')
  end

  it 'supports boolean hash rules and directly nested arrays' do
    view = described_class.new(:fields => [{'uid' => true}]).tap do |policy|
      policy.add([:provider])
    end.project(auth, :correlation_id => 'corr-3')

    expect(view['uid']).to eq('user-1')
    expect(view['provider']).to eq('local')
  end

  it 'can project every field as an isolated copy' do
    view = described_class.project(auth, :fields => :all, :correlation_id => 'corr-4')
    view['credentials']['token'] << '-mutated'

    expect(view['credentials']['token']).to eq('secret-token-mutated')
    expect(auth['credentials']['token']).to eq('secret-token')
  end

  it 'does not add calculated InfoHash fields to a strict subset' do
    view = described_class.project(
      {'info' => {'email' => 'alice@example.test'}},
      :fields => ['info.email'],
      :correlation_id => 'c'
    )

    expect(view['info'].to_hash.keys).to eq(['email'])
  end

  it 'omits missing source paths' do
    view = described_class.project(auth, :fields => ['uid', 'missing.deep'], :correlation_id => 'c')

    expect(view.to_hash.keys).to contain_exactly('uid', 'correlation_id')
  end

  it 'generates a correlation id and accepts nil or array-convertible identities' do
    expect(described_class.project(nil).correlation_id).to be_a(String)

    view = described_class.project([['uid', 'array-user']], :fields => ['uid'], :correlation_id => 'c')
    expect(view['uid']).to eq('array-user')
  end

  it 'returns immutable fallback values from deep duplication' do
    item = Class.new do
      def dup
        raise TypeError, 'cannot dup'
      end
    end.new

    expect(described_class.deep_dup(item)).to equal(item)
  end

  it 'rejects unsupported field rules' do
    expect do
      described_class.new(:fields => [{'uid' => 123}])
    end.to raise_error(ArgumentError, /unsupported auth view field rule/)
  end

  describe OmniAuth::AuthView::Registry do
    it 'registers and projects named policies' do
      registry = described_class.new
      policy = OmniAuth::AuthView.new(:fields => ['uid'])
      registry.register(:plugin, policy)

      expect(registry.key?('plugin')).to be(true)
      expect(registry.names).to eq([:plugin])
      expect(registry['plugin']).to equal(policy)
      expect(registry.project(:plugin, {'uid' => 'u'}, :correlation_id => 'c')['uid']).to eq('u')

      registry.clear
      expect(registry.names).to be_empty
    end
  end
end
