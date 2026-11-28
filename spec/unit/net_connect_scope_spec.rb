require 'spec_helper'

describe WebMock::NetConnectScope do
  after do
    WebMock::NetConnectScopeRegistry.instance.reset!
    WebMock.disable_net_connect!
  end

  describe '#net_connect_allowed?' do
    it 'is false for every host when only denied' do
      scope = WebMock.disable_net_connect_scope
      scope.activate do
        expect(WebMock.net_connect_allowed?).to eq(false)
        expect(WebMock.net_connect_allowed?('http://example.com/')).to eq(false)
      end
    end

    it 'honours an allow list only while active' do
      scope = WebMock.disable_net_connect_scope(allow: 'example.com')
      scope.activate do
        expect(WebMock.net_connect_allowed?('http://example.com/')).to eq(true)
        expect(WebMock.net_connect_allowed?('http://other.com/')).to eq(false)
      end
    end

    it 'ignores a closed scope' do
      scope = WebMock.disable_net_connect_scope(allow: 'example.com')
      scope.close

      expect(scope.net_connect_allowed?('http://example.com/')).to eq(false)
    end
  end

  describe '#net_http_connect_on_start?' do
    it 'defaults to false' do
      scope = WebMock.disable_net_connect_scope(allow: 'example.com')
      scope.activate do
        uri = Addressable::URI.parse('http://example.com/')
        expect(WebMock.net_http_connect_on_start?(uri)).to eq(false)
      end
    end

    it 'matches a host allowlist' do
      scope = WebMock.disable_net_connect_scope(
        allow: 'example.com', net_http_connect_on_start: 'example.com'
      )
      scope.activate do
        expect(WebMock.net_http_connect_on_start?(
          Addressable::URI.parse('http://example.com/')
        )).to eq(true)
        expect(WebMock.net_http_connect_on_start?(
          Addressable::URI.parse('http://other.com/')
        )).to eq(false)
      end
    end
  end

  describe '#close' do
    it 'marks the scope closed and removes it from the registry' do
      registry = WebMock::NetConnectScopeRegistry.instance
      scope = WebMock.disable_net_connect_scope(allow: 'example.com')

      expect(scope.open?).to eq(true)
      scope.close

      expect(scope.closed?).to eq(true)
      expect(registry.instance_variable_get(:@scopes)).not_to include(scope)
    end
  end

  describe 'isolation' do
    it 'keeps concurrent per-thread scopes independent' do
      WebMock.disable_net_connect!
      first = WebMock.disable_net_connect_scope(allow: 'a.example.com')
      second = WebMock.disable_net_connect_scope(allow: 'b.example.com')
      observations = {}

      threads = [
        Thread.new do
          first.activate do
            sleep 0.01
            observations[:first] = [
              WebMock.net_connect_allowed?('http://a.example.com/'),
              WebMock.net_connect_allowed?('http://b.example.com/')
            ]
          end
        end,
        Thread.new do
          second.activate do
            sleep 0.01
            observations[:second] = [
              WebMock.net_connect_allowed?('http://a.example.com/'),
              WebMock.net_connect_allowed?('http://b.example.com/')
            ]
          end
        end
      ]
      threads.each(&:join)

      expect(observations[:first]).to eq([true, false])
      expect(observations[:second]).to eq([false, true])
    ensure
      first&.close
      second&.close
    end

    it 'does not change the global configuration' do
      WebMock.disable_net_connect!(allow: 'global.example.com')
      config = WebMock::Config.instance

      WebMock.disable_net_connect_scope(allow: 'scoped.example.com') do
        expect(config.allow).to eq('global.example.com')
        expect(config.allow_net_connect).to eq(false)
      end

      expect(config.allow).to eq('global.example.com')
    end

    it 'falls back to the global rules once every scope closes' do
      WebMock.allow_net_connect!
      scope = WebMock.disable_net_connect_scope(allow: 'scoped.example.com')
      scope.activate do
        expect(WebMock.net_connect_allowed?('http://other.example.com/')).to eq(false)
      end

      expect(WebMock.net_connect_allowed?('http://other.example.com/')).to eq(true)
    end
  end

  describe 'block form' do
    it 'closes the scope after the block' do
      scope = WebMock.disable_net_connect_scope(allow: 'example.com') { |active| active }
      expect(scope).to be_closed
    end

    it 'restores the enclosing scope' do
      outer = WebMock.disable_net_connect_scope(allow: 'outer.example.com')
      outer.activate do
        WebMock.disable_net_connect_scope(allow: 'inner.example.com') do
          expect(WebMock.net_connect_allowed?('http://inner.example.com/')).to eq(true)
          expect(WebMock.net_connect_allowed?('http://outer.example.com/')).to eq(false)
        end
        expect(WebMock.net_connect_allowed?('http://outer.example.com/')).to eq(true)
      end
    ensure
      outer&.close
    end
  end
end
