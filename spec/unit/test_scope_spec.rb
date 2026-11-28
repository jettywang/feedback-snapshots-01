require 'spec_helper'

describe WebMock::TestScope do
  let(:url) { "http://www.example.com/" }

  after { WebMock.reset! }

  describe ".activate" do
    it "resolves the registries to the active scope and restores globals after" do
      global_stub_registry = WebMock::StubRegistry.instance
      global_request_registry = WebMock::RequestRegistry.instance

      WebMock::TestScope.activate do |scope|
        expect(WebMock::StubRegistry.instance).to be(scope.stub_registry)
        expect(WebMock::RequestRegistry.instance).to be(scope.request_registry)
      end

      expect(WebMock::StubRegistry.instance).to be(global_stub_registry)
      expect(WebMock::RequestRegistry.instance).to be(global_request_registry)
    end

    it "nests scopes and restores the parent on exit" do
      outer = WebMock::TestScope.new
      WebMock::TestScope.activate(outer) do
        expect(WebMock::TestScope.current).to be(outer)
        inner = WebMock::TestScope.new
        WebMock::TestScope.activate(inner) do
          expect(WebMock::TestScope.current).to be(inner)
        end
        expect(WebMock::TestScope.current).to be(outer)
      end
      expect(WebMock::TestScope.current).to be_nil
    end
  end

  describe "isolation" do
    it "keeps stubs and request counts private to each scope" do
      WebMock.scope do
        stub_request(:get, url).to_return(body: "a")
        Net::HTTP.get(URI(url))

        expect(a_request(:get, url)).to have_been_requested
        expect(WebMock::RequestRegistry.instance.times_executed(
          WebMock::RequestPattern.new(:get, url))).to eq(1)
      end

      expect(WebMock::RequestRegistry.instance.times_executed(
        WebMock::RequestPattern.new(:get, url))).to eq(0)
      expect(WebMock::StubRegistry.instance.response_for_request(
        WebMock::RequestSignature.new(:get, url))).to be_nil
    end

    it "rotates responses independently for two scopes on the same route" do
      responses = {}

      scope_a = WebMock::TestScope.new
      scope_b = WebMock::TestScope.new

      WebMock::TestScope.activate(scope_a) do
        stub_request(:get, url).to_return(
          { body: "a-fail" }, { body: "a-ok" })
      end

      WebMock::TestScope.activate(scope_b) do
        stub_request(:get, url).to_return(
          { body: "b-fail" }, { body: "b-ok" })
      end

      WebMock::TestScope.activate(scope_a) do
        responses[:a1] = Net::HTTP.get(URI(url))
      end
      WebMock::TestScope.activate(scope_b) do
        responses[:b1] = Net::HTTP.get(URI(url))
      end
      WebMock::TestScope.activate(scope_a) do
        responses[:a2] = Net::HTTP.get(URI(url))
      end
      WebMock::TestScope.activate(scope_b) do
        responses[:b2] = Net::HTTP.get(URI(url))
      end

      expect([responses[:a1], responses[:a2]]).to eq(["a-fail", "a-ok"])
      expect([responses[:b1], responses[:b2]]).to eq(["b-fail", "b-ok"])

      WebMock::TestScope.activate(scope_a) do
        expect(WebMock::RequestRegistry.instance.times_executed(
          WebMock::RequestPattern.new(:get, url))).to eq(2)
      end
      WebMock::TestScope.activate(scope_b) do
        expect(WebMock::RequestRegistry.instance.times_executed(
          WebMock::RequestPattern.new(:get, url))).to eq(2)
      end
    end
  end

  describe "shared stubs" do
    it "matches a parent's explicitly shared stub in a nested scope" do
      WebMock.scope do
        shared = stub_shared_request(:get, url).to_return(body: "shared")
        expect(WebMock.current_scope.shared_stubs).to eq([shared])

        WebMock.scope do
          expect(Net::HTTP.get(URI(url))).to eq("shared")
          expect(a_request(:get, url)).to have_been_requested
        end

        expect(WebMock::RequestRegistry.instance.times_executed(
          WebMock::RequestPattern.new(:get, url))).to eq(0)
      end
    end

    it "prefers a local stub over an inherited one" do
      WebMock.scope do
        stub_shared_request(:get, url).to_return(body: "shared")

        WebMock.scope do
          stub_request(:get, url).to_return(body: "local")
          expect(Net::HTTP.get(URI(url))).to eq("local")
        end
      end
    end
  end

  describe "named scopes" do
    it "reuses the same scope instance and its history" do
      WebMock.scope(:security) do
        stub_request(:get, url).to_return(body: "x")
        Net::HTTP.get(URI(url))
      end

      WebMock.scope(:security) do
        expect(WebMock::RequestRegistry.instance.times_executed(
          WebMock::RequestPattern.new(:get, url))).to eq(1)
      end
    end
  end
end
