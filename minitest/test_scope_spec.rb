require File.expand_path(File.dirname(__FILE__) + '/test_helper')

describe "WebMock::TestScope" do
  include HttpRequestTestHelper

  URL = "http://www.example.com/".freeze

  after do
    WebMock.reset!
  end

  it "keeps stubs private to the active scope" do
    WebMock.scope do
      stub_request(:get, URL).to_return(body: "scoped")
      assert_equal "scoped", http_request(:get, URL).body
    end

    # Outside the scope the global registry knows nothing about the stub.
    assert_raises(WebMock::NetConnectNotAllowedError) do
      http_request(:get, URL)
    end
  end

  it "preserves existing global usage without a scope" do
    stub_request(:get, URL).to_return(body: "global")
    assert_equal "global", http_request(:get, URL).body
    assert_requested(:get, URL, times: 1)
  end

  it "isolates response rotation for two groups stubbing the same route" do
    group_a = nil
    group_b = nil

    WebMock.scope do
      stub_request(:get, URL).to_return(
        { status: 500, body: "a-fail" },
        { status: 200, body: "a-ok" }
      )
      group_a = WebMock.current_scope

      WebMock.scope do
        stub_request(:get, URL).to_return(
          { status: 500, body: "b-fail" },
          { status: 200, body: "b-ok" }
        )
        group_b = WebMock.current_scope

        # Interleave requests on the same address across the two scopes.
        a1 = WebMock::TestScope.activate(group_a) { http_request(:get, URL) }
        b1 = http_request(:get, URL)
        a2 = WebMock::TestScope.activate(group_a) { http_request(:get, URL) }
        b2 = http_request(:get, URL)

        assert_equal ["a-fail", "a-ok"], [a1.body, a2.body]
        assert_equal ["b-fail", "b-ok"], [b1.body, b2.body]

        # Rotation position is owned by each scope's own stub.
        assert_requested(:get, URL, times: 2)
      end

      # Back in group A, its counter is unaffected by B's two requests.
      assert_requested(:get, URL, times: 2)
    end
  end

  it "records request counts against the active group only" do
    group_a = nil
    group_b = nil

    WebMock.scope do
      stub_request(:get, URL).to_return(body: "a")
      group_a = WebMock.current_scope

      WebMock.scope do
        stub_request(:get, URL).to_return(body: "b")
        group_b = WebMock.current_scope

        WebMock::TestScope.activate(group_a) { http_request(:get, URL) }
        http_request(:get, URL)
        http_request(:get, URL)

        assert_equal 2, WebMock::RequestRegistry.instance.
          times_executed(WebMock::RequestPattern.new(:get, URL))
      end

      assert_equal 1, WebMock::RequestRegistry.instance.
        times_executed(WebMock::RequestPattern.new(:get, URL))
    end

    # Nothing leaked into the global registry.
    assert_equal 0, WebMock::RequestRegistry.instance.
      times_executed(WebMock::RequestPattern.new(:get, URL))
  end

  it "ends one group midway while the other keeps working" do
    group_a = nil

    WebMock.scope do
      stub_request(:get, URL).to_return(
        { status: 500, body: "a-fail" },
        { status: 200, body: "a-ok" }
      )
      group_a = WebMock.current_scope
      assert_equal "a-fail", http_request(:get, URL).body
    end

    # Group A has ended: its stub no longer matches and the default
    # (net connect disabled) behaviour is observable again.
    assert_raises(WebMock::NetConnectNotAllowedError) do
      http_request(:get, URL)
    end

    # Group B, on the same address, starts fresh with its own rotation.
    WebMock.scope do
      stub_request(:get, URL).to_return(
        { status: 500, body: "b-fail" },
        { status: 200, body: "b-ok" }
      )
      assert_equal "b-fail", http_request(:get, URL).body
      assert_equal "b-ok", http_request(:get, URL).body
      assert_requested(:get, URL, times: 2)
    end

    # Reactivating the ended named group keeps its own history.
    WebMock::TestScope.activate(group_a) do
      stub_request(:get, URL).to_return(body: "a-more")
      assert_equal "a-more", http_request(:get, URL).body
      # The earlier failure is still recorded in group A's registry.
      assert_requested(:get, URL, times: 2)
    end
  end

  it "shares explicitly registered stubs with nested groups" do
    WebMock.scope do
      shared = stub_shared_request(:get, URL).to_return(body: "shared")

      WebMock.scope do
        # The nested group matches the parent's shared stub.
        assert_equal "shared", http_request(:get, URL).body
        assert_requested(:get, URL, times: 1)
      end

      # The nested group's request did not leak into the parent counts.
      assert_requested(:get, URL, times: 0)
      assert_equal shared, WebMock.current_scope.shared_stubs.first
    end
  end

  it "prefers a local stub over an inherited shared stub" do
    WebMock.scope do
      stub_shared_request(:get, URL).to_return(body: "shared")

      WebMock.scope do
        stub_request(:get, URL).to_return(body: "local")
        assert_equal "local", http_request(:get, URL).body
      end
    end
  end

  it "reuses named scopes across blocks" do
    WebMock.scope(:security) do
      stub_request(:get, URL).to_return(body: "named")
      http_request(:get, URL)
      assert_requested(:get, URL, times: 1)
    end

    WebMock.scope(:security) do
      # Same registry instance: the previously recorded request still counts.
      assert_requested(:get, URL, times: 1)
      http_request(:get, URL)
      assert_requested(:get, URL, times: 2)
    end
  end

  it "runs two groups truly in parallel without cross-talk" do
    errors = []
    mutex = Mutex.new
    condition = ConditionVariable.new
    ready = 0
    released = false

    threads = %i[a b].map do |name|
      Thread.new do
        begin
          WebMock.scope(name) do
            stub_request(:get, URL).to_return(
              { status: 500, body: "#{name}-fail" },
              { status: 200, body: "#{name}-ok" }
            )

            mutex.synchronize do
              ready += 1
              condition.broadcast
              condition.wait(mutex) until released
            end

            first = http_request(:get, URL)
            second = http_request(:get, URL)
            unless [first.body, second.body] == ["#{name}-fail", "#{name}-ok"]
              raise "#{name} rotation broken"
            end

            assert_requested(:get, URL, times: 2)
          end
        rescue => e
          mutex.synchronize { errors << e }
        end
      end
    end

    # Release both groups only after both have registered their stubs.
    mutex.synchronize do
      condition.wait(mutex) until ready == 2
      released = true
      condition.broadcast
    end
    threads.each(&:join)

    assert errors.empty?, errors.map(&:message).join("; ")
    assert_equal 0, WebMock::RequestRegistry.instance.
      times_executed(WebMock::RequestPattern.new(:get, URL))
  end
end
