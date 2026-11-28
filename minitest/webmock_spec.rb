require File.expand_path(File.dirname(__FILE__) + '/test_helper')

  describe "Webmock" do
    include HttpRequestTestHelper

    before do
      @stub_http = stub_http_request(:any, "http://www.example.com")
      @stub_https = stub_http_request(:any, "https://www.example.com")
    end

    it "should update assertions count" do
      assert_equal 0, assertions
      http_request(:get, "http://www.example.com/")

      assert_requested(@stub_http)
      assert_equal 2, assertions

      assert_not_requested(:post, "http://www.example.com")
      assert_equal 4, assertions
    end

    it "should raise error on non stubbed request" do
      expect { http_request(:get, "http://www.example.net/") }.must_raise(WebMock::NetConnectNotAllowedError)
    end

    it "should verify that expected request occured" do
      http_request(:get, "http://www.example.com/")
      assert_requested(:get, "http://www.example.com", times: 1)
      assert_requested(:get, "http://www.example.com")
    end

    it "should verify that expected http stub occured" do
      http_request(:get, "http://www.example.com/")
      assert_requested(@stub_http, times: 1)
      assert_requested(@stub_http)
    end

    it "should verify that expected https stub occured" do
      http_request(:get, "https://www.example.com/")
      http_request(:get, "https://www.example.com/")
      assert_requested(@stub_https, times: 2)
    end

    it  "should verify that expect request didn't occur" do
     expected_message = "The request GET http://www.example.com/ was expected to execute 1 time but it executed 0 times"
     expected_message += "\n\nThe following requests were made:\n\nNo requests were made.\n============================================================"
     assert_fail(expected_message) do
       assert_requested(:get, "http://www.example.com")
     end
    end

    it  "should verify that expect stub didn't occur" do
     expected_message = "The request ANY http://www.example.com/ was expected to execute 1 time but it executed 0 times"
     expected_message += "\n\nThe following requests were made:\n\nNo requests were made.\n============================================================"
     assert_fail(expected_message) do
       assert_requested(@stub_http)
     end
    end
  end


  describe "shared callback views" do
    include HttpRequestTestHelper

    before do
      WebMock.reset_callbacks
      WebMock.reset!
      @stub = stub_request(:get, "http://www.example.com").
        to_return(
          status: [200, "OK"],
          headers: {"X-Internal-Token" => "synthetic-secret"},
          body: "synthetic-payload"
        )
    end

    after do
      WebMock.reset_callbacks
    end

    it "gives a shared observer only its declared fields and no internal values" do
      observed = nil
      WebMock.after_request(
        shared_view: {request: [:method, :uri], response: [:status]}
      ) do |request, response|
        observed = [request.method, request.uri, response.status]
        assert_equal [:method, :uri], request.fields
        assert_equal [:status], response.fields
        assert_raises(NoMethodError) { request.body }
        assert_raises(NoMethodError) { response.headers }
      end

      http_request(:get, "http://www.example.com/")

      assert_equal [:get, "http://www.example.com:80/", [200, "OK"]], observed
    end

    it "keeps full parameters for trusted callbacks registered without a view" do
      trusted = nil
      WebMock.after_request do |request, response|
        trusted = [request, response]
      end

      http_request(:get, "http://www.example.com/")

      assert_same true, WebMock::RequestRegistry.instance.requested_signatures.
        hash.keys.first.equal?(trusted[0])
      assert_equal "synthetic-payload", trusted[1].body
      assert_equal "synthetic-secret", trusted[1].headers["X-Internal-Token"]
    end

    it "does not let an observer's mutation or error change the record, later callbacks or counts" do
      later_observations = []
      raised = false

      WebMock.after_request(
        shared_view: {request: [:uri], response: [:body]}
      ) do |request, response|
        request.uri.replace("http://forged.example/")
        request.headers["X-Forged"] = "synthetic-fake" rescue nil
        response.body.replace("synthetic-fake")
      end

      WebMock.after_request(
        shared_view: {request: [:method], response: [:status]}
      ) do |_request, _response|
        raised = true
        raise "observer failed"
      end

      WebMock.after_request do |request, response|
        later_observations << [request.uri.to_s, request.headers, response.body]
      end

      http_request(:get, "http://www.example.com/")

      assert_equal true, raised
      assert_requested(@stub, times: 1)
      assert_equal 1, WebMock::RequestRegistry.instance.times_executed(
        WebMock::RequestPattern.new(:get, "http://www.example.com")
      )
      assert_equal 1, WebMock::RequestRegistry.instance.requested_signatures.hash.size

      assert_equal "http://www.example.com:80/", later_observations[0][0]
      refute_includes later_observations[0][1].keys, "X-Forged"
      assert_equal "synthetic-payload", later_observations[0][2]
      refute_includes later_observations[0][1].values, "synthetic-fake"
    end

    it "does not leak synthetic values outside the observer either" do
      WebMock.after_request(
        shared_view: {request: [:body], response: [:headers]}
      ) { |request, response| assert_equal "synthetic-secret", response.headers["X-Internal-Token"] }

      http_request(:get, "http://www.example.com/")

      executed = WebMock::RequestRegistry.instance.requested_signatures.hash.keys.first.to_s
      refute_includes executed, "X-Internal-Token"
    end

    it "rejects unsupported fields at registration" do
      error = assert_raises(ArgumentError) do
        WebMock.after_request(shared_view: {request: [:password]}) { |_, _| }
      end
      assert_match(/unsupported fields/, error.message)
    end
  end
