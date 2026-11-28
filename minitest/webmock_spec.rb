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

  describe "WebMock stubbed response consumption contract" do
    include HttpRequestTestHelper

    def stream_get(uri_string, max_chunks: nil)
      uri = URI.parse(uri_string)
      chunks = []
      Net::HTTP.start(uri.host, uri.port) do |http|
        http.request_get(uri.path) do |response|
          response.read_body do |chunk|
            chunks << chunk
            break if max_chunks && chunks.size >= max_chunks
          end
        end
      end
      chunks.join
    end

    it "consumes one response per request when the stream completes" do
      stub_request(:get, "http://www.example.com/stream").
        to_return(body: "first").then.
        to_return(body: "second")

      assert_equal "first", stream_get("http://www.example.com/stream")
      assert_equal "second", stream_get("http://www.example.com/stream")
      # sequence exhausted: the last response is repeated
      assert_equal "second", stream_get("http://www.example.com/stream")
      assert_requested(:get, "http://www.example.com/stream", times: 3)
    end

    it "keeps the response consumed when the client stops reading after the first chunk" do
      stub_request(:get, "http://www.example.com/stream").
        to_return(body: "chunk-one").then.
        to_return(body: "chunk-two")

      assert_equal "chunk-one", stream_get("http://www.example.com/stream", max_chunks: 1)

      # the aborted response is not replayed: the next request gets the next response
      assert_equal "chunk-two", http_request(:get, "http://www.example.com/stream").body
      assert_requested(:get, "http://www.example.com/stream", times: 2)
    end

    it "keeps the response consumed and the request counted when an after_request callback raises" do
      callback_order = []
      WebMock.after_request do |request_signature, _response|
        callback_order << request_signature.uri.to_s
        raise "callback boom" if callback_order.size == 1
      end

      stub_request(:get, "http://www.example.com/stream").
        to_return(body: "first").then.
        to_return(body: "second")

      error = assert_raises(RuntimeError) { http_request(:get, "http://www.example.com/stream") }
      assert_equal "callback boom", error.message

      # the failed callback did not roll anything back: the retry gets the next response
      assert_equal "second", http_request(:get, "http://www.example.com/stream").body
      assert_requested(:get, "http://www.example.com/stream", times: 2)
      assert_equal(
        ["http://www.example.com:80/stream", "http://www.example.com:80/stream"],
        callback_order
      )
    end
  end

