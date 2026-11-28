require 'spec_helper'

describe WebMock::CallbackRegistry do
  before(:each) do
    WebMock::CallbackRegistry.reset
  end

  after(:each) do
    WebMock::CallbackRegistry.reset
  end

  let(:request_signature) do
    WebMock::RequestSignature.new(
      :post, "http://www.example.com/upload",
      body: "synthetic-payload",
      headers: {"Authorization" => "synthetic-token"}
    )
  end

  let(:response) do
    WebMock::Response.new(
      status: [200, "OK"],
      headers: {"X-Internal" => "synthetic-secret"},
      body: "synthetic-result"
    )
  end

  def callbacks_for(*args)
    WebMock::CallbackRegistry.invoke_callbacks({lib: :net_http}, *args)
  end

  describe "a callback without a shared view" do
    it "receives the real request signature and response objects" do
      received = nil
      WebMock::CallbackRegistry.add_callback({}, ->(request, res) { received = [request, res] })

      callbacks_for(request_signature, response)

      expect(received).to eq([request_signature, response])
      expect(received[0]).to be(request_signature)
      expect(received[1]).to be(response)
    end

    it "still propagates the errors it raises" do
      WebMock::CallbackRegistry.add_callback({}, ->(_request, _response) { raise "from trusted callback" })

      expect { callbacks_for(request_signature, response) }.to raise_error("from trusted callback")
    end
  end

  describe "a callback with a shared view" do
    it "exposes only the declared request and response fields" do
      received = nil
      WebMock::CallbackRegistry.add_callback(
        {shared_view: {request: [:method, :uri], response: [:status, :body]}},
        ->(request, res) { received = [request, res] }
      )

      callbacks_for(request_signature, response)

      request_view, response_view = received
      expect(request_view.method).to eq(:post)
      expect(request_view.uri).to eq("http://www.example.com:80/upload")
      expect(request_view.fields).to eq([:method, :uri])
      expect(request_view).not_to respond_to(:body)
      expect(request_view).not_to respond_to(:headers)
      expect(request_view).not_to be(request_signature)

      expect(response_view.status).to eq([200, "OK"])
      expect(response_view.body).to eq("synthetic-result")
      expect(response_view).not_to respond_to(:headers)
      expect(response_view).not_to be(response)
    end

    it "supports selecting only one side" do
      received = nil
      WebMock::CallbackRegistry.add_callback(
        {shared_view: {request: [:method]}},
        ->(request, res) { received = [request, res] }
      )

      callbacks_for(request_signature, response)
      expect(received[1]).to be_nil
    end

    it "hands out a separate copy to each observer" do
      first_view = second_view = nil
      WebMock::CallbackRegistry.add_callback(
        {shared_view: {request: [:uri]}},
        ->(request, _res) { first_view = request }
      )
      WebMock::CallbackRegistry.add_callback(
        {shared_view: {request: [:uri]}},
        ->(request, _res) { second_view = request }
      )

      callbacks_for(request_signature, response)

      expect(first_view).not_to be(second_view)
      first_view.uri.replace("http://forged.example/")
      expect(second_view.uri).to eq("http://www.example.com:80/upload")
    end

    it "does not let a mutating observer change the stored request or later callbacks" do
      mutated = nil
      later = nil
      WebMock::CallbackRegistry.add_callback(
        {shared_view: {request: [:uri, :body], response: [:headers, :body]}},
        ->(request, res) do
          request.uri.replace("http://forged.example/")
          request.body.replace("synthetic-fake")
          res.headers["X-Forged"] = "synthetic-fake"
          res.body.replace("synthetic-fake")
          mutated = [request.uri, res.headers]
        end
      )
      WebMock::CallbackRegistry.add_callback({}, ->(request, res) { later = [request, res] })

      expect { callbacks_for(request_signature, response) }.not_to raise_error

      expect(request_signature.uri.to_s).to eq("http://www.example.com:80/upload")
      expect(request_signature.body).to eq("synthetic-payload")
      expect(response.headers).to eq({"X-Internal" => "synthetic-secret"})
      expect(response.body).to eq("synthetic-result")
      expect(later).to eq([request_signature, response])
      expect(request_signature.to_s).not_to include("forged")
      expect(mutated).to eq(["http://forged.example/", {"X-Internal" => "synthetic-secret", "X-Forged" => "synthetic-fake"}])
    end

    it "contains an observer's error so later callbacks still run" do
      calls = []
      WebMock::CallbackRegistry.add_callback(
        {shared_view: {request: [:method]}},
        ->(_request, _res) { calls << :failing; raise "observer failed" }
      )
      WebMock::CallbackRegistry.add_callback({}, ->(_request, _res) { calls << :trusted })

      expect { callbacks_for(request_signature, response) }.not_to raise_error
      expect(calls).to eq([:failing, :trusted])
    end

    it "does not change the number of registrations or the matching of the request" do
      WebMock::CallbackRegistry.add_callback({shared_view: {request: [:method]}}, ->(_r, _s) {})
      expect(WebMock::CallbackRegistry.callbacks.size).to eq(1)

      callbacks_for(request_signature, response)

      expect(WebMock::CallbackRegistry.callbacks.size).to eq(1)
      expect(WebMock::RequestPattern.new(:post, "http://www.example.com/upload").matches?(request_signature)).to eq(true)
    end

    it "keeps real_requests_only and except filters" do
      called = []
      WebMock::CallbackRegistry.add_callback(
        {shared_view: {request: [:method]}, real_requests_only: true},
        ->(_request, _res) { called << :real }
      )
      WebMock::CallbackRegistry.add_callback(
        {shared_view: {request: [:method]}, except: [:net_http]},
        ->(_request, _res) { called << :excepted }
      )

      callbacks_for(request_signature, response)
      expect(called).to eq([])

      WebMock::CallbackRegistry.invoke_callbacks(
        {lib: :net_http, real_request: true}, request_signature, response
      )
      expect(called).to eq([:real])
    end

    it "rejects unsupported fields at registration time" do
      expect {
        WebMock::CallbackRegistry.add_callback({shared_view: {request: [:password]}}, ->(_r, _s) {})
      }.to raise_error(ArgumentError, /unsupported fields/)
      expect {
        WebMock::CallbackRegistry.add_callback({shared_view: {response: [:reason]}}, ->(_r, _s) {})
      }.to raise_error(ArgumentError, /unsupported fields/)
    end
  end
end
