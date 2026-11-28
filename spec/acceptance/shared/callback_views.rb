shared_context "callback views" do |*adapter_info|
  describe "when an after_request callback declares a shared view" do
    before(:each) do
      @stub = stub_request(:get, "http://www.example.com").
        to_return(
          status: [200, "OK"],
          headers: {"X-Internal-Token" => "synthetic-secret"},
          body: "synthetic-payload"
        )
    end

    it "gives the observer only the declared fields" do
      observed = nil
      WebMock.after_request(shared_view: {request: [:method, :uri], response: [:status]}) do |request, response|
        observed = [request.fields, request.method, request.uri, response.fields, response.status]
      end
      http_request(:get, "http://www.example.com/")

      expect(observed).to eq([[:method, :uri], :get, "http://www.example.com:80/", [:status], [200, "OK"]])
    end

    it "keeps full parameters for callbacks without a view and does not let a view change them" do
      trusted = nil
      WebMock.after_request(shared_view: {request: [:uri], response: [:body]}) do |request, response|
        request.uri.replace("http://forged.example/")
        response.body.replace("synthetic-fake")
      end
      WebMock.after_request do |request, response|
        trusted = [request.uri.to_s, response.body, response.headers]
      end
      http_request(:get, "http://www.example.com/")

      expect(trusted[0]).to eq("http://www.example.com:80/")
      expect(trusted[1]).to eq("synthetic-payload")
      expect(trusted[2]["X-Internal-Token"]).to eq("synthetic-secret")
      expect(trusted[2]).not_to have_key("X-Forged")
    end

    it "contains an observer's error and keeps the executed request counts" do
      later_callbacks = []
      WebMock.after_request(shared_view: {request: [:method]}) { |_, _| raise "observer failed" }
      WebMock.after_request(shared_view: {request: [:uri]}) { |request, _| later_callbacks << request.uri }
      WebMock.after_request { |request, _| later_callbacks << request.uri.to_s }

      expect { http_request(:get, "http://www.example.com/") }.not_to raise_error

      expect(later_callbacks).to eq(["http://www.example.com:80/", "http://www.example.com:80/"])
      expect(a_request(:get, "http://www.example.com")).to have_been_made.once
      expect(WebMock::RequestRegistry.instance.requested_signatures.hash.size).to eq(1)
    end
  end
end
