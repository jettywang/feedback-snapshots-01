require 'spec_helper'

RSpec.describe "redacted failure output" do
  let(:stub_body) { { "amount" => 100, "card" => { "number" => "4111" } }.to_json }
  let(:matching_body) { stub_body }
  let(:differing_body) do
    { "amount" => 250, "card" => { "number" => "4242", "cvv" => "123" } }.to_json
  end
  let(:uri) { "http://example.net/charge?api_key=SECRET_KEY&locale=en" }

  def signature(body, authorization: "Bearer REAL_TOKEN", with_query: true)
    WebMock::RequestSignature.new(
      :post,
      with_query ? uri : "http://example.net/charge",
      body: body,
      headers: { "Content-Type" => "application/json", "Authorization" => authorization }
    )
  end

  before do
    WebMock.disable_net_connect!
    WebMock.stub_request(:post, "http://example.net/charge").
      with(
        body: stub_body,
        headers: { "Content-Type" => "application/json",
                   "Authorization" => "Bearer STUB_TOKEN" }
      )
  end

  after { WebMock.show_request_data! }

  describe "with the default permissive policy" do
    it "renders the real request data" do
      message = WebMock::NetConnectNotAllowedError.new(signature(differing_body)).message
      expect(message).to include("SECRET_KEY", "REAL_TOKEN", "4242", "Body diff:")
    end

    it "renders the same text as RequestSignature#to_s" do
      sig = signature(differing_body)
      expect(WebMock::RedactedRequestSignature.new(sig).to_s).to eq(sig.to_s)
    end
  end

  describe "with full redaction enabled" do
    before { WebMock.redact_request_data! }

    let(:stub) { WebMock::StubRegistry.instance.request_stubs.first }

    it "still matches a compliant request using the real request" do
      expect(stub.matches?(signature(matching_body,
                                     authorization: "Bearer STUB_TOKEN",
                                     with_query: false))).to be(true)
    end

    it "still rejects a request that differs from the stub" do
      expect(stub.matches?(signature(differing_body, with_query: false))).to be(false)
    end

    it "keeps the full internal representation on the signature" do
      sig = signature(differing_body)
      expect(sig.body).to include("4242")
      expect(sig.headers["Authorization"]).to eq("Bearer REAL_TOKEN")
      expect(sig.uri.to_s).to include("SECRET_KEY")
    end

    it "hides every secret from the exception, snippet and body diff" do
      message = WebMock::NetConnectNotAllowedError.new(signature(differing_body)).message
      %w[SECRET_KEY REAL_TOKEN STUB_TOKEN 4242 4111 123 250 100 api_key
         Authorization amount cvv number].each do |secret|
        expect(message).not_to include(secret)
      end
      expect(message).to include(WebMock::RedactionPolicy::REDACTED)
      expect(message).to include("Body diff:")
    end

    it "redacts the request history from an expectation failure" do
      WebMock::RequestRegistry.instance.reset!
      WebMock::RequestRegistry.instance.requested_signatures.put(signature(differing_body))
      rendered = WebMock::RequestRegistry.instance.to_s
      expect(rendered).not_to include("SECRET_KEY", "REAL_TOKEN", "4242")
      expect(rendered).to include(WebMock::RedactionPolicy::REDACTED)
    end
  end

  describe "the independent switches" do
    it "hides only values" do
      WebMock.hide_redacted_values!
      message = WebMock::NetConnectNotAllowedError.new(signature(differing_body)).message
      expect(message).not_to include("4242")
      expect(message).to include("amount", "api_key")
    end

    it "hides only field names" do
      WebMock.hide_redacted_field_names!
      message = WebMock::NetConnectNotAllowedError.new(signature(differing_body)).message
      expect(message).not_to include("api_key", "Authorization")
      expect(message).to include("4242")
    end

    it "collapses structured bodies" do
      WebMock.hide_redacted_structures!
      message = WebMock::NetConnectNotAllowedError.new(signature(differing_body)).message
      expect(message).to include(WebMock::RedactionPolicy::REDACTED)
      expect(message).not_to include('"cvv"')
    end
  end
end
