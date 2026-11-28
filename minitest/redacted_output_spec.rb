require File.expand_path(File.dirname(__FILE__) + '/test_helper')

describe "redacted WebMock output" do
  include HttpRequestTestHelper

  let(:stub_body) { { "amount" => 100, "card" => { "number" => "4111" } }.to_json }
  let(:matching_body) { { "amount" => 100, "card" => { "number" => "4111" } }.to_json }
  let(:differing_body) { { "amount" => 250, "card" => { "number" => "4242", "cvv" => "123" } }.to_json }

  let(:headers) do
    { "Content-Type" => "application/json", "Authorization" => "Bearer REAL_TOKEN" }
  end

  let(:uri) { "http://www.example.net/charge?api_key=SECRET_KEY&locale=en" }

  before do
    WebMock.disable_net_connect!
    stub_request(:post, "http://www.example.net/charge").
      with(body: stub_body,
           headers: { "Content-Type" => "application/json", "Authorization" => "Bearer STUB_TOKEN" })
  end

  after { WebMock.show_request_data! }

  def signature(body, authorization: "Bearer REAL_TOKEN", with_query: true)
    WebMock::RequestSignature.new(
      :post, with_query ? uri : "http://www.example.net/charge",
      body: body,
      headers: { "Content-Type" => "application/json", "Authorization" => authorization }
    )
  end

  def error_message(body)
    WebMock::NetConnectNotAllowedError.new(signature(body)).message
  end

  describe "with the default permissive policy" do
    it "renders the real request data unchanged" do
      message = error_message(differing_body)
      expect(message).must_include "SECRET_KEY"
      expect(message).must_include "REAL_TOKEN"
      expect(message).must_include "4242"
      expect(message).must_include "Body diff:"
    end

    it "renders the same signature text as RequestSignature#to_s" do
      sig = signature(differing_body)
      rendered = WebMock::RedactedRequestSignature.new(sig).to_s
      expect(rendered).must_equal sig.to_s
    end
  end

  describe "with full redaction turned on" do
    before { WebMock.redact_request_data! }

    it "still matches a compliant request using the real request" do
      stub = WebMock::StubRegistry.instance.request_stubs.first
      expect(stub.matches?(signature(matching_body, authorization: "Bearer STUB_TOKEN", with_query: false))).must_equal true
    end

    it "still rejects a request that differs from the stub" do
      stub = WebMock::StubRegistry.instance.request_stubs.first
      expect(stub.matches?(signature(differing_body))).must_equal false
    end

    it "keeps the full internal representation on the signature" do
      sig = signature(differing_body)
      expect(sig.body).must_include "4242"
      expect(sig.headers["Authorization"]).must_equal "Bearer REAL_TOKEN"
      expect(sig.uri.to_s).must_include "SECRET_KEY"
    end

    it "hides every secret from the exception, snippet and body diff" do
      message = error_message(differing_body)
      %w[SECRET_KEY REAL_TOKEN STUB_TOKEN 4242 4111 123 250 100 api_key Authorization amount cvv number].each do |secret|
        expect(message).wont_include secret
      end
      expect(message).must_include WebMock::RedactionPolicy::REDACTED
      # The diff still reports that two entries differ.
      expect(message).must_include "Body diff:"
    end

    it "redacts the request history shown by an expectation failure" do
      WebMock::RequestRegistry.instance.reset!
      WebMock::RequestRegistry.instance.requested_signatures.put(signature(differing_body))
      rendered = WebMock::RequestRegistry.instance.to_s
      expect(rendered).wont_include "SECRET_KEY"
      expect(rendered).wont_include "REAL_TOKEN"
      expect(rendered).wont_include "4242"
      expect(rendered).must_include WebMock::RedactionPolicy::REDACTED
    end
  end

  describe "comparing a compliant and a differing request" do
    it "the compliant request raises nothing while the differing one raises a redacted error" do
      WebMock.redact_request_data!
      stub = WebMock::StubRegistry.instance.request_stubs.first

      expect(stub.matches?(signature(matching_body, authorization: "Bearer STUB_TOKEN", with_query: false))).must_equal true

      differing_error = error_message(differing_body)
      expect(differing_error).must_include "Body diff:"
      expect(differing_error).wont_include "4242"
      expect(differing_error).wont_include "123"
    end
  end

  describe "independent switches" do
    it "hides only values when value redaction is enabled" do
      WebMock.hide_redacted_values!
      message = error_message(differing_body)
      expect(message).wont_include "4242"
      expect(message).must_include "amount"
      expect(message).must_include "api_key"
    end

    it "hides only field names when field name redaction is enabled" do
      WebMock.hide_redacted_field_names!
      message = error_message(differing_body)
      expect(message).wont_include "api_key"
      expect(message).wont_include "Authorization"
      expect(message).must_include "4242"
    end

    it "collapses structured bodies when structure redaction is enabled" do
      WebMock.hide_redacted_structures!
      message = error_message(differing_body)
      expect(message).must_include WebMock::RedactionPolicy::REDACTED
      expect(message).wont_include '"cvv"'
    end
  end
end
