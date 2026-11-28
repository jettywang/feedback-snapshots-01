require 'spec_helper'

RSpec.describe WebMock::RedactionPolicy do
  let(:data) do
    {
      "amount" => 250,
      "card" => { "number" => "4242" },
      "tags" => ["a", "b"]
    }
  end

  describe "the default policy" do
    it "is permissive and leaves data untouched" do
      policy = described_class.new
      expect(policy).to be_permissive
      expect(policy.redact(data)).to eq(data)
      expect(policy.redact_uri("https://e.com/x?a=1")).to eq("https://e.com/x?a=1")
    end
  end

  describe "hiding values" do
    subject(:policy) { described_class.new(show_values: false) }

    it "replaces scalars but keeps structure and field names" do
      redacted = policy.redact(data)
      expect(redacted["amount"]).to eq(WebMock::RedactionPolicy::REDACTED)
      expect(redacted["card"]).to eq("number" => WebMock::RedactionPolicy::REDACTED)
      expect(redacted["tags"]).to eq([WebMock::RedactionPolicy::REDACTED,
                                      WebMock::RedactionPolicy::REDACTED])
    end

    it "redacts query values while keeping parameter names" do
      expect(policy.redact_uri("https://e.com/x?api_key=SECRET")).
        to eq("https://e.com/x?api_key=#{WebMock::RedactionPolicy::REDACTED}")
    end
  end

  describe "hiding field names" do
    subject(:policy) { described_class.new(show_field_names: false) }

    it "replaces names but keeps values and structure" do
      expect(policy.redact("amount" => 250)).
        to eq(WebMock::RedactionPolicy::REDACTED => 250)
      expect(policy.redact("card" => { "number" => "4242" })).
        to eq(WebMock::RedactionPolicy::REDACTED => {
          WebMock::RedactionPolicy::REDACTED => "4242"
        })
    end

    it "redacts query parameter names while keeping values" do
      expect(policy.redact_uri("https://e.com/x?a=1")).
        to eq("https://e.com/x?#{WebMock::RedactionPolicy::REDACTED}=1")
    end
  end

  describe "hiding structures" do
    subject(:policy) { described_class.new(show_structures: false) }

    it "collapses hashes and arrays but keeps scalars" do
      expect(policy.redact(data)).to eq(WebMock::RedactionPolicy::REDACTED)
      expect(policy.redact(["x"])).to eq(WebMock::RedactionPolicy::REDACTED)
      expect(policy.redact("plain")).to eq("plain")
    end
  end

  describe "#redact_body_pattern" do
    it "parses and redacts a JSON string" do
      policy = described_class.new(show_values: false)
      expect(policy.redact_body_pattern('{"amount":5}')).
        to eq(%Q({"amount":"#{WebMock::RedactionPolicy::REDACTED}"}))
    end

    it "treats a non-JSON string as a single scalar" do
      policy = described_class.new(show_values: false)
      expect(policy.redact_body_pattern("abcdef")).
        to eq(WebMock::RedactionPolicy::REDACTED)
    end
  end

  describe "#redact_body_diff" do
    let(:diff) { [["~", "amount", 250, 100], ["-", ["card", "cvv"], "123"]] }

    it "keeps the operation and redacts values" do
      policy = described_class.new(show_values: false)
      expect(policy.redact_body_diff(diff)).to eq(
        [
          ["~", "amount", WebMock::RedactionPolicy::REDACTED, WebMock::RedactionPolicy::REDACTED],
          ["-", ["card", "cvv"], WebMock::RedactionPolicy::REDACTED]
        ]
      )
    end

    it "redacts path names but preserves array indices" do
      policy = described_class.new(show_field_names: false)
      expect(policy.redact_body_diff([["-", ["items", 0, "name"], "x"]])).
        to eq([["-", [WebMock::RedactionPolicy::REDACTED, 0,
                      WebMock::RedactionPolicy::REDACTED], "x"]])
    end
  end

  describe ".from_config" do
    after { WebMock.show_request_data! }

    it "reflects the global switches" do
      WebMock.hide_redacted_values!
      policy = described_class.from_config
      expect(policy).not_to be_permissive
      expect(policy.redact("secret")).to eq(WebMock::RedactionPolicy::REDACTED)
    end
  end
end
