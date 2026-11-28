require File.expand_path(File.dirname(__FILE__) + '/test_helper')

describe WebMock::RedactionPolicy do
  R = WebMock::RedactionPolicy
  let(:data) do
    {
      "amount" => 250,
      "card" => { "number" => "4242", "cvv" => "123" },
      "tags" => ["a", "b"]
    }
  end

  describe "a permissive policy" do
    it "is permissive by default and leaves data untouched" do
      policy = R.new
      expect(policy.permissive?).must_equal true
      expect(policy.redact(data)).must_equal data
    end

    it "leaves a uri untouched" do
      policy = R.new
      uri = "https://example.com/x?a=1&b=2"
      expect(policy.redact_uri(uri)).must_equal uri
    end
  end

  describe "hiding values only" do
    let(:policy) { R.new(show_values: false) }

    it "keeps structures and field names but replaces scalar values" do
      redacted = policy.redact(data)
      expect(redacted["amount"]).must_equal R::REDACTED
      expect(redacted["card"]["number"]).must_equal R::REDACTED
      expect(redacted["card"].keys).must_equal ["number", "cvv"]
      expect(redacted["tags"]).must_equal [R::REDACTED, R::REDACTED]
    end

    it "redacts query values but keeps parameter names" do
      expect(policy.redact_uri("https://e.com/x?api_key=SECRET&locale=en")).
        must_equal "https://e.com/x?api_key=#{R::REDACTED}&locale=#{R::REDACTED}"
    end
  end

  describe "hiding field names only" do
    let(:policy) { R.new(show_field_names: false) }

    it "keeps values and structure but replaces names" do
      expect(policy.redact("amount" => 250)).must_equal(R::REDACTED => 250)
      expect(policy.redact("card" => { "number" => "4242" })).
        must_equal(R::REDACTED => { R::REDACTED => "4242" })
      expect(policy.redact(["a", "b"])).must_equal ["a", "b"]
    end

    it "redacts query parameter names but keeps values" do
      expect(policy.redact_uri("https://e.com/x?a=1")).
        must_equal "https://e.com/x?#{R::REDACTED}=1"
    end
  end

  describe "hiding structures only" do
    let(:policy) { R.new(show_structures: false) }

    it "collapses hashes and arrays to a single marker" do
      expect(policy.redact(data)).must_equal R::REDACTED
      expect(policy.redact([1, 2])).must_equal R::REDACTED
    end

    it "keeps scalar values visible" do
      expect(policy.redact("plain")).must_equal "plain"
      expect(policy.redact(7)).must_equal 7
    end

    it "leaves the query string untouched since its flat structure stays visible" do
      expect(policy.redact_uri("https://e.com/x?a=1&b=2")).
        must_equal "https://e.com/x?a=1&b=2"
    end
  end

  describe "hiding everything" do
    let(:policy) { R.new(show_structures: false, show_field_names: false, show_values: false) }

    it "collapses any structure to the marker" do
      expect(policy.redact(data)).must_equal R::REDACTED
      expect(policy.redact("scalar")).must_equal R::REDACTED
    end

    it "redacts query names and values" do
      expect(policy.redact_uri("https://e.com/x?a=1")).
        must_equal "https://e.com/x?#{R::REDACTED}=#{R::REDACTED}"
    end
  end

  describe "#redact_body_pattern" do
    let(:policy) { R.new(show_values: false) }

    it "redacts a hash pattern as data" do
      expect(policy.redact_body_pattern("amount" => 5)).
        must_equal("amount" => R::REDACTED)
    end

    it "parses and redacts a JSON string pattern" do
      expect(policy.redact_body_pattern('{"amount":5}')).
        must_equal %Q({"amount":"#{R::REDACTED}"})
    end

    it "treats a non-JSON string as a single scalar" do
      expect(policy.redact_body_pattern("abcdef")).must_equal R::REDACTED
    end
  end

  describe "#redact_body_diff" do
    let(:body_diff_entries) do
      [["~", "amount", 250, 100], ["-", ["card", "cvv"], "123"]]
    end

    it "keeps operations and redacts values when values are hidden" do
      policy = R.new(show_values: false)
      expect(policy.redact_body_diff(body_diff_entries)).must_equal [
        ["~", "amount", R::REDACTED, R::REDACTED],
        ["-", ["card", "cvv"], R::REDACTED]
      ]
    end

    it "redacts path names when field names are hidden but keeps indices" do
      policy = R.new(show_field_names: false)
      redacted = policy.redact_body_diff([["-", ["items", 0, "name"], "x"]])
      expect(redacted).must_equal [["-", [R::REDACTED, 0, R::REDACTED], "x"]]
    end

    it "redacts nested hashes carried by an entry" do
      policy = R.new(show_values: false)
      redacted = policy.redact_body_diff([["-", "card", { "cvv" => "123" }]])
      expect(redacted).must_equal [["-", "card", { "cvv" => R::REDACTED }]]
    end
  end

  describe ".from_config" do
    after { WebMock.show_request_data! }

    it "builds a restrictive policy from the global config switches" do
      WebMock.hide_redacted_values!
      policy = R.from_config
      expect(policy.permissive?).must_equal false
      expect(policy.redact("secret")).must_equal R::REDACTED
    end
  end
end
