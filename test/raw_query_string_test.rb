require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

require 'onelogin/ruby-saml/slo_logoutrequest'

class RubySamlRawQueryStringTest < Minitest::Test

  describe "Utils.parse_raw_query_string" do
    it "preserves the exact received bytes without decoding" do
      raw = OneLogin::RubySaml::Utils.parse_raw_query_string(
        "SAMLRequest=a%2Bb&RelayState=http%3A%2F%2Fex%61mple.com&SigAlg=x%2fy&Signature=Zq%2F%2B"
      )
      assert_equal "a%2Bb", raw['SAMLRequest']
      assert_equal "http%3A%2F%2Fex%61mple.com", raw['RelayState']
      assert_equal "x%2fy", raw['SigAlg']
      assert_equal "Zq%2F%2B", raw['Signature']
    end

    it "keeps an empty RelayState as empty string and an absent one as missing" do
      raw = OneLogin::RubySaml::Utils.parse_raw_query_string("SAMLRequest=abc&RelayState=&SigAlg=x")
      assert_equal "", raw['RelayState']

      raw = OneLogin::RubySaml::Utils.parse_raw_query_string("SAMLRequest=abc&SigAlg=x")
      assert_nil raw['RelayState']
    end

    it "rejects duplicate SAML security parameters" do
      %w[SAMLRequest SAMLResponse RelayState SigAlg Signature].each do |param|
        error = assert_raises(ArgumentError) do
          OneLogin::RubySaml::Utils.parse_raw_query_string("#{param}=a&#{param}=b")
        end
        assert_match(/Duplicate parameter '#{param}'/, error.message)
      end
    end

    it "rejects malformed percent-encoding on SAML security parameters" do
      ["RelayState=%zz", "RelayState=%2", "RelayState=a%"].each do |query|
        error = assert_raises(ArgumentError) do
          OneLogin::RubySaml::Utils.parse_raw_query_string(query)
        end
        assert_match(/Invalid percent-encoding/, error.message)
      end
    end

    it "ignores duplicates of parameters not covered by the signature" do
      raw = OneLogin::RubySaml::Utils.parse_raw_query_string("foo=1&foo=2&SAMLRequest=abc")
      assert_equal "1", raw['foo']
    end

    it "raises if the query string is not a String" do
      assert_raises(ArgumentError) { OneLogin::RubySaml::Utils.parse_raw_query_string(nil) }
    end
  end

  describe "Utils.decode_raw_params" do
    it "decodes the raw parts once, so parsed params match the signed bytes" do
      decoded = OneLogin::RubySaml::Utils.decode_raw_params(
        'RelayState' => "token+with%20space%2Band%2Bplus"
      )
      assert_equal "token with space+and+plus", decoded['RelayState']
    end

    it "decodes percent-encoded UTF-8" do
      decoded = OneLogin::RubySaml::Utils.decode_raw_params(
        'RelayState' => downcased_escape("café 中文")
      )
      assert_equal "café 中文", decoded['RelayState']
    end
  end

  describe "HTTP-Redirect binding signature verification from the raw query string" do
    let(:settings) do
      s = OneLogin::RubySaml::Settings.new
      s.idp_cert = ruby_saml_cert_text
      s.soft = false
      s
    end

    # Simulates the IdP: builds a real LogoutRequest, assembles the raw query
    # string with the exact encodings the IdP chose, and signs those bytes with
    # the local private key (ruby-saml.key / ruby-saml.crt fixtures).
    def signed_redirect_query(relay_state_raw: nil, include_relay_state: false,
                              sig_alg: XMLSecurity::Document::RSA_SHA1)
      request_doc = OneLogin::RubySaml::Logoutrequest.new.create_logout_request_xml_doc(
        OneLogin::RubySaml::Settings.new
      )
      deflated = Zlib::Deflate.deflate(request_doc.to_s, 9)[2..-5]
      raw_request = CGI.escape(Base64.encode64(deflated).gsub(/\n/, ""))

      query = "SAMLRequest=#{raw_request}"
      query << "&RelayState=#{relay_state_raw}" if include_relay_state
      query << "&SigAlg=#{CGI.escape(sig_alg)}"

      sign_algorithm = XMLSecurity::BaseDocument.new.algorithm(sig_alg)
      signature = ruby_saml_key.sign(sign_algorithm.new, query)
      "#{query}&Signature=#{CGI.escape(Base64.encode64(signature).gsub(/\n/, ""))}"
    end

    # Simulates the application integration: parse the raw query string first
    # (rejecting ambiguous input before any SAML content is touched), decode
    # the very same raw parts, and hand both to the public validator.
    def slo_logout_request_from_query(query, settings)
      raw_params = OneLogin::RubySaml::Utils.parse_raw_query_string(query)
      get_params = OneLogin::RubySaml::Utils.decode_raw_params(raw_params)
      OneLogin::RubySaml::SloLogoutrequest.new(
        get_params['SAMLRequest'],
        :settings => settings,
        :get_params => get_params,
        :raw_get_params => raw_params
      )
    end

    # Simulates a web framework (Rack/Rails style) that hands the app only
    # decoded parameters.
    def framework_decoded_params(query)
      decoded = {}
      CGI.parse(query).each { |key, values| decoded[key] = values.first }
      decoded
    end

    it "verifies a request without RelayState" do
      query = signed_redirect_query
      assert slo_logout_request_from_query(query, settings).is_valid?
    end

    it "verifies a request with an empty RelayState" do
      query = signed_redirect_query(:relay_state_raw => "", :include_relay_state => true)
      raw = OneLogin::RubySaml::Utils.parse_raw_query_string(query)
      assert_equal "", raw['RelayState']
      assert slo_logout_request_from_query(query, settings).is_valid?
    end

    it "verifies a RelayState with spaces encoded as %20" do
      query = signed_redirect_query(
        :relay_state_raw => "http%3A%2F%2Fexample.com%2Fcb%20a%20b",
        :include_relay_state => true
      )
      assert slo_logout_request_from_query(query, settings).is_valid?
    end

    it "verifies a RelayState with spaces encoded as +" do
      query = signed_redirect_query(
        :relay_state_raw => "token+with+spaces",
        :include_relay_state => true
      )
      slo = slo_logout_request_from_query(query, settings)
      assert slo.is_valid?
      assert_equal "token with spaces", slo.options[:get_params]['RelayState']
    end

    it "verifies a RelayState with lowercase percent-encoding" do
      query = signed_redirect_query(
        :relay_state_raw => "http%3a%2f%2fexample.com%2fcb",
        :include_relay_state => true
      )
      assert slo_logout_request_from_query(query, settings).is_valid?
    end

    it "verifies a Unicode RelayState with downcased UTF-8 percent-encoding" do
      relay_state_raw = downcased_escape("café 中文")
      query = signed_redirect_query(
        :relay_state_raw => relay_state_raw,
        :include_relay_state => true
      )
      slo = slo_logout_request_from_query(query, settings)
      assert slo.is_valid?
      assert_equal "café 中文", slo.options[:get_params]['RelayState']
    end

    it "verifies the exact received bytes, not a re-encoded variant" do
      query = signed_redirect_query(
        :relay_state_raw => "http%3A%2F%2Fex%61mple.com%2Fcb%20x",
        :include_relay_state => true
      )
      raw = OneLogin::RubySaml::Utils.parse_raw_query_string(query)
      rebuilt = OneLogin::RubySaml::Utils.build_query_from_raw_parts(
        :type => 'SAMLRequest',
        :raw_data => raw['SAMLRequest'],
        :raw_relay_state => raw['RelayState'],
        :raw_sig_alg => raw['SigAlg']
      )
      assert_equal query.sub(/&Signature=.*\z/, ''), rebuilt
    end

    it "lists where framework decoding changes the signed bytes" do
      changes = []
      {
        "space as %20" => "cb%20a%20b",
        "space as +" => "cb+a+b",
        "lowercase %2f" => "http%3a%2f%2fexample.com",
        "tilde as %7E" => "cb%7Ex",
        "unicode downcased" => downcased_escape("café 中文")
      }.each do |label, relay_state_raw|
        framework_value = framework_decoded_params("RelayState=#{relay_state_raw}")['RelayState']
        reescaped = CGI.escape(framework_value)
        changes << "#{label}: #{relay_state_raw} -> #{reescaped}" if reescaped != relay_state_raw
      end

      assert_includes changes.join("\n"), "space as %20: cb%20a%20b -> cb+a+b"
      assert changes.any? { |c| c.start_with?("lowercase %2f") }
      assert changes.any? { |c| c.start_with?("tilde as %7E") }
      assert changes.any? { |c| c.start_with?("unicode downcased") }
      refute changes.any? { |c| c.start_with?("space as +") }
    end

    it "fails if the app only has framework-decoded params and re-encodes them" do
      query = signed_redirect_query(
        :relay_state_raw => "http%3A%2F%2Fexample.com%2Fcb%20x",
        :include_relay_state => true
      )
      get_params = framework_decoded_params(query)
      slo = OneLogin::RubySaml::SloLogoutrequest.new(
        get_params['SAMLRequest'],
        :settings => settings,
        :get_params => get_params
      )
      error = assert_raises(OneLogin::RubySaml::ValidationError) { slo.is_valid? }
      assert_match(/Invalid Signature on Logout Request/, error.message)
    end

    it "rejects duplicate security parameters before any SAML content is used" do
      query = signed_redirect_query(
        :relay_state_raw => "abc",
        :include_relay_state => true
      )
      ["RelayState=forged", "Signature=forged", "SigAlg=forged"].each do |extra|
        assert_raises(ArgumentError) do
          slo_logout_request_from_query("#{query}&#{extra}", settings)
        end
      end
    end
  end
end
