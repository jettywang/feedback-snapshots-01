require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

require 'onelogin/ruby-saml/response'
require 'securerandom'
require 'xml_security'

class AudienceRestrictionSemanticsTest < Minitest::Test

  describe "Response AudienceRestriction combinatorial semantics" do

    IDP_ENTITY = "https://idp.example.com/metadata"
    SP_ENTITY  = "https://sp.example.com/metadata"
    OTHER_SP   = "https://sp2.example.com/metadata"
    PARTNER    = "https://partner.example.net/audience"
    ACS_URL    = "https://sp.example.com/acs"

    let(:idp_cert_text) { read_certificate("ruby-saml.crt") }
    let(:idp_private_key) { OpenSSL::PKey::RSA.new(read_certificate("ruby-saml.key")) }
    let(:idp_certificate) { OpenSSL::X509::Certificate.new(idp_cert_text) }

    let(:settings) do
      settings = OneLogin::RubySaml::Settings.new
      settings.idp_entity_id = IDP_ENTITY
      settings.sp_entity_id = SP_ENTITY
      settings.assertion_consumer_service_url = ACS_URL
      settings.idp_cert = idp_cert_text
      settings.security[:want_assertions_signed] = true
      settings
    end

    # Builds a Response whose single Assertion carries a real XML-DSig signature
    # produced with the test IdP key (rsa-sha256) and currently valid time conditions.
    # audience_groups is an array of AudienceRestriction groups, each one being the
    # list of Audience values allowed by that group.
    def signed_response(audience_groups, extra_conditions_xml = "")
      now = Time.now.utc
      request_id = "_request_#{SecureRandom.hex(4)}"
      assertion_id = "_assertion_#{SecureRandom.hex(8)}"

      restrictions_xml = audience_groups.map do |group|
        audiences_xml = group.map { |audience| "<saml:Audience>#{audience}</saml:Audience>" }.join
        "<saml:AudienceRestriction>#{audiences_xml}</saml:AudienceRestriction>"
      end.join

      # The samlp namespace is declared on the Assertion because it is listed in the
      # exclusive canonicalization InclusiveNamespaces PrefixList of the signature.
      assertion_xml = [
        '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"',
        ' xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"',
        " ID=\"#{assertion_id}\" Version=\"2.0\"",
        " IssueInstant=\"#{(now - 300).strftime('%Y-%m-%dT%H:%M:%SZ')}\">",
        "<saml:Issuer>#{IDP_ENTITY}</saml:Issuer>",
        "<saml:Subject>",
        '<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">user@example.com</saml:NameID>',
        '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">',
        "<saml:SubjectConfirmationData InResponseTo=\"#{request_id}\"",
        " NotOnOrAfter=\"#{(now + 300).strftime('%Y-%m-%dT%H:%M:%SZ')}\"",
        " Recipient=\"#{ACS_URL}\"/>",
        "</saml:SubjectConfirmation>",
        "</saml:Subject>",
        "<saml:Conditions NotBefore=\"#{(now - 300).strftime('%Y-%m-%dT%H:%M:%SZ')}\"",
        " NotOnOrAfter=\"#{(now + 300).strftime('%Y-%m-%dT%H:%M:%SZ')}\">",
        restrictions_xml,
        extra_conditions_xml,
        "</saml:Conditions>",
        "<saml:AttributeStatement>",
        '<saml:Attribute Name="role"><saml:AttributeValue>admin</saml:AttributeValue></saml:Attribute>',
        "</saml:AttributeStatement>",
        "<saml:AuthnStatement AuthnInstant=\"#{(now - 300).strftime('%Y-%m-%dT%H:%M:%SZ')}\"",
        " SessionIndex=\"#{assertion_id}\">",
        "<saml:AuthnContext>",
        "<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>",
        "</saml:AuthnContext>",
        "</saml:AuthnStatement>",
        "</saml:Assertion>"
      ].join

      assertion_document = XMLSecurity::Document.new(assertion_xml)
      assertion_document.sign_document(
        idp_private_key,
        idp_certificate,
        XMLSecurity::Document::RSA_SHA256,
        XMLSecurity::Document::SHA256
      )

      [
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"',
        " ID=\"_response_#{SecureRandom.hex(8)}\" Version=\"2.0\"",
        " IssueInstant=\"#{now.strftime('%Y-%m-%dT%H:%M:%SZ')}\"",
        " Destination=\"#{ACS_URL}\" InResponseTo=\"#{request_id}\">",
        "<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">#{IDP_ENTITY}</saml:Issuer>",
        '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>',
        assertion_document.to_s,
        "</samlp:Response>"
      ].join
    end

    def response_for(audience_groups, extra_conditions_xml = "")
      OneLogin::RubySaml::Response.new(
        signed_response(audience_groups, extra_conditions_xml),
        :settings => settings
      )
    end

    def audience_error(expected, actual)
      s = actual.count > 1 ? 's' : ''
      "Invalid Audience#{s}. The audience#{s} #{actual.join(',')}, did not match the expected audience #{expected}"
    end

    # Reference implementations of the wrong algorithms the regression guards against.
    # They are exercised only inside the tests below to prove which assertions each
    # faulty implementation would misclassify.
    def first_group_only_valid?(response)
      response.audience_restrictions.first.include?(settings.sp_entity_id)
    end

    def first_audience_only_valid?(response)
      response.audience_restrictions.first.first == settings.sp_entity_id
    end

    def union_flattened_valid?(response)
      response.audiences.include?(settings.sp_entity_id)
    end

    describe "accepted assertions" do
      it "accepts one restriction group containing two audiences when the SP entity id is one of them (within-group disjunction)" do
        response = response_for([[SP_ENTITY, OTHER_SP]])

        assert_equal [[SP_ENTITY, OTHER_SP]], response.audience_restrictions
        assert response.is_valid?
        assert_empty response.errors
        assert_equal "admin", response.attributes["role"]
      end

      it "accepts two restriction groups that both contain the SP entity id (between-group conjunction)" do
        response = response_for([[SP_ENTITY, OTHER_SP], [SP_ENTITY]])

        assert_equal [[SP_ENTITY, OTHER_SP], [SP_ENTITY]], response.audience_restrictions
        assert response.is_valid?
        assert_empty response.errors
        assert_equal "admin", response.attributes["role"]
      end

      it "still exposes every audience through the flattened audiences accessor without losing the groups" do
        response = response_for([[SP_ENTITY, OTHER_SP], [SP_ENTITY]])

        assert_equal [SP_ENTITY, OTHER_SP, SP_ENTITY], response.audiences
        assert_equal [[SP_ENTITY, OTHER_SP], [SP_ENTITY]], response.audience_restrictions
      end
    end

    describe "rejected assertions" do
      let(:contradictory_groups) { [[SP_ENTITY, OTHER_SP], [PARTNER]] }

      it "rejects two mutually exclusive restriction groups even though the SP entity id appears in one group" do
        response = response_for(contradictory_groups)

        refute response.is_valid?
        assert_includes response.errors, audience_error(SP_ENTITY, [SP_ENTITY, OTHER_SP, PARTNER])
      end

      it "raises a ValidationError on the same assertion when soft mode is disabled" do
        response = response_for(contradictory_groups)
        response.soft = false

        error = assert_raises(OneLogin::RubySaml::ValidationError) { response.is_valid? }
        assert_includes error.message, "Invalid Audiences"
      end

      it "rejects when no restriction group contains the SP entity id" do
        response = response_for([[OTHER_SP], [PARTNER]])

        refute response.is_valid?
        assert_includes response.errors, audience_error(SP_ENTITY, [OTHER_SP, PARTNER])
      end

      it "keeps business attributes behind the failed validation gate" do
        response = response_for(contradictory_groups)

        # The attribute bag can still be parsed from the XML, but relying parties only
        # consume it after is_valid? succeeds, so the unsatisfied condition keeps the
        # business data out of any authenticated session.
        assert_equal "admin", response.attributes["role"]
        refute response.is_valid?
        assert response.errors.any? { |error| error.start_with?("Invalid Audience") }
      end
    end

    describe "assertions without Audience elements" do
      it "accepts an assertion without any AudienceRestriction in the default lenient mode" do
        response = response_for([])

        assert_equal [], response.audience_restrictions
        assert_equal [], response.audiences
        assert response.is_valid?
        assert_empty response.errors
      end

      it "rejects an assertion without any audience when strict audience validation is enabled" do
        strict_settings = settings
        strict_settings.security[:strict_audience_validation] = true
        response = OneLogin::RubySaml::Response.new(signed_response([]), :settings => strict_settings)

        refute response.is_valid?
        assert_includes response.errors,
                        "Invalid Audiences. The <AudienceRestriction> element contained only empty <Audience> elements. Expected audience #{SP_ENTITY}."
      end
    end

    describe "unknown Condition elements" do
      # OneTimeUse is a standard SAML condition that ruby-saml does not implement.
      # It is schema valid, so the document still passes structural validation, and the
      # toolkit intentionally does not reject it: only the conditions it understands
      # (time window and AudienceRestriction) are evaluated. This test pins that
      # documented behavior so a future "fail closed on unknown conditions" change is
      # made deliberately rather than by accident.
      let(:one_time_use) do
        '<saml:OneTimeUse xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>'
      end

      it "keeps accepting a valid audience restriction alongside an unrecognized condition" do
        response = response_for([[SP_ENTITY]], one_time_use)

        assert response.send(:validate_structure)
        assert response.is_valid?
        assert_empty response.errors
        assert_equal "admin", response.attributes["role"]
      end

      it "still enforces audience semantics when an unrecognized condition is present" do
        response = response_for([[OTHER_SP], [PARTNER]], one_time_use)

        refute response.is_valid?
        assert_includes response.errors, audience_error(SP_ENTITY, [OTHER_SP, PARTNER])
      end
    end

    describe "regression against flattened or first-group algorithms" do
      let(:contradictory_groups) { [[SP_ENTITY, OTHER_SP], [PARTNER]] }

      it "fails the public validation while a union-of-all-groups implementation would accept it" do
        response = response_for(contradictory_groups)

        assert union_flattened_valid?(response), "precondition: the flattened union algorithm would accept this assertion"
        refute response.is_valid?
      end

      it "fails the public validation while a first-group-only implementation would accept it" do
        response = response_for(contradictory_groups)

        assert first_group_only_valid?(response), "precondition: the first-group-only algorithm would accept this assertion"
        refute response.is_valid?
      end

      it "accepts a fully satisfied assertion that both faulty implementations also accept" do
        response = response_for([[SP_ENTITY, OTHER_SP], [SP_ENTITY]])

        assert union_flattened_valid?(response)
        assert first_group_only_valid?(response)
        assert response.is_valid?
      end

      it "catches a wrong-rejection case produced by only looking at the first audience of the first group" do
        # The SP entity id is accepted by every group (disjunction inside the first
        # group), so the assertion must be accepted. A variant that only inspects the
        # very first Audience element would wrongly reject it because it sits second.
        response = response_for([[OTHER_SP, SP_ENTITY], [SP_ENTITY]])

        refute first_audience_only_valid?(response)
        assert response.is_valid?
        assert_empty response.errors
      end
    end

    describe "conditions must come from the signed assertion" do
      it "ignores audience material injected into a second, unsigned assertion" do
        signed_xml = signed_response([[PARTNER]])
        unsigned_assertion = [
          '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_injected-assertion" Version="2.0"',
          " IssueInstant=\"#{Time.now.utc.strftime('%Y-%m-%dT%H:%M:%SZ')}\">",
          "<saml:Issuer>#{IDP_ENTITY}</saml:Issuer>",
          "<saml:Conditions>",
          "<saml:AudienceRestriction><saml:Audience>#{SP_ENTITY}</saml:Audience></saml:AudienceRestriction>",
          "</saml:Conditions>",
          "</saml:Assertion>"
        ].join
        tampered_xml = signed_xml.sub("</samlp:Response>", "#{unsigned_assertion}</samlp:Response>")

        response = OneLogin::RubySaml::Response.new(tampered_xml, :settings => settings)

        # Only the signed assertion is consulted for audience data; the injected
        # SP-matching audience is never read.
        assert_equal [[PARTNER]], response.audience_restrictions
        assert_equal [PARTNER], response.audiences
        refute response.send(:validate_audience)
        assert_includes response.errors, audience_error(SP_ENTITY, [PARTNER])

        # The public entry point rejects the tampered response outright.
        refute response.is_valid?
        assert_includes response.errors, "SAML Response must contain 1 assertion"
      end

      it "reads audiences from the signed assertion of a response-level signed message" do
        response = response_for([[SP_ENTITY, OTHER_SP], [SP_ENTITY]])

        # The signature protects the Assertion directly; its groups are the ones evaluated.
        assert_equal [[SP_ENTITY, OTHER_SP], [SP_ENTITY]], response.audience_restrictions
        assert response.send(:validate_signature)
        assert response.is_valid?
      end
    end
  end
end
