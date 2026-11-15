require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

require 'onelogin/ruby-saml/trusted_metadata_importer'

class TrustedMetadataImporterTest < Minitest::Test
  ENTITY_A = "https://idp-a.example.com/metadata".freeze
  ENTITY_B = "https://idp-b.example.com/metadata".freeze
  ENTITY_C = "https://idp-c.example.com/metadata".freeze

  def setup
    @importer = OneLogin::RubySaml::TrustedMetadataImporter.new
    @anchor = trusted_metadata_certificate("anchor.pem")
    @time = trusted_metadata_time
  end

  def import(name, entity_id = ENTITY_A, time = @time, anchors = [@anchor], options = {})
    @importer.import(trusted_metadata_fixture(name), anchors, entity_id, time, options)
  end

  def test_collection_signature_adopts_only_the_target
    result = import("collection_signed.xml")

    assert_equal ENTITY_A, result.entity_id
    assert_equal ENTITY_A, result.settings.idp_entity_id
    assert_equal "https://idp-a.example.com/sso", result.settings.idp_sso_service_url
    assert_equal "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", result.settings.idp_sso_service_binding
    assert_equal "https://idp-a.example.com/slo", result.settings.idp_slo_service_url
    assert_equal "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", result.settings.name_identifier_format
    assert_equal ["/EntitiesDescriptor[1]/Signature[1]"], result.signature_paths
  end

  def test_sibling_entity_is_evidence_only
    result = import("collection_signed.xml")

    refute_includes result.settings.idp_sso_service_url, "idp-b"
    assert_equal 1, result.rejected.length

    sibling = result.rejected.first
    assert_equal ENTITY_B, sibling.entity_id
    assert_equal :not_selected, sibling.status
    assert_includes sibling.sso_locations, "https://idp-b.example.com/sso"
    refute_empty sibling.signing_certificate_fingerprints
  end

  def test_entity_limit_wins_over_collection_limit
    result = import("collection_signed.xml")

    assert_equal Time.parse("2030-06-01T00:00:00Z").utc, result.effective_valid_until
    assert_equal "2030-06-01T00:00:00Z", result.settings.valid_until
  end

  def test_entity_signed_by_anchored_signer_is_adopted
    result = import("entity_a_signed.xml")

    assert_equal "https://idp-a.example.com/sso", result.settings.idp_sso_service_url
    assert_equal ["/EntitiesDescriptor[1]/EntityDescriptor[1]/Signature[1]"], result.signature_paths
  end

  def test_signature_on_sibling_does_not_cover_the_target
    error = assert_raises(OneLogin::RubySaml::TrustedMetadataError) do
      import("entity_b_signed.xml", ENTITY_A)
    end

    assert_match(/no trusted signature covers the target entity/, error.message)
    rejected = error.evidence.find { |entry| entry.entity_id == ENTITY_A }
    assert_equal :rejected, rejected.status
    assert_empty rejected.signature_paths

    sibling = error.evidence.find { |entry| entry.entity_id == ENTITY_B }
    assert_equal :not_selected, sibling.status
    assert_equal ["/EntitiesDescriptor[1]/EntityDescriptor[2]/Signature[1]"], sibling.signature_paths
  end

  def test_entity_self_advertised_certificate_is_not_a_trust_anchor
    error = assert_raises(OneLogin::RubySaml::TrustedMetadataError) do
      import("entity_b_self_signed.xml", ENTITY_B)
    end

    assert_match(/not chained to a configured trust anchor/, error.message)
  end

  def test_direct_signer_certificate_works_only_when_supplied_as_anchor
    signer = trusted_metadata_certificate("signer.pem")
    result = import("collection_signed.xml", ENTITY_A, @time, [signer])

    assert_equal ENTITY_A, result.settings.idp_entity_id
  end

  def test_expired_ancestor_rejects_the_target
    error = assert_raises(OneLogin::RubySaml::TrustedMetadataError) do
      import("collection_expired.xml")
    end

    assert_match(/effective validUntil is 2024-01-01/, error.message)
  end

  def test_expired_entity_rejects_the_target
    error = assert_raises(OneLogin::RubySaml::TrustedMetadataError) do
      import("entity_expired.xml")
    end

    assert_match(/effective validUntil is 2024-01-01/, error.message)
  end

  def test_expired_nested_ancestor_rejects_the_target
    error = assert_raises(OneLogin::RubySaml::TrustedMetadataError) do
      import("nested_expired_ancestor.xml")
    end

    assert_match(/effective validUntil is 2024-01-01/, error.message)
  end

  def test_cache_duration_is_relative_to_verification_time
    result = import("collection_cache_duration.xml")

    assert_equal Time.parse("2026-07-01T00:00:00Z").utc, result.effective_valid_until
    assert_equal "2026-07-01T00:00:00Z", result.settings.valid_until

    error = assert_raises(OneLogin::RubySaml::TrustedMetadataError) do
      import("collection_cache_duration.xml", ENTITY_A, Time.parse("2026-07-01T00:00:00Z").utc)
    end
    assert_match(/effective validUntil is 2026-07-01/, error.message)
  end

  def test_cache_duration_is_ignored_when_valid_until_is_present
    result = import("collection_signed.xml")

    assert_equal Time.parse("2030-06-01T00:00:00Z").utc, result.effective_valid_until
  end

  def test_multiple_covering_signatures_must_all_verify
    result = import("entity_and_collection_signed.xml")

    assert_equal "https://idp-a.example.com/sso", result.settings.idp_sso_service_url
    assert_equal 2, result.signature_paths.length
    assert_includes result.signature_paths, "/EntitiesDescriptor[1]/Signature[1]"
    assert_includes result.signature_paths, "/EntitiesDescriptor[1]/EntityDescriptor[1]/Signature[1]"
  end

  def test_untrusted_extra_covering_signature_rejects_the_target
    error = assert_raises(OneLogin::RubySaml::TrustedMetadataError) do
      import("target_with_untrusted_extra_signature.xml")
    end

    assert_match(/not chained to a configured trust anchor/, error.message)
    rejected = error.evidence.find { |entry| entry.entity_id == ENTITY_A }
    assert_equal :rejected, rejected.status
    assert_equal 2, rejected.signature_paths.length
  end

  def test_signature_created_by_sign_document_is_accepted
    certificate = OpenSSL::X509::Certificate.new(File.read(File.join(File.dirname(__FILE__), "certificates", "ruby-saml.crt")))
    key = OpenSSL::PKey::RSA.new(File.read(File.join(File.dirname(__FILE__), "certificates", "ruby-saml.key")))

    metadata = XMLSecurity::Document.new(<<-XML)
<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="_root" validUntil="2030-01-01T00:00:00Z">
  <md:EntityDescriptor entityID="#{ENTITY_A}" ID="_a">
    <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
      <md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>#{Base64.strict_encode64(certificate.to_der)}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
      <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp-a.example.com/sso"/>
    </md:IDPSSODescriptor>
  </md:EntityDescriptor>
</md:EntitiesDescriptor>
    XML
    metadata.sign_document(key, certificate)

    # The bundled ruby-saml.crt fixture is valid from 2014-04-23 to 2015-04-23.
    result = @importer.import(metadata.to_s, [certificate], ENTITY_A, Time.parse("2014-10-01T00:00:00Z").utc)

    assert_equal "https://idp-a.example.com/sso", result.settings.idp_sso_service_url
    assert_equal ["/EntitiesDescriptor[1]/Signature[1]"], result.signature_paths
  end

  def test_tampering_with_a_covered_sibling_breaks_the_collection_signature
    xml = trusted_metadata_fixture("collection_signed.xml")
              .sub("https://idp-b.example.com/sso", "https://evil.example.com/sso")

    error = assert_raises(OneLogin::RubySaml::TrustedMetadataError) do
      @importer.import(xml, [@anchor], ENTITY_A, @time)
    end

    assert_match(/Digest mismatch/, error.message)
  end

  def test_tampering_with_the_target_sso_endpoint_is_rejected
    xml = trusted_metadata_fixture("entity_a_signed.xml")
              .sub("https://idp-a.example.com/sso", "https://evil.example.com/sso")

    error = assert_raises(OneLogin::RubySaml::TrustedMetadataError) do
      @importer.import(xml, [@anchor], ENTITY_A, @time)
    end

    assert_match(/Digest mismatch/, error.message)
  end

  def test_target_without_a_signing_certificate_is_rejected
    xml = trusted_metadata_fixture("collection_signed.xml").sub(
      %r{<md:KeyDescriptor use="signing">.*?</md:KeyDescriptor>}m,
      ""
    )

    error = assert_raises(OneLogin::RubySaml::TrustedMetadataError) do
      @importer.import(xml, [@anchor], ENTITY_A, @time)
    end

    assert_match(/no signing certificate/, error.message)
  end

  def test_inner_collection_signature_covers_nested_entities_but_not_outer_siblings
    nested = import("inner_collection_signed.xml", ENTITY_A)
    assert_equal "https://idp-a.example.com/sso", nested.settings.idp_sso_service_url
    assert_equal ["/EntitiesDescriptor[1]/EntitiesDescriptor[1]/Signature[1]"], nested.signature_paths

    outer = assert_raises(OneLogin::RubySaml::TrustedMetadataError) do
      import("inner_collection_signed.xml", ENTITY_B)
    end
    assert_match(/no trusted signature covers the target entity/, outer.message)
  end

  def test_multiple_advertised_signing_certificates_are_kept_for_the_authenticated_target
    result = import("multiple_signing_certificates.xml")

    assert_nil result.settings.idp_cert
    assert_nil result.settings.idp_cert_fingerprint
    assert_equal 2, result.settings.idp_cert_multi[:signing].length
    assert_equal "https://idp-a.example.com/sso", result.settings.idp_sso_service_url
  end

  def test_result_evidence_includes_unselected_sibling_details
    result = import("collection_signed.xml")
    entry = result.rejected.first

    assert_equal ENTITY_B, entry.entity_id
    assert_equal "/EntitiesDescriptor[1]/EntityDescriptor[2]", entry.element_path
    assert_equal ["https://idp-b.example.com/sso"], entry.sso_locations
    assert_equal 1, entry.signing_certificate_fingerprints.length
    assert_equal Time.parse("2031-01-01T00:00:00Z").utc, entry.effective_valid_until
  end

  def test_malformed_xml_raises_a_typed_error
    error = assert_raises(OneLogin::RubySaml::TrustedMetadataError) do
      @importer.import("<md:EntitiesDescriptor>", [@anchor], ENTITY_A, @time)
    end

    assert_match(/Metadata XML is malformed/, error.message)
  end

  def test_invalid_verification_time_raises_a_typed_error
    error = assert_raises(OneLogin::RubySaml::TrustedMetadataError) do
      @importer.import(trusted_metadata_fixture("collection_signed.xml"), [@anchor], ENTITY_A, "not-a-time")
    end

    assert_match(/not a valid time/, error.message)
  end

  def test_expired_pinned_signer_certificate_is_not_accepted
    expired = trusted_metadata_certificate("short_lived_signer.pem")

    error = assert_raises(OneLogin::RubySaml::TrustedMetadataError) do
      import("collection_short_lived_signer.xml", ENTITY_A, @time, [expired])
    end

    assert_match(/certificate has expired/, error.message)
  end

  def test_duplicate_target_entity_id_is_rejected
    error = assert_raises(OneLogin::RubySaml::TrustedMetadataError) do
      import("duplicate_entity_id.xml")
    end

    assert_match(/Target entityID is not unique/, error.message)
    ambiguous = error.evidence.select { |entry| entry.status == :ambiguous }
    assert_equal 2, ambiguous.length
    assert ambiguous.all? { |entry| entry.entity_id == ENTITY_A }
  end

  def test_missing_target_is_rejected
    error = assert_raises(OneLogin::RubySaml::TrustedMetadataError) do
      import("target_missing.xml")
    end

    assert_match(/not found in the metadata collection/, error.message)
    assert_equal [ENTITY_B], error.evidence.map(&:entity_id)
  end

  def test_sp_target_is_rejected
    error = assert_raises(OneLogin::RubySaml::TrustedMetadataError) do
      import("target_is_sp.xml", ENTITY_C)
    end

    assert_match(/does not contain an IDPSSODescriptor/, error.message)
  end

  def test_trust_anchor_is_required
    error = assert_raises(OneLogin::RubySaml::TrustedMetadataError) do
      import("collection_signed.xml", ENTITY_A, @time, [])
    end

    assert_match(/trust anchor certificate is required/, error.message)
  end

  def test_target_entity_id_is_required
    error = assert_raises(OneLogin::RubySaml::TrustedMetadataError) do
      import("collection_signed.xml", nil)
    end

    assert_match(/target entityID is required/, error.message)
  end

  def test_doctype_is_rejected
    xml = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>' \
          '<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">&xxe;</md:EntitiesDescriptor>'

    error = assert_raises(OneLogin::RubySaml::TrustedMetadataError) do
      @importer.import(xml, [@anchor], ENTITY_A, @time)
    end

    assert_match(/DOCTYPE/, error.message)
  end

  def test_iso8601_string_verification_time_is_accepted
    result = @importer.import(
      trusted_metadata_fixture("collection_signed.xml"), [@anchor], ENTITY_A, "2026-06-01T00:00:00Z"
    )

    assert_equal Time.parse("2026-06-01T00:00:00Z").utc, result.verification_time
    assert_equal "https://idp-a.example.com/sso", result.settings.idp_sso_service_url
  end
end
