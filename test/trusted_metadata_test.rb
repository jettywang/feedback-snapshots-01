require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

require 'onelogin/ruby-saml/trusted_metadata'

class TrustedMetadataTest < Minitest::Test
  MD = "urn:oasis:names:tc:SAML:2.0:metadata".freeze
  DSIG = "http://www.w3.org/2000/09/xmldsig#".freeze
  C14N = "http://www.w3.org/2001/10/xml-exc-c14n#".freeze
  VERIFY_AT = Time.utc(2026, 6, 1, 12, 0, 0)

  # Builds a two-entity EntitiesDescriptor and can sign either the collection
  # or an individual entity. Metadata signatures are generated directly so a
  # test can place the signature at a precise position.
  class Builder
    attr_reader :root_certificate, :signing_certificate, :signing_key,
                :unrelated_certificate, :unrelated_key

    def initialize(options = {})
      @not_before = options[:not_before] || Time.utc(2024, 1, 1)
      @not_after = options[:not_after] || Time.utc(2030, 1, 1)
      @signer_not_after = options[:signer_not_after] || @not_after
      @root_key = OpenSSL::PKey::RSA.new(2048)
      @root_certificate = certificate("Metadata Root", @root_key, 1, nil, nil)
      @signing_key = OpenSSL::PKey::RSA.new(2048)
      @signing_certificate = certificate("Metadata Signer", @signing_key, 2,
                                         @root_certificate, @root_key,
                                         true, @signer_not_after)
      @unrelated_key = OpenSSL::PKey::RSA.new(2048)
      @unrelated_certificate = certificate("Unrelated", @unrelated_key, 3, nil, nil, false)
    end

    def entity(entity_id, id, sso, signing_certificate, options = {})
      attributes = ["entityID=\"#{entity_id}\"", "ID=\"#{id}\""]
      attributes << "validUntil=\"#{options[:valid_until]}\"" if options[:valid_until]

      idp_attributes = ["protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\""]
      idp_attributes << "validUntil=\"#{options[:idp_valid_until]}\"" if options[:idp_valid_until]

      key_descriptor = if options[:publish_signing_certificate] == false
                         ""
                       else
                         signing_key_descriptor(signing_certificate)
                       end
      slo = if options[:slo]
              "<md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" " \
              "Location=\"#{options[:slo]}\" ResponseLocation=\"#{options[:slo]}/return\"/>"
            else
              ""
            end

      <<-XML
  <md:EntityDescriptor #{attributes.join(' ')}>
    <md:IDPSSODescriptor #{idp_attributes.join(' ')}>
#{key_descriptor}      #{slo}<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>
      <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="#{sso}"/>
    </md:IDPSSODescriptor>
  </md:EntityDescriptor>
      XML
    end

    def document(entities, options = {})
      attributes = ["ID=\"#{options[:id] || 'root'}\""]
      attributes << "validUntil=\"#{options[:valid_until]}\"" if options[:valid_until]
      attributes << "cacheDuration=\"#{options[:cache_duration]}\"" if options[:cache_duration]

      <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<md:EntitiesDescriptor xmlns:md="#{MD}" xmlns:ds="#{DSIG}" #{attributes.join(' ')}>
#{entities.join("\n")}
</md:EntitiesDescriptor>
      XML
    end

    # Place the signature as the first child of the signed element, as the
    # metadata schema requires, so the signature covers the whole element.
    def sign(document, id, key = @signing_key, signing_certificate = @signing_certificate)
      doc = document.is_a?(Nokogiri::XML::Document) ? document : Nokogiri::XML(document)
      node = id == "root" ? doc.root : doc.at_xpath("//*[@ID=$id]", nil, { "id" => id })
      raise ArgumentError, "no element with ID #{id}" if node.nil?

      signature = Nokogiri::XML::Node.new("ds:Signature", doc)
      signature.add_namespace_definition("ds", DSIG)
      node.add_child(signature)

      signed_info = add(signature, doc, "ds:SignedInfo")
      add_algorithm(signed_info, doc, "ds:CanonicalizationMethod", C14N)
      add_algorithm(signed_info, doc, "ds:SignatureMethod",
                    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
      reference = add(signed_info, doc, "ds:Reference")
      reference["URI"] = "##{node['ID']}"
      transforms = add(reference, doc, "ds:Transforms")
      add_algorithm(transforms, doc, "ds:Transform",
                    "http://www.w3.org/2000/09/xmldsig#enveloped-signature")
      add_algorithm(transforms, doc, "ds:Transform", C14N)
      add_algorithm(reference, doc, "ds:DigestMethod", "http://www.w3.org/2001/04/xmlenc#sha256")
      digest = add(reference, doc, "ds:DigestValue")

      signature.unlink
      digest.content = Base64.strict_encode64(OpenSSL::Digest::SHA256.digest(canonicalize(node)))
      node.children.first.add_previous_sibling(signature)

      signature_value = add(signature, doc, "ds:SignatureValue")
      signature_value.content = Base64.strict_encode64(
        key.sign(OpenSSL::Digest::SHA256.new, canonicalize(signed_info))
      )
      key_info = add(signature, doc, "ds:KeyInfo")
      x509_data = add(key_info, doc, "ds:X509Data")
      add(x509_data, doc, "ds:X509Certificate").content =
        Base64.strict_encode64(signing_certificate.to_der)
      doc
    end

    def canonicalize(node)
      node.canonicalize(Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0)
    end

    private

    def signing_key_descriptor(signing_certificate)
      <<-XML
      <md:KeyDescriptor use="signing">
        <ds:KeyInfo xmlns:ds="#{DSIG}">
          <ds:X509Data><ds:X509Certificate>#{Base64.strict_encode64(signing_certificate.to_der)}</ds:X509Certificate></ds:X509Data>
        </ds:KeyInfo>
      </md:KeyDescriptor>
      XML
    end

    def add(parent, document, name)
      node = Nokogiri::XML::Node.new(name, document)
      parent.add_child(node)
      node
    end

    def add_algorithm(parent, document, name, algorithm)
      node = add(parent, document, name)
      node["Algorithm"] = algorithm
      node
    end

    def certificate(common_name, key, serial, issuer, issuer_key, ca = true, not_after = nil)
      certificate = OpenSSL::X509::Certificate.new
      certificate.version = 2
      certificate.serial = serial
      certificate.subject = OpenSSL::X509::Name.parse("/CN=#{common_name}")
      certificate.issuer = issuer ? issuer.subject : certificate.subject
      certificate.public_key = key.public_key
      certificate.not_before = @not_before
      certificate.not_after = not_after || @not_after

      factory = OpenSSL::X509::ExtensionFactory.new
      factory.subject_certificate = certificate
      factory.issuer_certificate = issuer || certificate
      certificate.add_extension(factory.create_extension("basicConstraints", ca ? "CA:TRUE" : "CA:FALSE", true))
      certificate.add_extension(factory.create_extension("keyUsage", ca ? "keyCertSign,cRLSign" : "digitalSignature", true))
      certificate.sign(issuer_key || key, OpenSSL::Digest::SHA256.new)
      certificate
    end
  end

  def setup
    @builder = Builder.new
    @entity_a = @builder.entity(
      "https://a.example/idp", "entity-a", "https://a.example/sso",
      @builder.signing_certificate, :slo => "https://a.example/slo"
    )
    @entity_b = @builder.entity(
      "https://b.example/idp", "entity-b", "https://b.example/sso",
      @builder.unrelated_certificate, :slo => "https://b.example/slo"
    )
    @metadata = @builder.document([@entity_a, @entity_b], :valid_until => "2028-01-01T00:00:00Z")
  end

  def import(metadata, entity_id, options = {})
    OneLogin::RubySaml::TrustedMetadata.import(
      metadata,
      :trust_anchors => @builder.root_certificate,
      :entity_id => entity_id,
      :verification_time => VERIFY_AT,
      :options => options
    )
  end

  def test_root_signature_selects_only_the_requested_entity
    result = import(@builder.sign(@metadata, "root"), "https://a.example/idp")

    assert result.adopted?
    assert_equal "https://a.example/idp", result.settings.idp_entity_id
    assert_equal "https://a.example/sso", result.settings.idp_sso_service_url
    assert_equal "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                 result.settings.idp_sso_service_binding
    assert_equal "https://a.example/slo", result.settings.idp_slo_service_url
    assert_equal "https://a.example/slo/return", result.settings.idp_slo_response_service_url
    assert_equal [Base64.strict_encode64(@builder.signing_certificate.to_der)],
                 result.settings.idp_cert_multi[:signing]
    assert_equal "2028-01-01T00:00:00Z", result.evidence[:adopted][:valid_until]
    assert_equal "2028-01-01T00:00:00Z", result.settings.valid_until

    assert_equal ["https://b.example/idp"],
                 result.evidence[:not_adopted].map { |entry| entry[:entity_id] }
    sibling = result.evidence[:not_adopted].first
    assert_includes sibling[:reasons], :not_target
    refute_includes sibling[:reasons], :no_trusted_signature
    assert_equal "https://b.example/sso", sibling[:sso_endpoints].first[:location]
    assert_equal [Base64.strict_encode64(@builder.unrelated_certificate.to_der)],
                 sibling[:signing_certificates]
  end

  def test_root_signature_can_select_the_other_entity_without_merging_certificates
    result = import(@builder.sign(@metadata, "root"), "https://b.example/idp")

    assert result.adopted?
    assert_equal "https://b.example/sso", result.settings.idp_sso_service_url
    assert_equal [Base64.strict_encode64(@builder.unrelated_certificate.to_der)],
                 result.settings.idp_cert_multi[:signing]
    refute_includes result.settings.idp_cert_multi[:signing],
                    Base64.strict_encode64(@builder.signing_certificate.to_der)
    assert_equal "https://a.example/idp", result.evidence[:not_adopted].first[:entity_id]
  end

  def test_one_signed_child_does_not_trust_its_sibling
    metadata = @builder.sign(@metadata, "entity-a")

    accepted = import(metadata, "https://a.example/idp")
    assert accepted.adopted?
    assert_equal "https://a.example/sso", accepted.settings.idp_sso_service_url

    rejected = import(metadata, "https://b.example/idp")
    refute rejected.adopted?
    assert_nil rejected.settings
    assert_includes rejected.errors.join(" "), "No trusted signature covers the target entity"
    sibling = rejected.evidence[:not_adopted].find { |entry| entry[:entity_id] == "https://b.example/idp" }
    assert_includes sibling[:reasons], :no_trusted_signature
  end

  def test_child_signature_is_recorded_as_coverage_for_that_child_only
    result = import(@builder.sign(@metadata, "entity-a"), "https://a.example/idp")

    assert result.adopted?
    signature = result.evidence[:signatures].first
    assert signature[:valid]
    assert_equal "EntityDescriptor", signature[:referenced_name]
    assert_equal "https://a.example/idp", signature[:referenced_entity_id]
    assert_equal "Metadata Signer", signature[:signer_certificate][:subject][/CN=([^,]+)/, 1]
    assert_equal ["Metadata Root"], signature[:certificate_chain].map { |cert| cert[:subject][/CN=([^,]+)/, 1] }.reject { |name| name == "Metadata Signer" }
  end

  def test_expired_ancestor_rejects_an_otherwise_valid_target
    metadata = @builder.document([@entity_a, @entity_b], :valid_until => "2025-01-01T00:00:00Z")
    result = import(@builder.sign(metadata, "root"), "https://a.example/idp")

    refute result.adopted?
    assert_includes result.errors.join(" "), "Metadata validity ended at 2025-01-01T00:00:00Z"
    assert_includes result.errors.join(" "), "ancestor EntitiesDescriptor"
    assert_equal :expired, result.evidence[:not_adopted].first[:reasons].first
  end

  def test_target_valid_until_limits_the_inherited_validity
    entity = @builder.entity("https://a.example/idp", "entity-a", "https://a.example/sso",
                             @builder.signing_certificate,
                             :valid_until => "2026-03-01T00:00:00Z")
    metadata = @builder.document([entity], :valid_until => "2027-01-01T00:00:00Z")
    result = import(@builder.sign(metadata, "root"), "https://a.example/idp")

    refute result.adopted?
    assert_includes result.errors.join(" "), "2026-03-01T00:00:00Z"
    assert_includes result.errors.join(" "), "target EntityDescriptor"
  end

  def test_idp_descriptor_validity_is_also_inherited
    entity = @builder.entity("https://a.example/idp", "entity-a", "https://a.example/sso",
                             @builder.signing_certificate,
                             :idp_valid_until => "2025-06-01T00:00:00Z")
    metadata = @builder.document([entity], :valid_until => "2027-01-01T00:00:00Z")
    result = import(@builder.sign(metadata, "root"), "https://a.example/idp")

    refute result.adopted?
    assert_includes result.errors.join(" "), "2025-06-01T00:00:00Z"
    assert_includes result.errors.join(" "), "target IDPSSODescriptor"
  end

  def test_cache_duration_on_an_ancestor_uses_the_retrieval_time
    entity = @builder.entity("https://a.example/idp", "entity-a", "https://a.example/sso",
                             @builder.signing_certificate)
    metadata = @builder.document([entity], :cache_duration => "P1D")
    result = OneLogin::RubySaml::TrustedMetadata.import(
      @builder.sign(metadata, "root"),
      :trust_anchors => @builder.root_certificate,
      :entity_id => "https://a.example/idp",
      :verification_time => Time.utc(2026, 6, 2, 12, 0, 0),
      :retrieved_at => Time.utc(2026, 5, 31, 12, 0, 0)
    )

    refute result.adopted?
    assert_includes result.errors.join(" "), "2026-06-01T12:00:00Z"
  end

  def test_duplicate_entity_ids_make_the_target_ambiguous
    duplicate = @builder.entity("https://a.example/idp", "entity-b", "https://evil.example/sso",
                                @builder.unrelated_certificate)
    metadata = @builder.document([@entity_a, duplicate])
    result = import(@builder.sign(metadata, "root"), "https://a.example/idp")

    refute result.adopted?
    assert_includes result.errors.join(" "), "more than once"
    assert_equal 2, result.evidence[:not_adopted].size
    result.evidence[:not_adopted].each do |entry|
      assert_includes entry[:reasons], :duplicate_entity_id
    end
  end

  def test_duplicate_xml_id_rejects_the_document
    duplicate = @entity_b.sub("ID=\"entity-b\"", "ID=\"entity-a\"")
    metadata = @builder.document([@entity_a, duplicate])
    result = import(@builder.sign(metadata, "root"), "https://a.example/idp")

    refute result.adopted?
    assert_includes result.errors.join(" "), "duplicate ID attributes"
  end

  def test_document_certificates_cannot_bootstrap_trust
    # The signature uses a certificate from the document itself, but that
    # certificate is self-signed and is not the configured anchor.
    metadata = @builder.sign(@metadata, "root",
                             @builder.unrelated_key, @builder.unrelated_certificate)
    result = import(metadata, "https://a.example/idp")

    refute result.adopted?
    assert_includes result.errors.join(" "), "does not chain to a configured trust anchor"
    signature = result.evidence[:signatures].first
    refute signature[:valid]
  end

  def test_signature_must_be_a_direct_child_of_the_element_it_covers
    metadata = @builder.sign(@metadata, "entity-a")
    doc = metadata
    signature = doc.xpath("//*[local-name()=$ln and namespace-uri()=$ds]", nil,
                          { "ln" => "Signature", "ds" => DSIG }).first

    # Keep the signature below the entity but make it claim to cover the
    # collection. A signature that is not a direct child of the covered
    # element must not be credited with covering that element.
    entity = doc.at_xpath("//*[@ID=$id]", nil, { "id" => "entity-a" })
    entity.add_child(signature)
    reference = signature.at_xpath("./ds:SignedInfo/ds:Reference", { "ds" => DSIG })
    reference["URI"] = "#root"

    result = import(doc, "https://a.example/idp")
    refute result.adopted?
    assert_includes result.errors.join(" "), "must be a direct child of the element it covers"
  end

  def test_tampering_with_a_signed_sibling_invalidates_the_collection_signature
    doc = @builder.sign(@metadata, "root")
    tampered = doc.to_xml(:save_with => Nokogiri::XML::Node::SaveOptions::AS_XML)
    tampered = tampered.sub("https://b.example/sso", "https://evil.example/sso")

    result = import(tampered, "https://a.example/idp")
    refute result.adopted?
    assert_includes result.errors.join(" "), "Signature covering the target is invalid"
    refute result.evidence[:signatures].first[:valid]
  end

  def test_unsigned_entity_is_not_adopted
    result = import(@metadata, "https://a.example/idp")

    refute result.adopted?
    assert_includes result.errors.join(" "), "No trusted signature covers the target entity"
  end

  def test_missing_entity_is_reported
    result = import(@builder.sign(@metadata, "root"), "https://missing.example/idp")

    refute result.adopted?
    assert_includes result.errors.join(" "), "No EntityDescriptor found"
  end

  def test_target_without_idp_descriptor_is_not_adopted
    sp = <<-XML
  <md:EntityDescriptor entityID="https://sp.example" ID="sp">
    <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/>
  </md:EntityDescriptor>
    XML
    metadata = @builder.document([sp])
    result = import(@builder.sign(metadata, "root"), "https://sp.example")

    refute result.adopted?
    assert_includes result.errors.join(" "), "no IDPSSODescriptor"
  end

  def test_signing_certificate_is_required
    entity = @builder.entity("https://a.example/idp", "entity-a", "https://a.example/sso",
                             @builder.signing_certificate,
                             :publish_signing_certificate => false)
    metadata = @builder.document([entity])
    result = import(@builder.sign(metadata, "root"), "https://a.example/idp")

    refute result.adopted?
    assert_includes result.errors.join(" "), "publishes no signing certificate"
  end

  def test_import_bang_raises_for_a_rejected_target
    error = assert_raises(OneLogin::RubySaml::ValidationError) do
      OneLogin::RubySaml::TrustedMetadata.import!(
        @metadata,
        :trust_anchors => @builder.root_certificate,
        :entity_id => "https://a.example/idp",
        :verification_time => VERIFY_AT
      )
    end
    assert_includes error.message, "No trusted signature covers the target entity"
  end

  def test_no_signing_reference_does_not_select_the_first_entity
    metadata = @builder.sign(@metadata, "root")
    result = import(metadata, "https://missing.example/idp")
    refute result.adopted?
    assert_includes result.errors.join(" "), "No EntityDescriptor found"
    assert_equal 2, result.evidence[:not_adopted].size
  end

  def test_single_certificate_is_exposed_as_idp_cert_and_fingerprint
    result = import(@builder.sign(@metadata, "root"), "https://a.example/idp")

    assert result.adopted?
    assert_equal result.settings.idp_cert_multi[:signing].first, result.settings.idp_cert
    fingerprint = OpenSSL::Digest::SHA1.hexdigest(@builder.signing_certificate.to_der).upcase.scan(/../).join(":")
    assert_equal fingerprint, result.settings.idp_cert_fingerprint
    assert_equal [], result.settings.idp_cert_multi[:encryption]
  end

  def test_encryption_only_certificate_is_not_a_signing_certificate
    entity = @builder.entity("https://a.example/idp", "entity-a", "https://a.example/sso",
                             @builder.signing_certificate,
                             :publish_signing_certificate => false)
    metadata = @builder.document([entity])
    result = import(@builder.sign(metadata, "root"), "https://a.example/idp")

    refute result.adopted?
    assert_includes result.errors.join(" "), "publishes no signing certificate"
  end

  def test_import_raises_for_invalid_arguments
    assert_raises(ArgumentError) do
      OneLogin::RubySaml::TrustedMetadata.import(
        @metadata,
        :trust_anchors => [],
        :entity_id => "https://a.example/idp",
        :verification_time => VERIFY_AT
      )
    end
    assert_raises(ArgumentError) do
      OneLogin::RubySaml::TrustedMetadata.import(
        @metadata,
        :trust_anchors => @builder.root_certificate,
        :entity_id => "",
        :verification_time => VERIFY_AT
      )
    end
    assert_raises(ArgumentError) do
      OneLogin::RubySaml::TrustedMetadata.import(
        @metadata,
        :trust_anchors => @builder.root_certificate,
        :entity_id => "https://a.example/idp",
        :verification_time => "not-a-time"
      )
    end
  end

  def test_malicious_doctype_is_rejected
    metadata = @builder.document([@entity_a])
    doctype = <<-XML
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
#{metadata.sub(/<\?xml version="1.0" encoding="UTF-8"\?>\n/, "")}
    XML
    result = import(doctype, "https://a.example/idp")

    refute result.adopted?
    assert_includes result.errors.join(" "), "safe SAML metadata document"
  end

  def test_class_import_supports_a_nokogiri_document_and_retrieved_at
    signed = @builder.sign(@metadata, "root")
    result = OneLogin::RubySaml::TrustedMetadata.import(
      signed,
      :trust_anchors => @builder.root_certificate,
      :entity_id => "https://a.example/idp",
      :verification_time => VERIFY_AT,
      :retrieved_at => VERIFY_AT - 3600
    )
    assert result.adopted?
  end

  def test_signing_certificate_expiry_is_checked_at_verification_time
    builder = Builder.new(:not_before => Time.utc(2024, 1, 1),
                          :not_after => Time.utc(2028, 1, 1),
                          :signer_not_after => Time.utc(2025, 1, 1))
    entity = builder.entity("https://a.example/idp", "entity-a", "https://a.example/sso",
                            builder.signing_certificate)
    metadata = builder.document([entity], :valid_until => "2028-01-01T00:00:00Z")
    result = OneLogin::RubySaml::TrustedMetadata.import(
      builder.sign(metadata, "root"),
      :trust_anchors => builder.root_certificate,
      :entity_id => "https://a.example/idp",
      :verification_time => VERIFY_AT
    )

    refute result.adopted?
    assert_includes result.errors.join(" "), "does not chain to a configured trust anchor"
    assert_includes result.errors.join(" "), "expired"
  end

  def test_trust_anchor_validity_is_checked_at_verification_time
    builder = Builder.new(:not_before => Time.utc(2024, 1, 1),
                          :not_after => Time.utc(2027, 1, 1))
    entity = builder.entity("https://a.example/idp", "entity-a", "https://a.example/sso",
                            builder.signing_certificate)
    metadata = builder.document([entity], :valid_until => "2030-01-01T00:00:00Z")
    result = OneLogin::RubySaml::TrustedMetadata.import(
      builder.sign(metadata, "root"),
      :trust_anchors => builder.root_certificate,
      :entity_id => "https://a.example/idp",
      :verification_time => Time.utc(2027, 6, 1)
    )

    refute result.adopted?
    assert_includes result.errors.join(" "), "does not chain to a configured trust anchor"
    assert_includes result.errors.join(" "), "expired"
  end

  def test_every_signature_is_recorded_in_evidence
    metadata = @builder.sign(@builder.sign(@metadata, "entity-a"), "root")
    result = import(metadata, "https://a.example/idp")

    assert result.adopted?
    assert_equal 2, result.evidence[:signatures].size
    assert result.evidence[:signatures].all? { |signature| signature[:valid] }
    referenced = result.evidence[:signatures].map { |signature| signature[:referenced_name] }.sort
    assert_equal ["EntitiesDescriptor", "EntityDescriptor"], referenced
  end

  def test_idp_metadata_parser_exposes_the_restricted_entry_point
    result = OneLogin::RubySaml::IdpMetadataParser.new.parse_restricted(
      @builder.sign(@metadata, "root"),
      :trust_anchors => @builder.root_certificate,
      :entity_id => "https://a.example/idp",
      :verification_time => VERIFY_AT
    )

    assert result.adopted?
    assert_equal "https://a.example/sso", result.settings.idp_sso_service_url

    rejected = OneLogin::RubySaml::IdpMetadataParser.new.parse_restricted(
      @metadata,
      :trust_anchors => @builder.root_certificate,
      :entity_id => "https://a.example/idp",
      :verification_time => VERIFY_AT
    )
    refute rejected.adopted?
    assert_includes rejected.errors.join(" "), "No trusted signature covers the target entity"
  end

  def test_nested_collection_signature_covers_only_its_descendants
    nested = <<-XML
  <md:EntitiesDescriptor ID="inner" Name="inner-collection">
#{@entity_a}
  </md:EntitiesDescriptor>
    XML
    metadata = @builder.document([nested, @entity_b])
    signed = @builder.sign(metadata, "inner")

    inside = import(signed, "https://a.example/idp")
    assert inside.adopted?
    assert_equal "https://a.example/sso", inside.settings.idp_sso_service_url

    outside = import(signed, "https://b.example/idp")
    refute outside.adopted?
    assert_includes outside.errors.join(" "), "No trusted signature covers the target entity"
  end

  def test_nested_ancestor_validity_applies_only_to_its_descendants
    nested = <<-XML
  <md:EntitiesDescriptor ID="inner" Name="inner-collection" validUntil="2025-01-01T00:00:00Z">
#{@entity_a}
  </md:EntitiesDescriptor>
    XML
    metadata = @builder.document([nested, @entity_b], :valid_until => "2029-01-01T00:00:00Z")
    signed = @builder.sign(metadata, "root")

    expired = import(signed, "https://a.example/idp")
    refute expired.adopted?
    assert_includes expired.errors.join(" "), "2025-01-01T00:00:00Z"
    assert_includes expired.errors.join(" "), "inner-collection"

    # The sibling is outside the expired nested collection and the root
    # signature covers it.
    accepted = import(signed, "https://b.example/idp")
    assert accepted.adopted?
    assert_equal "https://b.example/sso", accepted.settings.idp_sso_service_url
    assert_equal "2029-01-01T00:00:00Z", accepted.settings.valid_until
  end

  def test_trust_anchor_accepts_a_pem_string
    result = OneLogin::RubySaml::TrustedMetadata.import(
      @builder.sign(@metadata, "root"),
      :trust_anchors => @builder.root_certificate.to_pem,
      :entity_id => "https://a.example/idp",
      :verification_time => VERIFY_AT
    )

    assert result.adopted?
  end
end
