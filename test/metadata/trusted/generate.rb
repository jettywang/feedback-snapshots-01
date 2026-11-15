# Regenerates the signed metadata fixtures used by trusted_metadata_importer_test.rb.
# Run from the repository root with the locked bundle:
#   /opt/homebrew/opt/ruby@3.3/bin/ruby .feedback/run.rb exec \
#     /opt/homebrew/opt/ruby@3.3/bin/ruby test/metadata/trusted/generate.rb
require "openssl"
require "base64"
require "time"
require "securerandom"
require "nokogiri"

DS = "http://www.w3.org/2000/09/xmldsig#".freeze
MD = "urn:oasis:names:tc:SAML:2.0:metadata".freeze
EXC_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#".freeze
ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature".freeze
RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256".freeze
SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256".freeze
SERIALIZE_AS_XML = Nokogiri::XML::Node::SaveOptions::AS_XML

ENTITY_A = "https://idp-a.example.com/metadata".freeze
ENTITY_B = "https://idp-b.example.com/metadata".freeze
ENTITY_C = "https://idp-c.example.com/metadata".freeze

def certificate(subject, issuer_cert, issuer_key, serial, ca, not_before, not_after)
  key = OpenSSL::PKey::RSA.new(2048)
  cert = OpenSSL::X509::Certificate.new
  cert.version = 2
  cert.serial = serial
  cert.subject = OpenSSL::X509::Name.parse(subject)
  cert.issuer = issuer_cert ? issuer_cert.subject : cert.subject
  cert.public_key = key.public_key
  cert.not_before = not_before
  cert.not_after = not_after
  extensions = OpenSSL::X509::ExtensionFactory.new
  extensions.subject_certificate = cert
  extensions.issuer_certificate = issuer_cert || cert
  cert.add_extension(extensions.create_extension("basicConstraints", ca ? "CA:TRUE" : "CA:FALSE", true))
  cert.add_extension(extensions.create_extension("keyUsage", ca ? "keyCertSign,cRLSign" : "digitalSignature", true))
  cert.sign(issuer_key || key, OpenSSL::Digest::SHA256.new)
  [key, cert]
end

def b64(cert)
  Base64.strict_encode64(cert.to_der)
end

def key_info(cert)
  %(<ds:KeyInfo><ds:X509Data><ds:X509Certificate>#{b64(cert)}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>)
end

def sign!(node, key, cert, signature_id: nil)
  node["ID"] ||= "_#{SecureRandom.hex(8)}"
  reference_id = node["ID"]
  signature_id ||= "_sig#{SecureRandom.hex(8)}"
  signature_attributes = %( Id="#{signature_id}")
  signed_info = %(<ds:SignedInfo xmlns:ds="#{DS}"><ds:CanonicalizationMethod Algorithm="#{EXC_C14N}"/><ds:SignatureMethod Algorithm="#{RSA_SHA256}"/><ds:Reference URI="##{reference_id}"><ds:Transforms><ds:Transform Algorithm="#{ENVELOPED}"/><ds:Transform Algorithm="#{EXC_C14N}"/></ds:Transforms><ds:DigestMethod Algorithm="#{SHA256}"/><ds:DigestValue></ds:DigestValue></ds:Reference></ds:SignedInfo>)
  signature = Nokogiri::XML::Document.parse(
    %(<ds:Signature#{signature_attributes} xmlns:ds="#{DS}">#{signed_info}) +
    %(<ds:SignatureValue></ds:SignatureValue>) +
    %(#{key_info(cert)}</ds:Signature>)
  ).root
  if node.element_children.first
    node.element_children.first.add_previous_sibling(signature)
  else
    node.add_child(signature)
  end

  document = Nokogiri::XML::Document.parse(node.document.to_xml(:save_with => SERIALIZE_AS_XML))
  signature = document.at_xpath("//ds:Signature[@Id='#{signature_id}']", "ds" => DS)
  raise "signature #{signature_id} not found after reparse" unless signature
  covered_element = document.at_xpath("//*[@ID='#{reference_id}']")
  covered = covered_element.dup(1)
  covered.at_xpath("./ds:Signature", "ds" => DS).remove
  covered_document = Nokogiri::XML::Document.new
  covered_document.root = covered
  digest = Base64.strict_encode64(OpenSSL::Digest::SHA256.digest(covered_document.root.canonicalize(Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0)))
  signature.at_xpath("./ds:SignedInfo/ds:Reference/ds:DigestValue", "ds" => DS).content = digest

  signed_info_node = signature.at_xpath("./ds:SignedInfo", "ds" => DS)
  signed_info_canonical = signed_info_node.canonicalize(Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0)
  signature.at_xpath("./ds:SignatureValue", "ds" => DS).content = Base64.strict_encode64(key.sign(OpenSSL::Digest::SHA256.new, signed_info_canonical))
  document.to_xml(:save_with => SERIALIZE_AS_XML)
end

def material
  @material ||= begin
    anchor_key, anchor_cert = certificate("/CN=Metadata Collection Anchor", nil, nil, 100, true,
      Time.utc(2020, 1, 1), Time.utc(2045, 1, 1))
    signer_key, signer_cert = certificate("/CN=Metadata Collection Signer", anchor_cert, anchor_key, 101, false,
      Time.utc(2020, 1, 1), Time.utc(2045, 1, 1))
    entity_a_key, entity_a_cert = certificate("/CN=IdP A Signing Certificate", nil, nil, 201, false,
      Time.utc(2020, 1, 1), Time.utc(2045, 1, 1))
    entity_b_key, entity_b_cert = certificate("/CN=IdP B Signing Certificate", nil, nil, 202, false,
      Time.utc(2020, 1, 1), Time.utc(2045, 1, 1))
    entity_c_key, entity_c_cert = certificate("/CN=IdP C Signing Certificate", nil, nil, 203, false,
      Time.utc(2020, 1, 1), Time.utc(2045, 1, 1))
    rogue_key, rogue_cert = certificate("/CN=Unanchored Metadata Signer", nil, nil, 301, false,
      Time.utc(2020, 1, 1), Time.utc(2045, 1, 1))
    short_key, short_cert = certificate("/CN=Short Lived Metadata Signer", nil, nil, 302, false,
      Time.utc(2020, 1, 1), Time.utc(2025, 1, 1))
    {
      :anchor_key => anchor_key, :anchor_cert => anchor_cert,
      :signer_key => signer_key, :signer_cert => signer_cert,
      :entity_a_key => entity_a_key, :entity_a_cert => entity_a_cert,
      :entity_b_key => entity_b_key, :entity_b_cert => entity_b_cert,
      :entity_c_key => entity_c_key, :entity_c_cert => entity_c_cert,
      :rogue_key => rogue_key, :rogue_cert => rogue_cert,
      :short_key => short_key, :short_cert => short_cert
    }
  end
end

def entity(entity_id, cert, role: "idp", valid_until: nil, cache_duration: nil, id: nil)
  attributes = %(entityID="#{entity_id}")
  attributes << %( ID="#{id}") if id
  attributes << %( validUntil="#{valid_until}") if valid_until
  attributes << %( cacheDuration="#{cache_duration}") if cache_duration
  if role == "idp"
    body = %(<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">) +
      %(<md:KeyDescriptor use="signing">#{key_info(cert)}</md:KeyDescriptor>) +
      %(<md:KeyDescriptor use="encryption">#{key_info(cert)}</md:KeyDescriptor>) +
      %(<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="#{entity_id.sub('/metadata', '/slo')}"/>) +
      %(<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>) +
      %(<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="#{entity_id.sub('/metadata', '/sso')}"/>) +
      %(</md:IDPSSODescriptor>)
  else
    body = %(<md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">) +
      %(<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="#{entity_id.sub('/metadata', '/acs')}" index="0"/>) +
      %(</md:SPSSODescriptor>)
  end
  %(<md:EntityDescriptor xmlns:md="#{MD}" xmlns:ds="#{DS}" #{attributes}>#{body}</md:EntityDescriptor>)
end

def collection(entities, valid_until: nil, cache_duration: nil, id: "collection", issue_instant: nil)
  attributes = %(ID="#{id}" xmlns:md="#{MD}" xmlns:ds="#{DS}")
  attributes << %( validUntil="#{valid_until}") if valid_until
  attributes << %( cacheDuration="#{cache_duration}") if cache_duration
  attributes << %( IssueInstant="#{issue_instant}") if issue_instant
  "<md:EntitiesDescriptor #{attributes}>#{entities}</md:EntitiesDescriptor>"
end

def write(name, xml)
  File.write(File.join(__dir__, name), xml)
end

m = material
a = entity(ENTITY_A, m[:entity_a_cert], valid_until: "2030-06-01T00:00:00Z")
b = entity(ENTITY_B, m[:entity_b_cert])
c = entity(ENTITY_C, m[:entity_c_cert])

# 1. Collection signed; A and B are both covered by the collection signature.
xml = Nokogiri::XML(collection(a + b, valid_until: "2031-01-01T00:00:00Z"))
write("collection_signed.xml", sign!(xml.root, m[:signer_key], m[:signer_cert]))

# 2. Collection expired before verification time, although both entities are individually current.
xml = Nokogiri::XML(collection(a + b, valid_until: "2024-01-01T00:00:00Z"))
write("collection_expired.xml", sign!(xml.root, m[:signer_key], m[:signer_cert]))

# 3. Only entity A is signed. B must not inherit the signature.
xml = Nokogiri::XML(collection(a + b, valid_until: "2031-01-01T00:00:00Z"))
target = xml.at_xpath("//md:EntityDescriptor[@entityID='#{ENTITY_A}']", "md" => MD)
write("entity_a_signed.xml", sign!(target, m[:signer_key], m[:signer_cert], :signature_id => "sig-entity-a"))

# 4. Entity B is signed with the certificate it advertises in its own KeyDescriptor,
#    but that certificate is not chained to the configured trust anchor.
xml = Nokogiri::XML(collection(a + b, valid_until: "2031-01-01T00:00:00Z"))
target = xml.at_xpath("//md:EntityDescriptor[@entityID='#{ENTITY_B}']", "md" => MD)
write("entity_b_self_signed.xml", sign!(target, m[:entity_b_key], m[:entity_b_cert], :signature_id => "sig-entity-b"))

# 4b. Only entity B is signed by an anchored signer. Target A must not inherit it.
xml = Nokogiri::XML(collection(a + b, valid_until: "2031-01-01T00:00:00Z"))
target = xml.at_xpath("//md:EntityDescriptor[@entityID='#{ENTITY_B}']", "md" => MD)
write("entity_b_signed.xml", sign!(target, m[:signer_key], m[:signer_cert], :signature_id => "sig-entity-b-anchored"))

# 5. Duplicate entityID: A appears twice, one with a different SSO endpoint.
duplicate = entity(ENTITY_A, m[:entity_b_cert], valid_until: "2030-06-01T00:00:00Z", id: "dup-a")
xml = Nokogiri::XML(collection(a + duplicate + b, valid_until: "2031-01-01T00:00:00Z"))
write("duplicate_entity_id.xml", sign!(xml.root, m[:signer_key], m[:signer_cert]))

# 6. Entity's own validUntil limits an otherwise valid collection signature.
a_short = entity(ENTITY_A, m[:entity_a_cert], valid_until: "2024-01-01T00:00:00Z")
xml = Nokogiri::XML(collection(a_short + b, valid_until: "2031-01-01T00:00:00Z"))
write("entity_expired.xml", sign!(xml.root, m[:signer_key], m[:signer_cert]))

# 7. Nested collection: inner collection expired; A is only signed by an unanchored signer.
inner_entities = entity(ENTITY_A, m[:entity_a_cert]) + c
inner = collection(inner_entities, valid_until: "2024-01-01T00:00:00Z", id: "inner")
xml = Nokogiri::XML(collection(inner + b, valid_until: "2031-01-01T00:00:00Z"))
target = xml.at_xpath("//md:EntityDescriptor[@entityID='#{ENTITY_A}']", "md" => MD)
write("nested_expired_ancestor.xml", sign!(target, m[:rogue_key], m[:rogue_cert], :signature_id => "sig-inner-a"))

# 8. Target is an SP, so no SSO endpoint and no IdP certificate may be adopted.
sp = entity(ENTITY_C, m[:entity_c_cert], :role => "sp", :valid_until => "2030-06-01T00:00:00Z")
xml = Nokogiri::XML(collection(a + sp, valid_until: "2031-01-01T00:00:00Z"))
write("target_is_sp.xml", sign!(xml.root, m[:signer_key], m[:signer_cert]))

# 9. Target absent from the collection.
xml = Nokogiri::XML(collection(b, valid_until: "2031-01-01T00:00:00Z"))
write("target_missing.xml", sign!(xml.root, m[:signer_key], m[:signer_cert]))

# 10. No validUntil anywhere; cacheDuration limits freshness from the verification time.
xml = Nokogiri::XML(collection(a + b, cache_duration: "P30D", issue_instant: "2026-06-01T00:00:00Z"))
write("collection_cache_duration.xml", sign!(xml.root, m[:signer_key], m[:signer_cert]))

# 11. Target A carries two covering signatures: one on the collection and one
#     directly on the entity. Both are anchored and both must verify.
xml = Nokogiri::XML(collection(a + b, valid_until: "2031-01-01T00:00:00Z"))
target = xml.at_xpath("//md:EntityDescriptor[@entityID='#{ENTITY_A}']", "md" => MD)
xml = Nokogiri::XML(sign!(target, m[:signer_key], m[:signer_cert], :signature_id => "sig-entity-a"))
xml = Nokogiri::XML(sign!(xml.root, m[:signer_key], m[:signer_cert]))
write("entity_and_collection_signed.xml", xml.to_xml(:save_with => SERIALIZE_AS_XML))

# 12. Target A has a valid anchored collection signature and an additional
#     entity signature made by an unanchored key. The whole target must be
#     rejected rather than falling back to the valid signature.
xml = Nokogiri::XML(collection(a + b, valid_until: "2031-01-01T00:00:00Z"))
target = xml.at_xpath("//md:EntityDescriptor[@entityID='#{ENTITY_A}']", "md" => MD)
xml = Nokogiri::XML(sign!(target, m[:rogue_key], m[:rogue_cert], :signature_id => "sig-rogue-a"))
xml = Nokogiri::XML(sign!(xml.root, m[:signer_key], m[:signer_cert]))
write("target_with_untrusted_extra_signature.xml", xml.to_xml(:save_with => SERIALIZE_AS_XML))

# 13. Target A is nested one level deeper; the signature is on the inner
#     collection, so it covers A and C but not the outer sibling B.
inner_signed_entities = entity(ENTITY_A, m[:entity_a_cert], valid_until: "2030-06-01T00:00:00Z") + c
inner = collection(inner_signed_entities, valid_until: "2031-01-01T00:00:00Z", id: "inner")
xml = Nokogiri::XML(collection(inner + b, valid_until: "2031-01-01T00:00:00Z"))
inner = xml.at_xpath("//md:EntitiesDescriptor[@ID='inner']", "md" => MD)
raise "inner collection missing" unless inner
xml = Nokogiri::XML(sign!(inner, m[:signer_key], m[:signer_cert], :signature_id => "sig-inner"))
write("inner_collection_signed.xml", xml.to_xml(:save_with => SERIALIZE_AS_XML))

# 14. Target A advertises two signing certificates; both are adopted, but only
#     after the entity is authenticated through the anchor.
multi_cert_entity = entity(ENTITY_A, m[:entity_a_cert], valid_until: "2030-06-01T00:00:00Z")
                      .sub(%q{<md:KeyDescriptor use="encryption">}, %{<md:KeyDescriptor use="signing">#{key_info(m[:entity_b_cert])}</md:KeyDescriptor><md:KeyDescriptor use="encryption">})
xml = Nokogiri::XML(collection(multi_cert_entity + b, valid_until: "2031-01-01T00:00:00Z"))
write("multiple_signing_certificates.xml", sign!(xml.root, m[:signer_key], m[:signer_cert]))

# 15. Collection signed by a certificate that was valid when the metadata was
#     issued but has expired by the verification time.
xml = Nokogiri::XML(collection(a + b, valid_until: "2031-01-01T00:00:00Z"))
write("collection_short_lived_signer.xml", sign!(xml.root, m[:short_key], m[:short_cert]))
write("short_lived_signer.pem", m[:short_cert].to_pem)

write("anchor.pem", m[:anchor_cert].to_pem)
write("signer.pem", m[:signer_cert].to_pem)
write("rogue.pem", m[:rogue_cert].to_pem)
puts "fixtures written to #{__dir__}"
