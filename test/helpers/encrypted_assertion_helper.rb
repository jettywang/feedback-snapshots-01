require 'base64'
require 'openssl'
require 'securerandom'
require 'rexml/document'
require 'xml_security'

# Builds schema-valid SAML responses carrying an EncryptedAssertion so tests can
# target the decryption and key-binding layers instead of XML parsing failures.
module EncryptedAssertionHelper
  extend self

  XENC = 'http://www.w3.org/2001/04/xmlenc#'.freeze
  DSIG = 'http://www.w3.org/2000/09/xmldsig#'.freeze
  SAML_ASSERTION = 'urn:oasis:names:tc:SAML:2.0:assertion'.freeze

  # @return [Array(OpenSSL::PKey::RSA, OpenSSL::X509::Certificate)]
  def sp_keypair
    key = OpenSSL::PKey::RSA.new(2048)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 0
    cert.not_before = Time.now - 3600
    cert.not_after = Time.now + 3600
    cert.public_key = key.public_key
    cert.subject = OpenSSL::X509::Name.parse('/CN=Ruby SAML Test SP')
    cert.issuer = cert.subject
    cert.sign(key, OpenSSL::Digest::SHA256.new)
    [key, cert]
  end

  # @return [Hash] A settings object configured with both SP encryption pairs.
  def settings_for(idp_cert, acs, *pairs)
    settings = OneLogin::RubySaml::Settings.new
    settings.idp_cert = idp_cert.to_pem
    settings.sp_entity_id = 'https://sp.example.org/metadata'
    settings.assertion_consumer_service_url = acs
    settings.sp_cert_multi = {
      encryption: pairs.map { |key, cert| { certificate: cert.to_pem, private_key: key.to_pem } }
    }
    settings
  end

  # @return [String] A short-lived assertion addressed to +recipient+.
  def assertion(assertion_id, recipient:, audience: 'https://sp.example.org/metadata', name_id: 'alice@example.com')
    issue_instant = Time.now.utc
    not_before = (issue_instant - 60).strftime('%Y-%m-%dT%H:%M:%SZ')
    not_on_or_after = (issue_instant + 300).strftime('%Y-%m-%dT%H:%M:%SZ')
    issue_instant = issue_instant.strftime('%Y-%m-%dT%H:%M:%SZ')

    <<~XML
      <saml:Assertion xmlns:saml="#{SAML_ASSERTION}" ID="#{assertion_id}" Version="2.0" IssueInstant="#{issue_instant}">
        <saml:Issuer>https://idp.example.org/metadata</saml:Issuer>
        <saml:Subject>
          <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">#{name_id}</saml:NameID>
          <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
            <saml:SubjectConfirmationData InResponseTo="_request" NotOnOrAfter="#{not_on_or_after}" Recipient="#{recipient}"/>
          </saml:SubjectConfirmation>
        </saml:Subject>
        <saml:Conditions NotBefore="#{not_before}" NotOnOrAfter="#{not_on_or_after}">
          <saml:AudienceRestriction><saml:Audience>#{audience}</saml:Audience></saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AuthnStatement AuthnInstant="#{issue_instant}" SessionIndex="_session">
          <saml:AuthnContext>
            <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
          </saml:AuthnContext>
        </saml:AuthnStatement>
      </saml:Assertion>
    XML
  end

  # Wraps an assertion in an EncryptedAssertion.
  #
  # @param assertion [String] plaintext assertion
  # @param key [OpenSSL::PKey::RSA] recipient public key
  # @param data_id [String] EncryptedData Id
  # @param key_id [String] EncryptedKey Id
  # @param recipient [String, nil] EncryptedKey Recipient
  # @param data_reference [String, nil] EncryptedKey DataReference target
  # @param corrupt_key [Boolean] replace the encrypted symmetric key with random bytes
  # @param extra_key [Hash, nil] a second key, with :key_xml
  # @return [String]
  def encrypted_assertion(assertion, key, data_id:, key_id:, recipient: nil, data_reference: nil, corrupt_key: false, extra_key: nil)
    cipher_value, encrypted_key = encrypted_key_material(assertion, key, data_id: data_id, key_id: key_id,
                                                         recipient: recipient, data_reference: data_reference,
                                                         corrupt_key: corrupt_key)

    inline_keys = [encrypted_key]
    inline_keys << extra_key[:key_xml] if extra_key && extra_key[:key_xml]

    data_xml = <<~XML
      <xenc:EncryptedData xmlns:xenc="#{XENC}" Id="#{data_id}" Type="#{XENC}Element">
        <xenc:EncryptionMethod Algorithm="#{XENC}aes128-cbc"/>
        <ds:KeyInfo xmlns:ds="#{DSIG}">#{inline_keys.join}</ds:KeyInfo>
        <xenc:CipherData><xenc:CipherValue>#{cipher_value}</xenc:CipherValue></xenc:CipherData>
      </xenc:EncryptedData>
    XML

    %(<saml:EncryptedAssertion xmlns:saml="#{SAML_ASSERTION}">#{data_xml}</saml:EncryptedAssertion>)
  end

  # Builds an EncryptedKey element without a surrounding EncryptedAssertion.
  # @return [String]
  def encrypted_key(key, assertion, data_id:, key_id:, recipient: nil, data_reference: nil, corrupt_key: false)
    encrypted_key_material(assertion, key, data_id: data_id, key_id: key_id, recipient: recipient,
                           data_reference: data_reference, corrupt_key: corrupt_key).last
  end

  # Builds an EncryptedAssertion whose key travels by RetrievalMethod.
  # @return [String]
  def encrypted_assertion_with_retrieval_method(assertion, key, data_id:, key_id:, recipient: nil)
    cipher_value, encrypted_key = encrypted_key_material(assertion, key, data_id: data_id, key_id: key_id,
                                                         recipient: recipient, data_reference: data_id)
    data_xml = <<~XML
      <xenc:EncryptedData xmlns:xenc="#{XENC}" Id="#{data_id}" Type="#{XENC}Element">
        <xenc:EncryptionMethod Algorithm="#{XENC}aes128-cbc"/>
        <ds:KeyInfo xmlns:ds="#{DSIG}">
          <ds:RetrievalMethod Type="#{XENC}EncryptedKey" URI="##{key_id}"/>
        </ds:KeyInfo>
        <xenc:CipherData><xenc:CipherValue>#{cipher_value}</xenc:CipherValue></xenc:CipherData>
      </xenc:EncryptedData>
    XML

    %(<saml:EncryptedAssertion xmlns:saml="#{SAML_ASSERTION}">#{data_xml}#{encrypted_key}</saml:EncryptedAssertion>)
  end

  # Builds an EncryptedAssertion whose KeyInfo uses a default ds namespace,
  # matching ADFS output.
  # @return [String]
  def encrypted_assertion_with_default_key_info_namespace(assertion, key, data_id:, key_id:, recipient: nil)
    cipher_value, encrypted_key = encrypted_key_material(assertion, key, data_id: data_id, key_id: key_id,
                                                         recipient: recipient, data_reference: data_id)
    encrypted_key = encrypted_key.sub('xmlns:xenc=', 'xmlns:e=').gsub('<xenc:', '<e:').gsub('</xenc:', '</e:')
    data_xml = <<~XML
      <xenc:EncryptedData xmlns:xenc="#{XENC}" Id="#{data_id}" Type="#{XENC}Element">
        <xenc:EncryptionMethod Algorithm="#{XENC}aes128-cbc"/>
        <KeyInfo xmlns="#{DSIG}">#{encrypted_key}</KeyInfo>
        <xenc:CipherData><xenc:CipherValue>#{cipher_value}</xenc:CipherValue></xenc:CipherData>
      </xenc:EncryptedData>
    XML

    %(<saml:EncryptedAssertion xmlns:saml="#{SAML_ASSERTION}">#{data_xml}</saml:EncryptedAssertion>)
  end

  # Builds a Response with the supplied EncryptedAssertion and signs it.
  # Fixtures must be schema-valid unless +allow_invalid_ids+ is set, which is
  # used only for duplicate-ID cases where the XSD itself rejects the Id.
  # @return [String]
  def signed_response(encrypted_assertion, idp_key, idp_cert, response_id: 'RESP_1', acs: 'https://sp.example.org/acs', extensions: nil, status_detail: nil, allow_invalid_ids: false)
    response = response_xml(encrypted_assertion, response_id: response_id, acs: acs,
                            extensions: extensions, status_detail: status_detail)
    unless allow_invalid_ids || schema_valid?(response)
      raise "Fixture is not schema-valid: #{schema_errors(response).first}"
    end

    document = XMLSecurity::Document.new(response)
    document.sign_document(idp_key, idp_cert)
    document.to_s
  end

  # @return [String]
  def response_xml(encrypted_assertion, response_id: 'RESP_1', acs: 'https://sp.example.org/acs', extensions: nil, status_detail: nil)
    issue_instant = Time.now.utc.strftime('%Y-%m-%dT%H:%M:%SZ')
    extensions_xml = extensions ? "<samlp:Extensions>#{extensions}</samlp:Extensions>" : ''
    status_detail_xml = status_detail ? "<samlp:StatusDetail>#{status_detail}</samlp:StatusDetail>" : ''

    <<~XML
      <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="#{SAML_ASSERTION}" ID="#{response_id}" Version="2.0" IssueInstant="#{issue_instant}" Destination="#{acs}" InResponseTo="_request">
        <saml:Issuer>https://idp.example.org/metadata</saml:Issuer>
        #{extensions_xml}
        <samlp:Status>
          <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
          #{status_detail_xml}
        </samlp:Status>
        #{encrypted_assertion}
      </samlp:Response>
    XML
  end

  # @return [Boolean]
  def schema_valid?(response_xml)
    schema_errors(response_xml).empty?
  end

  # @return [Array<Nokogiri::XML::SyntaxError>]
  def schema_errors(response_xml)
    OneLogin::RubySaml::SamlMessage.schema.validate(Nokogiri::XML(response_xml))
  end

  private

  def encrypted_key_material(assertion, key, data_id:, key_id:, recipient: nil, data_reference: nil, corrupt_key: false)
    symmetric_key = SecureRandom.random_bytes(16)
    iv = SecureRandom.random_bytes(16)
    cipher = OpenSSL::Cipher.new('AES-128-CBC').encrypt
    cipher.key = symmetric_key
    cipher.iv = iv
    cipher_text = cipher.update(assertion) + cipher.final
    cipher_value = Base64.strict_encode64(iv + cipher_text)

    encrypted_symmetric_key =
      if corrupt_key
        Base64.strict_encode64(SecureRandom.random_bytes(256))
      else
        Base64.strict_encode64(key.public_encrypt(symmetric_key, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING))
      end

    recipient_attribute = recipient ? %( Recipient="#{recipient}") : ''
    reference_list =
      if data_reference
        %(<xenc:ReferenceList><xenc:DataReference URI="##{data_reference}"/></xenc:ReferenceList>)
      else
        ''
      end

    encrypted_key = <<~XML
      <xenc:EncryptedKey xmlns:xenc="#{XENC}" Id="#{key_id}"#{recipient_attribute}>
        <xenc:EncryptionMethod Algorithm="#{XENC}rsa-oaep-mgf1p"/>
        <xenc:CipherData><xenc:CipherValue>#{encrypted_symmetric_key}</xenc:CipherValue></xenc:CipherData>
        #{reference_list}
      </xenc:EncryptedKey>
    XML

    [cipher_value, encrypted_key]
  end
end
