require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))
require 'onelogin/ruby-saml/response'

class EncryptedAssertionBindingTest < Minitest::Test
  ACS = 'https://sp.example.org/acs'.freeze

  def setup
    @idp_key = OpenSSL::PKey::RSA.new(ruby_saml_key_text)
    @idp_cert = OpenSSL::X509::Certificate.new(ruby_saml_cert_text)
    @sp1_key, @sp1_cert = EncryptedAssertionHelper.sp_keypair
    @sp2_key, @sp2_cert = EncryptedAssertionHelper.sp_keypair
    @settings = EncryptedAssertionHelper.settings_for(@idp_cert, ACS, [@sp1_key, @sp1_cert], [@sp2_key, @sp2_cert])
  end

  def response_for(encrypted_assertion, **options)
    signed = EncryptedAssertionHelper.signed_response(encrypted_assertion, @idp_key, @idp_cert, **options)
    OneLogin::RubySaml::Response.new(signed, settings: @settings)
  end

  def assert_duplicate_id_fixture_is_well_formed_and_signed(encrypted_assertion, **options)
    signed = EncryptedAssertionHelper.signed_response(
      encrypted_assertion, @idp_key, @idp_cert, allow_invalid_ids: true, **options
    )
    document = XMLSecurity::SignedDocument.new(signed)
    assert_equal 'RESP_1', document.signed_element_id
    assert document.validate_document_with_cert(@idp_cert)
    signed
  end

  # A correct sample: same key, same data node, same assertion, correct recipient.
  def test_correctly_bound_encrypted_assertion_is_accepted_and_decrypts_the_signed_assertion
    encrypted = EncryptedAssertionHelper.encrypted_assertion(
      EncryptedAssertionHelper.assertion('_assertion_ok', recipient: ACS),
      @sp1_key,
      data_id: 'ED_1',
      key_id: 'EK_1',
      recipient: ACS,
      data_reference: 'ED_1'
    )

    response = response_for(encrypted)

    assert response.decrypted_document
    assert_equal 'alice@example.com', response.nameid
    assert response.is_valid?
    assert_empty response.errors

    encrypted_data = REXML::XPath.first(response.document, '//xenc:EncryptedData', 'xenc' => EncryptedAssertionHelper::XENC)
    assert_equal 'ED_1', encrypted_data.attributes['Id']

    encrypted_key = REXML::XPath.first(response.document, '//xenc:EncryptedKey', 'xenc' => EncryptedAssertionHelper::XENC)
    assert_equal 'EK_1', encrypted_key.attributes['Id']
    assert_equal ACS, encrypted_key.attributes['Recipient']
    assert_equal '#ED_1', REXML::XPath.first(encrypted_key, './xenc:ReferenceList/xenc:DataReference',
                                              'xenc' => EncryptedAssertionHelper::XENC).attributes['URI']

    assert_nil REXML::XPath.first(response.decrypted_document, '//xenc:EncryptedData', 'xenc' => EncryptedAssertionHelper::XENC)
    decrypted_assertion = REXML::XPath.first(response.decrypted_document, '//a:Assertion', 'a' => EncryptedAssertionHelper::SAML_ASSERTION)
    assert_equal '_assertion_ok', decrypted_assertion.attributes['ID']
  end

  # The assertion is correctly decrypted, then rejected at assertion validation.
  def test_wrong_subject_confirmation_recipient_is_rejected_by_assertion_validation
    encrypted = EncryptedAssertionHelper.encrypted_assertion(
      EncryptedAssertionHelper.assertion('_assertion_wrong_recipient', recipient: 'https://evil.example.org/acs'),
      @sp1_key,
      data_id: 'ED_1',
      key_id: 'EK_1',
      recipient: ACS,
      data_reference: 'ED_1'
    )

    response = response_for(encrypted)

    assert response.decrypted_document
    assert_equal 'alice@example.com', response.nameid
    refute response.is_valid?
    assert_includes response.errors, 'A valid SubjectConfirmation was not found on this Response'
  end

  # The EncryptedKey is addressed to another SP and must not be used, even though it decrypts.
  def test_encrypted_key_for_another_recipient_is_rejected_before_key_trial
    encrypted = EncryptedAssertionHelper.encrypted_assertion(
      EncryptedAssertionHelper.assertion('_assertion_key_recipient', recipient: ACS),
      @sp1_key,
      data_id: 'ED_1',
      key_id: 'EK_1',
      recipient: 'https://other-sp.example.org/acs',
      data_reference: 'ED_1'
    )

    error = assert_raises(OneLogin::RubySaml::ValidationError) { response_for(encrypted) }
    assert_includes error.message, 'EncryptedKey #EK_1 is for another Recipient'
  end

  # The EncryptedKey references another EncryptedData node.
  def test_data_reference_to_another_data_node_is_rejected_at_key_binding
    encrypted = EncryptedAssertionHelper.encrypted_assertion(
      EncryptedAssertionHelper.assertion('_assertion_data_reference', recipient: ACS),
      @sp1_key,
      data_id: 'ED_1',
      key_id: 'EK_1',
      recipient: ACS,
      data_reference: 'ED_decoy'
    )

    error = assert_raises(OneLogin::RubySaml::ValidationError) do
      response_for(encrypted, status_detail: decoy_encrypted_data('ED_decoy'))
    end
    assert_includes error.message, 'EncryptedKey #EK_1 references another EncryptedData'
  end

  # Two EncryptedKey elements carry the same Id: one correct, one broken.
  def test_duplicate_encrypted_key_id_is_rejected_even_when_one_key_is_correct
    encrypted = EncryptedAssertionHelper.encrypted_assertion(
      EncryptedAssertionHelper.assertion('_assertion_duplicate_key_id', recipient: ACS),
      @sp1_key,
      data_id: 'ED_1',
      key_id: 'EK_duplicate',
      recipient: ACS,
      data_reference: 'ED_1',
      extra_key: {
        key_xml: EncryptedAssertionHelper.encrypted_key(
          @sp2_key,
          EncryptedAssertionHelper.assertion('_assertion_other', recipient: ACS),
          data_id: 'ED_2',
          key_id: 'EK_duplicate',
          recipient: ACS,
          data_reference: 'ED_1'
        )
      }
    )

    signed = assert_duplicate_id_fixture_is_well_formed_and_signed(encrypted)

    error = assert_raises(OneLogin::RubySaml::ValidationError) do
      OneLogin::RubySaml::Response.new(signed, settings: @settings)
    end
    assert_includes error.message, 'duplicated EncryptedKey Id'
  end

  # Two EncryptedData nodes share an Id: the real one and a decoy in a
  # well-formed StatusDetail extension. The duplicate ID itself violates xs:ID.
  def test_duplicate_encrypted_data_id_is_rejected_at_binding
    encrypted = EncryptedAssertionHelper.encrypted_assertion(
      EncryptedAssertionHelper.assertion('_assertion_duplicate_data_id', recipient: ACS),
      @sp1_key,
      data_id: 'ED_duplicate',
      key_id: 'EK_1',
      recipient: ACS,
      data_reference: 'ED_duplicate'
    )

    signed = assert_duplicate_id_fixture_is_well_formed_and_signed(
      encrypted, status_detail: decoy_encrypted_data('ED_duplicate')
    )

    error = assert_raises(OneLogin::RubySaml::ValidationError) do
      OneLogin::RubySaml::Response.new(signed, settings: @settings)
    end
    assert_includes error.message, 'duplicated EncryptedData Id'
  end

  # The duplicate-Id rejection is raised while the Response is constructed,
  # before is_valid? can run schema validation on the document.
  def test_duplicate_data_id_is_rejected_before_schema_validation
    encrypted = EncryptedAssertionHelper.encrypted_assertion(
      EncryptedAssertionHelper.assertion('_assertion_duplicate_data_id_layering', recipient: ACS),
      @sp1_key,
      data_id: 'ED_duplicate_layering',
      key_id: 'EK_1',
      recipient: ACS,
      data_reference: 'ED_duplicate_layering'
    )

    signed = assert_duplicate_id_fixture_is_well_formed_and_signed(
      encrypted, status_detail: decoy_encrypted_data('ED_duplicate_layering')
    )

    response = nil
    error = assert_raises(OneLogin::RubySaml::ValidationError) do
      response = OneLogin::RubySaml::Response.new(signed, settings: @settings)
    end
    assert_nil response
    assert_includes error.message, 'duplicated EncryptedData Id'
  end

  # A valid key and a corrupt key both target the same EncryptedData. The
  # correct key must not be used to silently bypass the corrupt one.
  def test_correct_and_corrupt_encrypted_keys_for_the_same_data_are_rejected_as_ambiguous
    encrypted = EncryptedAssertionHelper.encrypted_assertion(
      EncryptedAssertionHelper.assertion('_assertion_good_and_bad', recipient: ACS),
      @sp1_key,
      data_id: 'ED_1',
      key_id: 'EK_good',
      recipient: ACS,
      data_reference: 'ED_1',
      extra_key: {
        key_xml: EncryptedAssertionHelper.encrypted_key(
          @sp2_key,
          EncryptedAssertionHelper.assertion('_assertion_decoy', recipient: ACS, name_id: 'mallory@example.com'),
          data_id: 'ED_decoy',
          key_id: 'EK_bad',
          recipient: ACS,
          data_reference: 'ED_1',
          corrupt_key: true
        )
      }
    )

    error = assert_raises(OneLogin::RubySaml::ValidationError) { response_for(encrypted) }
    assert_includes error.message, 'multiple EncryptedKey elements are bound to the EncryptedData'
  end

  # A key bound to a different data node must not be used just because it
  # happens to decrypt successfully for one SP key. The correct key is supplied
  # as an inline extra, while the only key bound to ED_1 points at ED_2.
  def test_key_bound_to_a_different_data_node_cannot_be_selected_by_successful_decryption
    encrypted = EncryptedAssertionHelper.encrypted_assertion(
      EncryptedAssertionHelper.assertion('_assertion_primary', recipient: ACS),
      @sp1_key,
      data_id: 'ED_1',
      key_id: 'EK_decoy',
      recipient: ACS,
      data_reference: 'ED_2',
      extra_key: {
        key_xml: EncryptedAssertionHelper.encrypted_key(
          @sp1_key,
          EncryptedAssertionHelper.assertion('_assertion_primary', recipient: ACS),
          data_id: 'ED_1',
          key_id: 'EK_correct',
          recipient: ACS,
          data_reference: 'ED_2'
        )
      }
    )

    error = assert_raises(OneLogin::RubySaml::ValidationError) do
      response_for(encrypted, status_detail: decoy_encrypted_data('ED_2'))
    end
    assert_includes error.message, 'references another EncryptedData'
  end

  # Ensures the outer Response signature covers the encrypted assertion and
  # that decryption does not alter the signed node's identity.
  def test_outer_signature_is_valid_and_decryption_keeps_the_signed_assertion_chain
    encrypted = EncryptedAssertionHelper.encrypted_assertion(
      EncryptedAssertionHelper.assertion('_assertion_chain', recipient: ACS),
      @sp1_key,
      data_id: 'ED_1',
      key_id: 'EK_1',
      recipient: ACS,
      data_reference: 'ED_1'
    )

    response = response_for(encrypted)

    assert response.send(:validate_signature)
    assert_equal 'RESP_1', response.document.signed_element_id
    assert_equal '_assertion_chain', response.assertion_id
    assert_equal 'alice@example.com', response.nameid

    encrypted_data = REXML::XPath.first(response.document, '//xenc:EncryptedData', 'xenc' => EncryptedAssertionHelper::XENC)
    assert_equal 'ED_1', encrypted_data.attributes['Id']

    decrypted_assertion = REXML::XPath.first(response.decrypted_document, '//a:Assertion', 'a' => EncryptedAssertionHelper::SAML_ASSERTION)
    assert_equal response.assertion_id, decrypted_assertion.attributes['ID']
    assert_equal '_assertion_chain', decrypted_assertion.attributes['ID']
  end

  def test_decrypt_multi_refuses_to_select_a_key_from_multiple_candidates
    encrypted = EncryptedAssertionHelper.encrypted_assertion(
      EncryptedAssertionHelper.assertion('_assertion_helper', recipient: ACS),
      @sp1_key,
      data_id: 'ED_1',
      key_id: 'EK_1',
      recipient: ACS,
      data_reference: 'ED_1',
      extra_key: {
        key_xml: EncryptedAssertionHelper.encrypted_key(
          @sp2_key,
          EncryptedAssertionHelper.assertion('_assertion_helper_other', recipient: ACS),
          data_id: 'ED_1',
          key_id: 'EK_2',
          recipient: ACS,
          data_reference: 'ED_1'
        )
      }
    )

    encrypted_node = REXML::Document.new(encrypted).root
    error = assert_raises(OneLogin::RubySaml::ValidationError) do
      OneLogin::RubySaml::Utils.decrypt_multi(encrypted_node, [@sp1_key, @sp2_key], ACS)
    end
    assert_includes error.message, 'multiple EncryptedKey elements are bound to the EncryptedData'
  end

  def test_retrieval_method_key_is_accepted_when_it_resolves_to_the_same_data_node
    encrypted = EncryptedAssertionHelper.encrypted_assertion_with_retrieval_method(
      EncryptedAssertionHelper.assertion('_assertion_retrieval', recipient: ACS),
      @sp1_key,
      data_id: 'ED_retrieval',
      key_id: 'EK_retrieval',
      recipient: ACS
    )

    response = response_for(encrypted)

    assert response.decrypted_document
    assert_equal 'alice@example.com', response.nameid
    assert response.is_valid?
  end

  def test_default_key_info_namespace_key_is_accepted_for_adfs_style_responses
    encrypted = EncryptedAssertionHelper.encrypted_assertion_with_default_key_info_namespace(
      EncryptedAssertionHelper.assertion('_assertion_adfs', recipient: ACS),
      @sp1_key,
      data_id: 'ED_adfs',
      key_id: 'EK_adfs',
      recipient: ACS
    )

    response = response_for(encrypted)

    assert response.decrypted_document
    assert_equal 'alice@example.com', response.nameid
    assert response.is_valid?
  end

  private

  def decoy_encrypted_data(id)
    <<~XML
      <xenc:EncryptedData xmlns:xenc="#{EncryptedAssertionHelper::XENC}" Id="#{id}" Type="#{EncryptedAssertionHelper::XENC}Element">
        <xenc:EncryptionMethod Algorithm="#{EncryptedAssertionHelper::XENC}aes128-cbc"/>
        <xenc:CipherData><xenc:CipherValue>AAAAAAAAAAAAAAAAAAAAAA==</xenc:CipherValue></xenc:CipherData>
      </xenc:EncryptedData>
    XML
  end
end
