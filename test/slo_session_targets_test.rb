require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

require 'base64'
require 'cgi'
require 'zlib'

require 'onelogin/ruby-saml/logoutrequest'
require 'onelogin/ruby-saml/slo_logoutrequest'
require 'onelogin/ruby-saml/utils'

class SloSessionTargetsTest < Minitest::Test
  # Stands in for the application's session store. It is only asked to
  # delete after the caller has successfully parsed and validated a request.
  class RecordingSessionStore
    attr_reader :deletions

    def initialize
      @deletions = []
    end

    def delete(principal, session_indexes)
      @deletions << {
        :issuer => principal.fetch(:issuer),
        :name_id => principal.fetch(:name_id),
        :name_qualifier => principal.fetch(:name_qualifier),
        :sp_name_qualifier => principal.fetch(:sp_name_qualifier),
        :session_indexes => session_indexes
      }
    end
  end

  # A deliberately small backend boundary. It refuses to resolve targets
  # unless the request has passed validation, and it passes through the
  # complete, raw SessionIndex set. There is no fallback from "no index"
  # to "all sessions", and empty/duplicate indexes are not normalized.
  class SloSessionResolver
    def self.targets(logout_request)
      raise ArgumentError, "logout request must be validated first" unless logout_request.is_valid?

      {
        :issuer => logout_request.issuer,
        :name_id => logout_request.name_id,
        :name_qualifier => logout_request.name_id_namequalifier,
        :sp_name_qualifier => logout_request.name_id_spnamequalifier,
        :session_indexes => logout_request.session_indexes.empty? ? nil : logout_request.session_indexes.dup
      }
    end
  end

  IdP = Struct.new(:entity_id, :name_qualifier, :key, :certificate) do
    def settings
      OneLogin::RubySaml::Settings.new(
        :idp_entity_id => entity_id,
        :idp_name_qualifier => name_qualifier,
        :idp_slo_service_url => "#{entity_id}/slo",
        :idp_cert => certificate.to_pem,
        :security => {
          :signature_method => XMLSecurity::Document::RSA_SHA256
        }
      )
    end
  end

  SP_ENTITY_ID = "https://sp.example.com/metadata"
  SHARED_NAME_ID = "shared-user@example.org"

  def setup
    @idp_a = build_idp("https://idp-a.example.com/metadata", "https://idp-a.example.com/names")
    @idp_b = build_idp("https://idp-b.example.com/metadata", "https://idp-b.example.com/names")
    @store = RecordingSessionStore.new
  end

  # Headline case: the same NameID text and the same SessionIndex value can
  # exist at two IdPs. Each request must reach only its own principal and only
  # the exact index set named in that request.
  def test_two_idps_same_name_id_and_shared_index_do_not_cross_delete
    shared_index = index("shared")
    targets_a = resolve(signed_request(@idp_a, [shared_index]))
    targets_b = resolve(signed_request(@idp_b, [shared_index]))

    deliver(targets_a)
    deliver(targets_b)

    assert_equal 2, @store.deletions.length
    assert_equal [shared_index], @store.deletions[0][:session_indexes]
    assert_equal [shared_index], @store.deletions[1][:session_indexes]
    assert_equal @idp_a.entity_id, @store.deletions[0][:issuer]
    assert_equal @idp_b.entity_id, @store.deletions[1][:issuer]
    assert_equal SHARED_NAME_ID, @store.deletions[0][:name_id]
    assert_equal SHARED_NAME_ID, @store.deletions[1][:name_id]
    assert_equal @idp_a.name_qualifier, @store.deletions[0][:name_qualifier]
    assert_equal @idp_b.name_qualifier, @store.deletions[1][:name_qualifier]
  end

  # A single signed request with multiple indexes must deliver all of them,
  # in source order, without dropping the tail after the first index.
  def test_multiple_indexes_are_all_delivered_once_each
    indexes = [index("a-1"), index("a-2"), index("a-3")]
    targets = resolve(signed_request(@idp_a, indexes))

    assert_equal indexes, targets[:session_indexes]
    refute_nil targets[:session_indexes]
    refute_empty targets[:session_indexes]

    deliver(targets)

    assert_equal 1, @store.deletions.length
    assert_equal indexes, @store.deletions[0][:session_indexes]
    assert_equal @idp_a.entity_id, @store.deletions[0][:issuer]
    assert_equal SHARED_NAME_ID, @store.deletions[0][:name_id]
  end

  # A request from IdP A that claims IdP B's issuer must not be accepted
  # even though both IdPs use the exact same NameID text.
  def test_request_with_another_idp_issuer_is_rejected_before_deletion
    request = signed_request(@idp_a, [index("a-1")])
    request.settings.idp_entity_id = @idp_b.entity_id

    refute request.is_valid?
    assert_includes request.errors, "Doesn't match the issuer, expected: <#{@idp_b.entity_id}>, but was: <#{@idp_a.entity_id}>"

    deliver(resolve_validated(request, expected: false))
    assert_empty @store.deletions
  end

  # Same NameID text, two IdPs, and different index sets: neither request
  # inherits or widens the other IdP's sessions.
  def test_same_name_id_with_different_indexes_stays_per_idp
    targets_a = resolve(signed_request(@idp_a, [index("a-1"), index("a-2")]))
    targets_b = resolve(signed_request(@idp_b, [index("b-9")]))

    assert_equal SHARED_NAME_ID, targets_a[:name_id]
    assert_equal SHARED_NAME_ID, targets_b[:name_id]
    assert_equal [index("a-1"), index("a-2")], targets_a[:session_indexes]
    assert_equal [index("b-9")], targets_b[:session_indexes]

    deliver(targets_a)
    deliver(targets_b)

    assert_equal 2, @store.deletions.length
    assert_equal [index("a-1"), index("a-2")], @store.deletions[0][:session_indexes]
    assert_equal [index("b-9")], @store.deletions[1][:session_indexes]
    assert_equal @idp_a.entity_id, @store.deletions[0][:issuer]
    assert_equal @idp_b.entity_id, @store.deletions[1][:issuer]
    assert_equal @idp_a.name_qualifier, @store.deletions[0][:name_qualifier]
    assert_equal @idp_b.name_qualifier, @store.deletions[1][:name_qualifier]
  end

  # No SessionIndex is distinct from an explicitly empty SessionIndex.
  # Neither is turned into a wildcard set.
  def test_missing_index_is_nil_and_not_an_empty_or_wildcard_set
    targets = resolve(signed_request(@idp_a, []))

    assert_nil targets[:session_indexes]

    deliver(targets)

    assert_equal 1, @store.deletions.length
    assert_nil @store.deletions[0][:session_indexes]
    assert_equal @idp_a.entity_id, @store.deletions[0][:issuer]
    assert_equal SHARED_NAME_ID, @store.deletions[0][:name_id]
  end

  def test_empty_index_is_preserved_and_is_not_missing
    targets = resolve(signed_request(@idp_a, [""]))

    assert_equal [""], targets[:session_indexes]
    refute_nil targets[:session_indexes]

    deliver(targets)

    assert_equal 1, @store.deletions.length
    assert_equal [""], @store.deletions[0][:session_indexes]
  end

  def test_duplicate_indexes_are_preserved_not_collapsed
    duplicate = index("a-1")
    targets = resolve(signed_request(@idp_a, [duplicate, duplicate]))

    assert_equal [duplicate, duplicate], targets[:session_indexes]

    deliver(targets)

    assert_equal 1, @store.deletions.length
    assert_equal [duplicate, duplicate], @store.deletions[0][:session_indexes]
  end

  def test_sp_name_qualifier_mismatch_does_not_trigger_deletion
    request = signed_request(@idp_a, [index("a-1")], :sp_name_qualifier => "https://other-sp.example.com/metadata")

    refute request.is_valid?
    assert_includes request.errors, "SPNameQualifier value does not match the SP entityID value."

    deliver(resolve_validated(request, expected: false))
    assert_empty @store.deletions
  end

  def test_idp_name_qualifier_mismatch_does_not_trigger_deletion
    request = signed_request(@idp_a, [index("a-1")], :name_qualifier => @idp_b.name_qualifier)
    # The verifying SP trusts IdP A, whose expected qualifier differs from
    # the claimed IdP B qualifier carried in this request.
    request.settings.idp_name_qualifier = @idp_a.name_qualifier

    refute request.is_valid?
    assert_includes request.errors, "NameQualifier value does not match the IdP name qualifier value."

    deliver(resolve_validated(request, expected: false))
    assert_empty @store.deletions
  end

  # Changing the serialized request after it was signed must invalidate the
  # redirect signature, even if a different valid index is substituted.
  def test_index_tampered_after_signing_does_not_trigger_deletion
    valid_request = signed_request(@idp_a, [index("a-1")])
    tampered = tampered_request(valid_request, index("a-2"))

    refute tampered.is_valid?
    assert_includes tampered.errors, "Invalid Signature on Logout Request"

    deliver(resolve_validated(tampered, expected: false))
    assert_empty @store.deletions
  end

  def test_forged_signature_does_not_trigger_deletion
    request = signed_request(@idp_a, [index("a-1")])
    request.options[:get_params]["Signature"] = Base64.strict_encode64("forged")

    refute request.is_valid?
    assert_includes request.errors, "Invalid Signature on Logout Request"

    deliver(resolve_validated(request, expected: false))
    assert_empty @store.deletions
  end

  private

  def build_idp(entity_id, name_qualifier)
    certificate, key = CertificateHelper.generate_pair
    IdP.new(entity_id, name_qualifier, key, certificate)
  end

  def index(value)
    "_#{value}"
  end

  def signed_request(idp, session_indexes, name_qualifier: idp.name_qualifier, sp_name_qualifier: SP_ENTITY_ID)
    settings = request_settings(idp, name_qualifier, sp_name_qualifier)
    logout_request = OneLogin::RubySaml::Logoutrequest.new
    xml = logout_request.create_xml_document(settings)
    xml.root.delete_element("samlp:SessionIndex") while xml.root.elements["samlp:SessionIndex"]
    session_indexes.each do |session_index|
      node = REXML::Element.new("samlp:SessionIndex")
      node.text = session_index
      xml.root.add_element(node)
    end

    encoded = encode_request(xml.to_s, settings.compress_request)
    params = redirect_params(encoded, settings.security[:signature_method], idp.key)
    # The XML is already built, so now switch the settings to the SP view
    # used by the verifying application for qualifier checks.
    settings.sp_entity_id = SP_ENTITY_ID
    options = {
      :settings => settings,
      :get_params => params,
      :raw_get_params => {
        "SAMLRequest" => CGI.escape(params["SAMLRequest"]),
        "SigAlg" => CGI.escape(params["SigAlg"])
      }
    }
    OneLogin::RubySaml::SloLogoutrequest.new(params["SAMLRequest"], options)
  end

  def request_settings(idp, name_qualifier, sp_name_qualifier)
    settings = idp.settings
    settings.compress_request = true
    settings.name_identifier_value = SHARED_NAME_ID
    # Logoutrequest writes Issuer from sp_entity_id; for an IdP-initiated
    # request the trusted signer's entity ID must appear there instead.
    settings.issuer = idp.entity_id
    settings.idp_name_qualifier = name_qualifier
    settings.sp_name_qualifier = sp_name_qualifier
    settings.certificate = idp.certificate.to_pem
    settings.private_key = idp.key.to_pem
    settings.security[:logout_requests_signed] = true
    settings.idp_slo_service_binding = :redirect
    settings
  end

  def redirect_params(encoded_request, sig_alg, idp_key)
    params = {
      "SAMLRequest" => encoded_request,
      "SigAlg" => sig_alg
    }
    query_string = OneLogin::RubySaml::Utils.build_query(
      :type => "SAMLRequest",
      :data => encoded_request,
      :sig_alg => sig_alg
    )
    algorithm = XMLSecurity::BaseDocument.new.algorithm(sig_alg)
    params["Signature"] = Base64.strict_encode64(idp_key.sign(algorithm.new, query_string))
    params
  end

  def encode_request(xml, compress)
    xml = Zlib::Deflate.deflate(xml, 9)[2..-5] if compress
    Base64.strict_encode64(xml)
  end

  def decode_request(encoded_request, compressed)
    raw = Base64.decode64(encoded_request)
    compressed ? Zlib::Inflate.new(-Zlib::MAX_WBITS).inflate(raw) : raw
  end

  def tampered_request(valid_request, replacement_index)
    params = valid_request.options[:get_params].dup
    xml = decode_request(params["SAMLRequest"], true)
    document = REXML::Document.new(xml)
    document.root.elements["samlp:SessionIndex"].text = replacement_index

    tampered_encoded = encode_request(document.to_s, true)
    tampered_params = params.merge("SAMLRequest" => tampered_encoded)
    options = {
      :settings => valid_request.settings,
      :get_params => tampered_params,
      :raw_get_params => {
        "SAMLRequest" => CGI.escape(tampered_encoded),
        "SigAlg" => CGI.escape(tampered_params["SigAlg"])
      }
    }
    OneLogin::RubySaml::SloLogoutrequest.new(tampered_encoded, options)
  end

  def resolve(request)
    request.settings.sp_entity_id = SP_ENTITY_ID

    assert request.is_valid?
    assert_empty request.errors
    SloSessionResolver.targets(request)
  end

  # Runs the same delivery boundary even when validation is expected to fail.
  # Returning no targets is what prevents a rejected request from deleting.
  def resolve_validated(request, expected:)
    request.settings.sp_entity_id = SP_ENTITY_ID

    assert_equal expected, request.is_valid?
    assert_empty request.errors if expected

    unless expected
      assert_raises(ArgumentError) { SloSessionResolver.targets(request) }
      return []
    end

    SloSessionResolver.targets(request)
  end

  def deliver(target)
    targets = target.is_a?(Array) ? target : [target]
    targets.each do |session_target|
      next if session_target.nil?

      principal = {
        :issuer => session_target[:issuer],
        :name_id => session_target[:name_id],
        :name_qualifier => session_target[:name_qualifier],
        :sp_name_qualifier => session_target[:sp_name_qualifier]
      }
      @store.delete(principal, session_target[:session_indexes])
    end
  end
end
