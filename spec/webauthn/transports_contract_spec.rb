# frozen_string_literal: true

require "spec_helper"
require "cbor"
require "openssl"

require "webauthn/fake_authenticator"
require "webauthn/fake_authenticator/authenticator_data"
require "webauthn/fake_client"
require "webauthn/relying_party"

RSpec.describe "WebAuthn transports contract" do
  # A FakeClient whose registration responses carry a packed, x5c-backed
  # attestation statement so the relying party can verify a real trust path,
  # while assertion responses are produced exactly like the stock FakeClient.
  class PackedAttestationFakeClient < WebAuthn::FakeClient
    attr_reader :attestation_root_certificate, :attestation_root_key

    def initialize(*)
      super
      @attestation_root_key = create_ec_key
      @attestation_root_certificate = create_root_certificate(attestation_root_key)
    end

    def create(challenge: fake_challenge, rp_id: nil, transports: ["internal"], **options)
      rp_id ||= URI.parse(origin).host

      client_data_json = data_json_for(:create, encoder.decode(challenge))
      client_data_hash = hashed(client_data_json)

      credential_id = SecureRandom.random_bytes(16)
      credential_key = OpenSSL::PKey::EC.generate("prime256v1")
      attestation_key = create_ec_key

      authenticator_data_bytes =
        WebAuthn::FakeAuthenticator::AuthenticatorData.new(
          rp_id_hash: hashed(rp_id),
          credential: { id: credential_id, public_key: credential_key.public_key },
          extensions: nil
        ).serialize

      attestation_certificate =
        issue_certificate(
          attestation_root_certificate,
          attestation_root_key,
          attestation_key,
          version: 2,
          name: "/C=UY/O=ACME/OU=Authenticator Attestation/CN=packed-fake",
          extensions: [
            OpenSSL::X509::ExtensionFactory.new.create_extension("basicConstraints", "CA:FALSE", true)
          ]
        )

      to_be_signed = authenticator_data_bytes + client_data_hash
      attestation_object =
        CBOR.encode(
          "fmt" => "packed",
          "attStmt" => {
            "alg" => -7,
            "sig" => attestation_key.sign("SHA256", to_be_signed),
            "x5c" => [attestation_certificate.to_der]
          },
          "authData" => authenticator_data_bytes
        )

      register_credential(rp_id, credential_id, credential_key)

      {
        "type" => "public-key",
        "id" => internal_encoder.encode(credential_id),
        "rawId" => encoder.encode(credential_id),
        "authenticatorAttachment" => "platform",
        "clientExtensionResults" => nil,
        "response" => {
          "attestationObject" => encoder.encode(attestation_object),
          "clientDataJSON" => encoder.encode(client_data_json),
          "transports" => transports
        }
      }
    end

    private

    def register_credential(rp_id, credential_id, credential_key)
      credentials = authenticator.instance_variable_get(:@credentials)
      credentials[rp_id] ||= {}
      credentials[rp_id][credential_id] = { credential_key: credential_key, sign_count: 1 }
    end
  end

  # Application-side persisted record. `transports` are only client hints;
  # `attestation_trust_path` is the verified hardware evidence.
  let(:credential_record) do
    Struct.new(
      :webauthn_id,
      :public_key,
      :sign_count,
      :transports,
      :attestation_trust_path,
      :attestation_type,
      :version,
      keyword_init: true
    )
  end

  # Correct application policy: hardware admission is granted only when a
  # verified attestation trust path was configured for the record.
  class TrustPathDevicePolicy
    def self.hardware_admitted?(record)
      Array(record.attestation_trust_path).any?
    end
  end

  # Application policy double for the configured attestation root certificates.
  class RootCertificateFinderDouble
    def initialize(root_certificate)
      @root_certificate = root_certificate
    end

    def find(*)
      [@root_certificate]
    end
  end

  # Deliberately broken policy double: it grants hardware admission from the
  # transports hint alone. The contract suite must expose this as a violation.
  class HintOnlyDevicePolicy
    def self.hardware_admitted?(record)
      Array(record.transports).any?
    end
  end

  let(:rp_id) { "device.example.test" }
  let(:origin) { "https://#{rp_id}" }

  let(:fake_client) { PackedAttestationFakeClient.new(origin) }
  let(:relying_party) do
    WebAuthn::RelyingParty.new(
      allowed_origins: [origin],
      id: rp_id,
      name: "Device Admission",
      attestation_root_certificates_finders: [finder_double]
    )
  end
  let(:finder_double) { RootCertificateFinderDouble.new(fake_client.attestation_root_certificate) }

  let(:shared_hint) { ["internal"] }
  let(:updated_hint) { ["hybrid", "internal"] }

  def register_verified_record(transports:)
    options = relying_party.options_for_registration(
      user: { id: WebAuthn.generate_user_id, name: "verified-user" }
    )
    raw_credential = fake_client.create(challenge: options.challenge, rp_id: rp_id, transports: transports)
    webauthn_credential = relying_party.verify_registration(raw_credential, options.challenge)

    credential_record.new(
      webauthn_id: webauthn_credential.id,
      public_key: webauthn_credential.public_key,
      sign_count: webauthn_credential.sign_count,
      transports: webauthn_credential.response.transports,
      attestation_trust_path: webauthn_credential.response.attestation_trust_path,
      attestation_type: webauthn_credential.response.attestation_type,
      version: 1
    )
  end

  def build_legacy_record(transports:)
    credential_id, public_key, sign_count = create_credential(client: fake_client, relying_party: relying_party)

    credential_record.new(
      webauthn_id: credential_id,
      public_key: relying_party.encoder.encode(public_key),
      sign_count: sign_count,
      transports: transports,
      attestation_trust_path: nil,
      attestation_type: nil,
      version: 1
    )
  end

  describe "registration persistence" do
    it "stores transports only as hints while the trust path is the hardware evidence" do
      record = register_verified_record(transports: shared_hint)

      expect(record.transports).to eq(shared_hint)
      expect(record.attestation_type).to eq("Basic_or_AttCA")
      expect(record.attestation_trust_path).to all(be_kind_of(OpenSSL::X509::Certificate))
    end

    it "keeps a verifiable registration hint-only when no attestation trust path is configured" do
      options = relying_party.options_for_registration(
        user: { id: WebAuthn.generate_user_id, name: "hint-only-user" }
      )
      raw_credential = fake_client.create(challenge: options.challenge, rp_id: rp_id, transports: shared_hint)

      unverified_rp =
        WebAuthn::RelyingParty.new(
          allowed_origins: [origin],
          id: rp_id,
          name: "No Trust Path",
          verify_attestation_statement: false
        )
      webauthn_credential = unverified_rp.verify_registration(raw_credential, options.challenge)

      record =
        credential_record.new(
          webauthn_id: webauthn_credential.id,
          public_key: webauthn_credential.public_key,
          sign_count: webauthn_credential.sign_count,
          transports: webauthn_credential.response.transports,
          attestation_trust_path: nil,
          attestation_type: nil,
          version: 1
        )

      expect(webauthn_credential).to be_truthy
      expect(record.transports).to eq(shared_hint)
      expect(TrustPathDevicePolicy.hardware_admitted?(record)).to be(false)
      expect(HintOnlyDevicePolicy.hardware_admitted?(record)).to be(true)
    end

    it "preserves legacy records that only saved hints without hardware attestation" do
      legacy_record = build_legacy_record(transports: shared_hint)

      expect(legacy_record.transports).to eq(shared_hint)
      expect(legacy_record.attestation_trust_path).to be_nil
      expect(TrustPathDevicePolicy.hardware_admitted?(legacy_record)).to be(false)
    end
  end

  describe "request option generation" do
    let!(:verified_record) { register_verified_record(transports: shared_hint) }
    let!(:legacy_record) { build_legacy_record(transports: shared_hint) }

    it "renders the stored transports as client hints inside allowCredentials" do
      options = relying_party.options_for_authentication(
        allow_credentials: [
          { type: "public-key", id: verified_record.webauthn_id, transports: verified_record.transports },
          { type: "public-key", id: legacy_record.webauthn_id, transports: legacy_record.transports }
        ]
      )

      expect(options.as_json[:allowCredentials]).to contain_exactly(
        { type: "public-key", id: verified_record.webauthn_id, transports: shared_hint },
        { type: "public-key", id: legacy_record.webauthn_id, transports: shared_hint }
      )
    end

    it "reflects a hint update in client options without touching the verified trust path" do
      verified_record.transports = updated_hint
      verified_record.version = 2

      options = relying_party.options_for_authentication(
        allow_credentials: [
          { type: "public-key", id: verified_record.webauthn_id, transports: verified_record.transports }
        ]
      )

      expect(options.as_json[:allowCredentials]).to eq(
        [{ type: "public-key", id: verified_record.webauthn_id, transports: updated_hint }]
      )
      expect(verified_record.attestation_trust_path).to all(be_kind_of(OpenSSL::X509::Certificate))
      expect(verified_record.version).to eq(2)
    end
  end

  describe "post-verification authorization" do
    let!(:verified_record) { register_verified_record(transports: shared_hint) }
    let!(:legacy_record) { build_legacy_record(transports: shared_hint) }

    before do
      verified_record.transports = updated_hint
      verified_record.version = 2
    end

    it "admits only the record backed by a configured attestation trust path" do
      expect(TrustPathDevicePolicy.hardware_admitted?(verified_record)).to be(true)
      expect(TrustPathDevicePolicy.hardware_admitted?(legacy_record)).to be(false)
    end

    it "still completes ordinary passwordless authentication after the hint update" do
      options = relying_party.options_for_authentication(allow: [verified_record.webauthn_id])
      raw_credential = fake_client.get(challenge: options.challenge, rp_id: rp_id, sign_count: 1)

      verified_credential, stored_record =
        relying_party.verify_authentication(raw_credential, options.challenge) do |webauthn_credential|
          [verified_record, legacy_record].find { |record| record.webauthn_id == webauthn_credential.id }
        end

      expect(verified_credential.id).to eq(verified_record.webauthn_id)
      expect(stored_record).to eq(verified_record)
      expect(stored_record.transports).to eq(updated_hint)
      expect(stored_record.version).to eq(2)
    end

    it "detects a policy double that authorizes hardware from transports hints alone" do
      results =
        [verified_record, legacy_record].map do |record|
          HintOnlyDevicePolicy.hardware_admitted?(record)
        end

      expect(results).to eq([true, true])
      expect(HintOnlyDevicePolicy.hardware_admitted?(legacy_record)).to be(true)
      expect(TrustPathDevicePolicy.hardware_admitted?(legacy_record)).to be(false)
    end
  end
end
