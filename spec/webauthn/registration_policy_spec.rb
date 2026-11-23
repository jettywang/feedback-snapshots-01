# frozen_string_literal: true

require "spec_helper"
require "support/seeds"
require "webauthn/fake_client"
require "webauthn/relying_party"

RSpec.describe WebAuthn::RegistrationPolicy do
  # The local TPM fixture has an ES256 credential public key and an RS1
  # attestation statement signed by a certificate chain rooted in the
  # Microsoft TPM root certificate.
  let(:tpm_seed) { seeds[:tpm] }
  let(:tpm_origin) { tpm_seed[:origin] }
  let(:tpm_challenge) do
    WebAuthn::Encoders::Base64UrlEncoder.encode(
      WebAuthn::Encoders::Base64UrlEncoder.decode(tpm_seed[:credential_creation_options][:challenge])
    )
  end
  let(:tpm_raw_credential) do
    response = tpm_seed[:authenticator_attestation_response]
    decoder = WebAuthn::Encoders::Base64UrlEncoder

    attestation_object = decoder.decode(response[:attestation_object])
    client_data_json = decoder.decode(response[:client_data_json])
    credential_id =
      WebAuthn::AuthenticatorData
        .deserialize(CBOR.decode(attestation_object)["authData"])
        .attested_credential_data
        .id

    {
      "type" => "public-key",
      "id" => WebAuthn::standard_encoder.encode(credential_id),
      "rawId" => WebAuthn::standard_encoder.encode(credential_id),
      "response" => {
        "attestationObject" => WebAuthn::Encoders::Base64UrlEncoder.encode(attestation_object),
        "clientDataJSON" => WebAuthn::Encoders::Base64UrlEncoder.encode(client_data_json)
      }
    }
  end
  let(:tpm_root_finder) { finder_for("microsoft_tpm_root_certificate_authority_2014.cer") }

  def relying_party(policy:, finder: tpm_root_finder, **options)
    WebAuthn::RelyingParty.new(
      allowed_origins: [tpm_origin],
      attestation_root_certificates_finders: finder,
      acceptable_attestation_types: ["AttCA"],
      registration_policy: policy,
      **options
    )
  end

  describe "independently constraining the two pieces of evidence" do
    let(:policy) do
      described_class.new(
        credential_algorithms: ["ES256"],
        attestation_algorithms: ["RS1"]
      )
    end
    let(:rp) { relying_party(policy: policy) }

    it "approves a registration whose credential key and attestation signatures each match their own policy" do
      result = rp.evaluate_registration(tpm_raw_credential, tpm_challenge)

      expect(result).to be_persistable
      expect(result.credential_algorithm).to eq("ES256")
      expect(result.attestation_algorithm).to eq("RS1")
      expect(result.rejection_reasons).to be_empty
    end

    it "records that the attestation was backed by a validated certificate trust path" do
      expect(tpm_root_finder).to receive(:find).at_least(:once).and_call_original

      result = rp.evaluate_registration(tpm_raw_credential, tpm_challenge)

      expect(result.attestation_source).to eq(:trust_path)
      expect(result.trust_path_checked?).to be(true)
      expect(result.attestation_trust_path).to all(be_kind_of(OpenSSL::X509::Certificate))
      expect(result.attestation_type).to eq("AttCA")
    end

    it "keeps the two approvals and their reasons independent in one result" do
      result = rp.evaluate_registration(tpm_raw_credential, tpm_challenge)

      expect(result.credential_evidence.reason).to eq(:credential_algorithm_allowed)
      expect(result.attestation_evidence.reason).to eq(:attestation_algorithm_allowed)
      expect(result.credential_evidence.kind).to eq(:credential)
      expect(result.attestation_evidence.kind).to eq(:attestation)
      expect(result.attestation_evidence.verified).to be(true)
    end

    it "returns a credential only through the approved result" do
      result = rp.evaluate_registration(tpm_raw_credential, tpm_challenge)

      expect(result.id).to be_a(String)
      expect(result.public_key).to be_a(String)
      expect(result.sign_count).to eq(0)
    end

    it "verifies the registration through the policy-aware entry point" do
      result = rp.verify_registration(tpm_raw_credential, tpm_challenge)

      expect(result).to be_truthy
      expect(result.public_key).to be_truthy
    end
  end

  describe "rejecting when only the other piece of evidence is allowed" do
    context "when the credential algorithm matches but the attestation algorithm does not" do
      let(:policy) do
        described_class.new(
          credential_algorithms: ["ES256"],
          attestation_algorithms: ["ES256"]
        )
      end
      let(:rp) { relying_party(policy: policy) }

      it "does not consider the shared success to approve both pieces" do
        result = rp.evaluate_registration(tpm_raw_credential, tpm_challenge)

        expect(result.credential_evidence).to be_approved
        expect(result.attestation_evidence).not_to be_approved
        expect(result).not_to be_persistable
        expect(result.rejection_reasons).to eq([:attestation_algorithm_not_allowed])
      end

      it "raises a classified rejection carrying the result" do
        expect {
          rp.verify_registration(tpm_raw_credential, tpm_challenge)
        }.to raise_error(WebAuthn::RegistrationPolicy::RejectedError) do |error|
          expect(error.result).not_to be_persistable
          expect(error.result.rejection_reasons).to eq([:attestation_algorithm_not_allowed])
        end
      end
    end

    context "when the attestation algorithm matches but the credential algorithm does not" do
      let(:policy) do
        described_class.new(
          credential_algorithms: ["RS1"],
          attestation_algorithms: ["RS1"]
        )
      end
      let(:rp) { relying_party(policy: policy) }

      it "rejects only the credential evidence" do
        result = rp.evaluate_registration(tpm_raw_credential, tpm_challenge)

        expect(result.credential_evidence).not_to be_approved
        expect(result.attestation_evidence).to be_approved
        expect(result).not_to be_persistable
        expect(result.rejection_reasons).to eq([:credential_algorithm_not_allowed])
      end
    end

    context "when the attestation trust path cannot be validated" do
      let(:policy) do
        described_class.new(
          credential_algorithms: ["ES256"],
          attestation_algorithms: ["RS1"]
        )
      end
      let(:rp) { relying_party(policy: policy, finder: finder_for("yubico_u2f_root.pem")) }

      it "classifies the attestation as unverifiable and does not approve it" do
        result = rp.evaluate_registration(tpm_raw_credential, tpm_challenge)

        expect(result.credential_evidence).to be_approved
        expect(result.attestation_evidence).not_to be_approved
        expect(result.attestation_evidence.reason).to eq(:attestation_unverifiable)
        expect(result).not_to be_persistable
      end
    end
  end

  describe "self-attested provenance" do
    let(:self_seed) { seeds[:security_key_packed_self] }
    let(:self_origin) { "https://localhost:13010" }
    let(:self_challenge) do
      WebAuthn::Encoders::Base64UrlEncoder.encode(
        WebAuthn::Encoders::Base64Encoder.decode(self_seed[:credential_creation_options][:challenge])
      )
    end
    let(:self_raw_credential) do
      response = self_seed[:authenticator_attestation_response]
      decoder = WebAuthn::Encoders::Base64Encoder
      attestation_object = decoder.decode(response[:attestation_object])
      client_data_json = decoder.decode(response[:client_data_json])
      credential_id =
        WebAuthn::AuthenticatorData
          .deserialize(CBOR.decode(attestation_object)["authData"])
          .attested_credential_data
          .id

      {
        "type" => "public-key",
        "id" => WebAuthn::standard_encoder.encode(credential_id),
        "rawId" => WebAuthn::standard_encoder.encode(credential_id),
        "response" => {
          "attestationObject" => WebAuthn::Encoders::Base64UrlEncoder.encode(attestation_object),
          "clientDataJSON" => WebAuthn::Encoders::Base64UrlEncoder.encode(client_data_json)
        }
      }
    end
    let(:self_rp) do
      WebAuthn::RelyingParty.new(
        allowed_origins: [self_origin],
        registration_policy: described_class.new(
          credential_algorithms: ["ES256"],
          attestation_algorithms: ["ES256"]
        )
      )
    end

    it "approves self attestation using the attestation algorithm, without a trust path" do
      finder = finder_for("feitian_ft_fido_0200.pem")
      rp = WebAuthn::RelyingParty.new(
        allowed_origins: [self_origin],
        attestation_root_certificates_finders: finder,
        registration_policy: described_class.new(
          credential_algorithms: ["ES256"],
          attestation_algorithms: ["ES256"]
        )
      )

      expect(finder).not_to receive(:find)

      result = rp.evaluate_registration(self_raw_credential, self_challenge)

      expect(result).to be_persistable
      expect(result.attestation_source).to eq(:self_attestation)
      expect(result.attestation_type).to eq("Self")
      expect(result.attestation_algorithm).to eq("ES256")
      expect(result.attestation_trust_path).to be_nil
      expect(result.trust_path_checked?).to be(false)
    end
  end

  describe "an entry point that explicitly allows no external attestation" do
    let(:challenge) { SecureRandom.random_bytes(32) }
    let(:raw_credential) do
      WebAuthn::FakeClient.new("http://localhost").create(
        challenge: WebAuthn::standard_encoder.encode(challenge)
      )
    end
    let(:open_policy) do
      described_class.allowing_no_attestation(credential_algorithms: ["ES256"])
    end
    let(:strict_policy) do
      described_class.new(credential_algorithms: ["ES256"], attestation_algorithms: ["ES256"])
    end
    let(:open_rp) do
      WebAuthn::RelyingParty.new(allowed_origins: ["http://localhost"], registration_policy: open_policy)
    end
    let(:strict_rp) do
      WebAuthn::RelyingParty.new(allowed_origins: ["http://localhost"], registration_policy: strict_policy)
    end

    it "accepts the none attestation when no proof is requested" do
      finder = finder_for("feitian_ft_fido_0200.pem")
      rp = WebAuthn::RelyingParty.new(
        allowed_origins: ["http://localhost"],
        attestation_root_certificates_finders: finder,
        registration_policy: open_policy
      )

      expect(finder).not_to receive(:find)

      result = rp.evaluate_registration(raw_credential, WebAuthn::standard_encoder.encode(challenge))

      expect(result).to be_persistable
      expect(result.attestation_source).to eq(:none)
      expect(result.attestation_evidence.reason).to eq(:attestation_not_required)
      expect(result.trust_path_checked?).to be(false)
    end

    it "still rejects a credential whose public key algorithm is not allowed" do
      rp = WebAuthn::RelyingParty.new(
        allowed_origins: ["http://localhost"],
        registration_policy: described_class.allowing_no_attestation(credential_algorithms: ["RS1"])
      )

      result = rp.evaluate_registration(raw_credential, WebAuthn::standard_encoder.encode(challenge))

      expect(result).not_to be_persistable
      expect(result.rejection_reasons).to eq([:credential_algorithm_not_allowed])
    end

    it "classifies a missing proof at an entry point that requires it" do
      finder = finder_for("feitian_ft_fido_0200.pem")
      rp = WebAuthn::RelyingParty.new(
        allowed_origins: ["http://localhost"],
        attestation_root_certificates_finders: finder,
        registration_policy: strict_policy
      )

      expect(finder).not_to receive(:find)

      result = rp.evaluate_registration(raw_credential, WebAuthn::standard_encoder.encode(challenge))

      expect(result).not_to be_persistable
      expect(result.attestation_source).to eq(:none)
      expect(result.attestation_evidence.reason).to eq(:attestation_missing)
      expect(result.rejection_reasons).to eq([:attestation_missing])
    end

    it "keeps the original entry point accepting registrations without attestation" do
      legacy_rp = WebAuthn::RelyingParty.new(allowed_origins: ["http://localhost"])

      credential = legacy_rp.verify_registration(raw_credential, WebAuthn::standard_encoder.encode(challenge))

      expect(credential.public_key).to be_truthy
    end
  end

  describe "evaluating the same response under two different policies" do
    let(:tpm_policy) do
      described_class.new(credential_algorithms: ["ES256"], attestation_algorithms: ["RS1"])
    end
    let(:other_policy) do
      described_class.new(credential_algorithms: ["ES256"], attestation_algorithms: ["ES256"])
    end

    it "does not leak one policy's result into the other" do
      tpm_rp = relying_party(policy: tpm_policy)
      other_rp = relying_party(policy: other_policy)

      first = tpm_rp.evaluate_registration(tpm_raw_credential, tpm_challenge)
      second = other_rp.evaluate_registration(tpm_raw_credential, tpm_challenge)

      expect(first).to be_persistable
      expect(second).not_to be_persistable
      expect(second.rejection_reasons).to eq([:attestation_algorithm_not_allowed])
    end
  end

  describe "the default, policy-less behavior" do
    it "does not change how registration is verified" do
      rp = relying_party(policy: nil)
      credential = rp.verify_registration(tpm_raw_credential, tpm_challenge)

      expect(credential).to be_a(WebAuthn::PublicKeyCredentialWithAttestation)
      expect(credential.response.attestation_type).to eq("AttCA")
    end

    it "rejects an unknown algorithm when constructing a policy" do
      expect {
        described_class.new(credential_algorithms: ["NOPE"])
      }.to raise_error(ArgumentError, /Unknown COSE algorithm/)
    end
  end
end
