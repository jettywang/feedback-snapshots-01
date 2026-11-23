# frozen_string_literal: true

require "spec_helper"
require "webauthn/credential_operation"
require "webauthn/fake_authenticator"
require "webauthn/fake_client"
require "webauthn/relying_party"

RSpec.describe WebAuthn::CredentialOperation do
  let(:authenticator) { WebAuthn::FakeAuthenticator.new }
  let(:admin_origin) { "https://admin.example.test" }
  let(:consumer_origin) { "https://www.example.test" }

  let(:admin_rp) do
    WebAuthn::RelyingParty.new(
      allowed_origins: [admin_origin],
      id: "admin.example.test",
      name: "Admin"
    )
  end

  let(:consumer_rp) do
    WebAuthn::RelyingParty.new(
      allowed_origins: [consumer_origin],
      id: "example.test",
      name: "Consumer"
    )
  end

  let(:admin_client) { WebAuthn::FakeClient.new(admin_origin, authenticator: authenticator) }
  let(:consumer_client) { WebAuthn::FakeClient.new(consumer_origin, authenticator: authenticator) }

  describe ".for_registration" do
    it "issues options with the relying party configuration at issuance" do
      operation = admin_rp.registration_operation(user: { id: "user-1", name: "User" })

      expect(operation).to be_registration
      expect(operation.options.rp.id).to eq("admin.example.test")
      expect(operation.options.rp.name).to eq("Admin")
      expect(operation.challenge).to be_truthy
      expect(operation.options.challenge).to eq(operation.challenge)
      expect(operation.configuration_snapshot.fingerprint).to match(/\A[0-9a-f]{64}\z/)
    end

    it "lets options build their own issuance-bound operation" do
      options = admin_rp.options_for_registration(user: { id: "user-1", name: "User" })
      raw_credential = admin_client.create(challenge: options.challenge, rp_id: admin_rp.id)

      admin_rp.allowed_origins = ["https://changed.example.test"]

      expect(options.operation).to be_registration
      expect(options.operation.compatibility_with(admin_rp)).to be_stop
      expect(options.operation.verify_registration(raw_credential).id).to be_truthy
    end

    it "keeps the issued challenge stable" do
      operation = admin_rp.registration_operation(user: { id: "user-1", name: "User" })
      restored = described_class.from_json(operation.to_json)

      expect(operation.challenge).to eq(operation.options.challenge)
      expect(restored.challenge).to eq(operation.challenge)
      expect(restored.to_json).to include(WebAuthn.standard_encoder.encode(operation.raw_challenge))
    end
  end

  describe "serialization" do
    it "round-trips the operation and preserves the challenge and configuration" do
      operation = admin_rp.registration_operation(
        user: { id: "user-1", name: "User" },
        request_id: "req-1"
      )

      restored = described_class.from_json(operation.to_json)

      expect(restored.kind).to eq(:registration)
      expect(restored.request_id).to eq("req-1")
      expect(restored.challenge).to eq(operation.challenge)
      expect(restored.fingerprint).to eq(operation.fingerprint)
      expect(restored.configuration_snapshot.fingerprint).to eq(operation.configuration_snapshot.fingerprint)
      expect(restored.options.rp.id).to eq("admin.example.test")
    end

    it "round-trips registration and authentication option payloads" do
      registration = described_class.for_registration(
        relying_party: admin_rp,
        user: { id: "user-1", name: "User" },
        exclude: ["credential-1"]
      )
      restored_registration = described_class.from_h(registration.to_h)
      expect(restored_registration.options.as_json[:excludeCredentials])
        .to eq([{ type: "public-key", id: "credential-1" }])

      authentication = described_class.for_authentication(
        relying_party: admin_rp,
        allow: ["credential-1"],
        user_verification: "required"
      )
      restored_authentication = described_class.from_h(authentication.to_h)
      expect(restored_authentication.options.as_json[:allowCredentials])
        .to eq([{ type: "public-key", id: "credential-1" }])
      expect(restored_authentication.options.as_json[:userVerification]).to eq("required")
    end

    it "rejects a tampered challenge" do
      operation = admin_rp.registration_operation(user: { id: "user-1", name: "User" })
      hash = operation.to_h
      hash["challenge_raw"] = WebAuthn.standard_encoder.encode(SecureRandom.random_bytes(32))

      expect { described_class.from_h(hash) }
        .to raise_error(WebAuthn::ConfigurationSnapshot::FingerprintMismatchError)
    end

    it "verifies a callback in a fresh process-like instance" do
      operation = admin_rp.registration_operation(user: { id: "user-1", name: "User" })
      raw_credential = admin_client.create(challenge: operation.challenge, rp_id: admin_rp.id)
      restored = described_class.from_json(operation.to_json)

      credential = restored.verify_registration(raw_credential)

      expect(credential.id).to be_truthy
      expect(credential.sign_count).to eq(0)
    end
  end

  describe "#verify_registration" do
    it "uses the issuance-time configuration after the live relying party changes" do
      operation = admin_rp.registration_operation(user: { id: "user-1", name: "User" })
      raw_credential = admin_client.create(challenge: operation.challenge, rp_id: admin_rp.id)

      admin_rp.allowed_origins = ["https://changed.example.test"]
      admin_rp.id = "changed.example.test"
      admin_rp.encoding = :base64
      admin_rp.name = "Changed"

      expect { admin_rp.verify_registration(raw_credential, operation.challenge) }
        .to raise_error(StandardError)
      expect(operation.verify_registration(raw_credential).id).to be_truthy
    end

    it "decodes with the issuance-time encoder when the live encoding changes" do
      operation = admin_rp.registration_operation(user: { id: "user-1", name: "User" })
      raw_credential = admin_client.create(challenge: operation.challenge, rp_id: admin_rp.id)

      admin_rp.encoding = :base64

      credential = operation.verify_registration(raw_credential)

      expect(credential.id).to be_truthy
      expect(operation.diagnose(raw_credential)[:encoding]).to eq("base64url")
    end

    it "rejects a credential created for another origin" do
      operation = admin_rp.registration_operation(user: { id: "user-1", name: "User" })
      raw_credential = consumer_client.create(challenge: operation.challenge)

      expect { operation.verify_registration(raw_credential) }
        .to raise_error(WebAuthn::OriginVerificationError)
    end
  end

  describe "#verify_authentication" do
    let(:registration) { admin_rp.registration_operation(user: { id: "user-1", name: "User" }) }
    let(:registered_credential) do
      raw = admin_client.create(challenge: registration.challenge, rp_id: admin_rp.id)
      registration.verify_registration(raw)
    end
    let!(:public_key) { registration.configuration_snapshot.encoder.encode(registered_credential.raw_public_key) }

    it "attributes the credential and user handle through the issuance-time configuration" do
      operation = admin_rp.authentication_operation
      raw_credential = admin_client.get(
        challenge: operation.challenge,
        rp_id: admin_rp.id,
        sign_count: 1,
        user_handle: "user-1"
      )

      credential, stored = operation.verify_authentication(
        raw_credential,
        public_key: public_key,
        sign_count: 0
      ) { |webauthn_credential| { id: webauthn_credential.id } }

      expect(credential.sign_count).to eq(1)
      expect(stored[:id]).to eq(registered_credential.id)
      expect(operation.diagnose(raw_credential)).to include(
        user_handle: "user-1",
        origin_allowed: true,
        rp_id_hash_matches: true
      )
    end

    it "keeps working after the global configuration changes" do
      operation = admin_rp.authentication_operation
      raw_credential = admin_client.get(challenge: operation.challenge, rp_id: admin_rp.id, sign_count: 1)

      WebAuthn.configure do |config|
        config.allowed_origins = ["https://global.example.test"]
        config.rp_id = "global.example.test"
        config.encoding = :base64
      end

      expect(
        operation.verify_authentication(
          raw_credential,
          public_key: public_key,
          sign_count: 0
        ).sign_count
      ).to eq(1)
    end
  end

  describe "#compatibility_with" do
    let!(:operation) { admin_rp.registration_operation(user: { id: "user-1", name: "User" }) }

    it "continues when the configuration did not change" do
      compatible_rp = WebAuthn::RelyingParty.new(
        allowed_origins: [admin_origin],
        id: "admin.example.test",
        name: "Admin renamed"
      )

      compatibility = operation.compatibility_with(compatible_rp)

      expect(compatibility).to be_continue
      expect(compatibility.changed_fields).to be_empty
    end

    it "stops when the origin changes" do
      admin_rp.allowed_origins = ["https://changed.example.test"]

      compatibility = operation.compatibility_with(admin_rp)

      expect(compatibility).to be_stop
      expect(compatibility.changed_fields).to eq([:allowed_origins])
    end

    it "stops when the RP ID changes" do
      admin_rp.id = "changed.example.test"

      expect(operation.compatibility_with(admin_rp).changed_fields).to eq([:rp_id])
    end

    it "stops when the encoding changes" do
      admin_rp.encoding = :base64

      expect(operation.compatibility_with(admin_rp).changed_fields).to eq([:encoding])
    end

    it "stops when a verification requirement changes" do
      admin_rp.verify_attestation_statement = false

      expect(operation.compatibility_with(admin_rp).changed_fields).to eq([:verify_attestation_statement])
    end

    it "stops when the global configuration changes" do
      WebAuthn.configure do |config|
        config.allowed_origins = ["https://global.example.test"]
        config.rp_id = "global.example.test"
      end

      expect(operation.compatibility_with(WebAuthn.configuration.relying_party)).to be_stop
    end
  end

  describe "#verify_registration compatibility enforcement" do
    let!(:operation) { admin_rp.registration_operation(user: { id: "user-1", name: "User" }) }
    let!(:raw_credential) { admin_client.create(challenge: operation.challenge, rp_id: admin_rp.id) }

    before do
      admin_rp.allowed_origins = ["https://changed.example.test"]
    end

    it "stops by default when compared against a changed live configuration" do
      expect { operation.verify_registration(raw_credential, against: admin_rp) }
        .to raise_error(WebAuthn::CredentialOperation::CompatibilityError) { |error|
          expect(error.compatibility.changed_fields).to eq([:allowed_origins])
        }

      expect(operation.verifications).to be_empty
    end

    it "can be explicitly allowed to continue" do
      credential = operation.verify_registration(raw_credential, against: admin_rp, on_change: :continue)

      expect(credential.id).to be_truthy
      expect(operation.last_verification).to be_stop
      expect(operation.last_verification).to be_verified
      expect(operation.last_verification.details[:changed_fields]).to eq([:allowed_origins])
    end

    it "records each verification attempt with its attribution" do
      operation.verify_registration(raw_credential, against: admin_rp, on_change: :continue)

      record = operation.last_verification

      expect(record.credential_id).to be_truthy
      expect(record.origin).to eq(admin_origin)
      expect(record.encoding).to eq("base64url")
      expect(record.to_h[:details][:operation_fingerprint]).to eq(operation.fingerprint)
    end

    it "records failed attempts" do
      wrong_origin = consumer_client.create(challenge: operation.challenge)

      expect { operation.verify_registration(wrong_origin, against: admin_rp, on_change: :continue) }
        .to raise_error(WebAuthn::OriginVerificationError)

      expect(operation.last_verification).to be_failed
      expect(operation.last_verification.error_class).to eq("WebAuthn::OriginVerificationError")
      expect(operation.last_verification.origin).to eq(consumer_origin)
    end
  end

  describe "two relying parties in parallel" do
    it "keeps each issued registration bound to its own site after one is reconfigured" do
      admin_operation = admin_rp.registration_operation(user: { id: "user-1", name: "User" })
      consumer_operation = consumer_rp.registration_operation(user: { id: "user-1", name: "User" })

      admin_raw = admin_client.create(challenge: admin_operation.challenge, rp_id: admin_rp.id)
      consumer_raw = consumer_client.create(challenge: consumer_operation.challenge, rp_id: consumer_rp.id)

      admin_rp.allowed_origins = ["https://changed.example.test"]
      admin_rp.id = "changed.example.test"
      admin_rp.encoding = :base64

      expect(admin_operation.compatibility_with(admin_rp)).to be_stop
      expect(consumer_operation.compatibility_with(consumer_rp)).to be_continue

      admin_credential = admin_operation.verify_registration(admin_raw)
      consumer_credential = consumer_operation.verify_registration(consumer_raw)

      expect(admin_credential.id).to be_truthy
      expect(consumer_credential.id).to be_truthy
      expect(admin_operation.diagnose(admin_raw)).to include(
        encoding: "base64url",
        client_data_origin: admin_origin,
        origin_allowed: true
      )
      expect(consumer_operation.diagnose(consumer_raw)).to include(
        encoding: "base64url",
        client_data_origin: consumer_origin,
        origin_allowed: true
      )
    end

    it "keeps each issued authentication bound to its own site after one is reconfigured" do
      admin_registration = admin_rp.registration_operation(user: { id: "admin-user", name: "Admin User" })
      consumer_registration = consumer_rp.registration_operation(user: { id: "consumer-user", name: "Consumer User" })

      admin_registered = admin_registration.verify_registration(
        admin_client.create(challenge: admin_registration.challenge, rp_id: admin_rp.id)
      )
      consumer_registered = consumer_registration.verify_registration(
        consumer_client.create(challenge: consumer_registration.challenge, rp_id: consumer_rp.id)
      )

      admin_operation = admin_rp.authentication_operation
      consumer_operation = consumer_rp.authentication_operation

      admin_raw = admin_client.get(
        challenge: admin_operation.challenge,
        rp_id: admin_rp.id,
        sign_count: 1,
        user_handle: "admin-user"
      )
      consumer_raw = consumer_client.get(
        challenge: consumer_operation.challenge,
        rp_id: consumer_rp.id,
        sign_count: 1,
        user_handle: "consumer-user"
      )

      admin_rp.allowed_origins = ["https://changed.example.test"]
      admin_rp.id = "changed.example.test"
      admin_rp.encoding = :base64

      expect(admin_operation.compatibility_with(admin_rp)).to be_stop
      expect(consumer_operation.compatibility_with(consumer_rp)).to be_continue

      admin_credential, admin_stored = admin_operation.verify_authentication(
        admin_raw,
        public_key: admin_registration.configuration_snapshot.encoder.encode(admin_registered.raw_public_key),
        sign_count: 0
      ) { |credential| { id: credential.id } }

      consumer_credential, consumer_stored = consumer_operation.verify_authentication(
        consumer_raw,
        public_key: consumer_registration.configuration_snapshot.encoder.encode(consumer_registered.raw_public_key),
        sign_count: 0
      ) { |credential| { id: credential.id } }

      expect(admin_stored[:id]).to eq(admin_registered.id)
      expect(consumer_stored[:id]).to eq(consumer_registered.id)
      expect(admin_credential.sign_count).to eq(1)
      expect(consumer_credential.sign_count).to eq(1)

      expect(admin_operation.diagnose(admin_raw)).to include(
        user_handle: "admin-user",
        client_data_origin: admin_origin,
        rp_id_hash_matches: true
      )
      expect(consumer_operation.diagnose(consumer_raw)).to include(
        user_handle: "consumer-user",
        client_data_origin: consumer_origin,
        rp_id_hash_matches: true
      )
    end
  end

  describe "options built by the global configuration" do
    it "also expose an issuance-bound operation" do
      WebAuthn.configure do |config|
        config.allowed_origins = ["https://www.example.com"]
        config.rp_name = "Example Consumer page"
      end
      client = WebAuthn::FakeClient.new(WebAuthn.configuration.allowed_origins.first, authenticator: authenticator)
      options = WebAuthn.configuration.relying_party.options_for_registration(user: { id: "user-1", name: "User" })

      WebAuthn.configure do |config|
        config.allowed_origins = ["https://changed.example.com"]
        config.rp_id = "changed.example.com"
      end

      raw_credential = client.create(challenge: options.challenge)

      expect(options.operation.compatibility_with(WebAuthn.configuration.relying_party)).to be_stop
      expect(options.operation.verify_registration(raw_credential).id).to be_truthy
    end
  end

  describe "legacy global entrypoint" do
    before do
      WebAuthn.configure do |config|
        config.allowed_origins = ["https://www.example.com"]
        config.rp_name = "Example Consumer page"
      end
    end

    it "still verifies existing integrations" do
      client = WebAuthn::FakeClient.new(WebAuthn.configuration.allowed_origins.first, authenticator: authenticator)
      options = WebAuthn.configuration.relying_party.options_for_registration(user: { id: "user-1", name: "User" })
      raw_credential = client.create(challenge: options.challenge)

      credential = WebAuthn::Credential.from_create(raw_credential)

      expect(credential.verify(options.challenge)).to be_truthy
      expect(WebAuthn.configuration.relying_party.verify_registration(raw_credential, options.challenge).id)
        .to be_truthy
    end
  end
end
