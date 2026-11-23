# frozen_string_literal: true

require "spec_helper"
require "webauthn/configuration_snapshot"
require "webauthn/relying_party"

RSpec.describe WebAuthn::ConfigurationSnapshot do
  let(:relying_party) do
    WebAuthn::RelyingParty.new(
      allowed_origins: ["https://admin.example.test"],
      allowed_top_origins: ["https://app.example.test"],
      id: "admin.example.test",
      name: "Admin",
      encoding: :base64url,
      algorithms: ["ES256"],
      verify_attestation_statement: true,
      acceptable_attestation_types: ["None", "Basic"],
      legacy_u2f_appid: "https://admin.example.test"
    )
  end

  describe ".from_relying_party" do
    it "captures the relying party settings" do
      snapshot = described_class.from_relying_party(relying_party)

      expect(snapshot.allowed_origins).to eq(["https://admin.example.test"])
      expect(snapshot.allowed_top_origins).to eq(["https://app.example.test"])
      expect(snapshot.rp_id).to eq("admin.example.test")
      expect(snapshot.rp_name).to eq("Admin")
      expect(snapshot.encoding).to eq(:base64url)
      expect(snapshot.algorithms).to eq(["ES256"])
      expect(snapshot.acceptable_attestation_types).to eq(["None", "Basic"])
      expect(snapshot.legacy_u2f_appid).to eq("https://admin.example.test")
    end

    it "is detached from later relying party mutations" do
      snapshot = described_class.from_relying_party(relying_party)

      relying_party.allowed_origins = ["https://changed.example.test"]
      relying_party.id = "changed.example.test"
      relying_party.encoding = :base64
      relying_party.algorithms << "RS256"

      expect(snapshot.allowed_origins).to eq(["https://admin.example.test"])
      expect(snapshot.rp_id).to eq("admin.example.test")
      expect(snapshot.encoding).to eq(:base64url)
      expect(snapshot.algorithms).to eq(["ES256"])
    end
  end

  describe "#fingerprint" do
    it "is stable for equivalent configurations" do
      other = WebAuthn::RelyingParty.new(
        allowed_origins: ["https://admin.example.test"],
        allowed_top_origins: ["https://app.example.test"],
        id: "admin.example.test",
        name: "Admin renamed",
        encoding: :base64url,
        algorithms: ["ES256"],
        acceptable_attestation_types: ["Basic", "None"],
        legacy_u2f_appid: "https://admin.example.test"
      )

      expect(described_class.from_relying_party(relying_party).fingerprint)
        .to eq(described_class.from_relying_party(other).fingerprint)
    end

    it "is independent of the order of allowed origins and algorithms" do
      reordered = WebAuthn::RelyingParty.new(
        allowed_origins: ["https://other.example.test", "https://admin.example.test"],
        allowed_top_origins: ["https://app.example.test"],
        id: "admin.example.test",
        name: "Admin",
        algorithms: ["ES256", "RS256"],
        acceptable_attestation_types: ["None", "Basic"]
      )

      original = WebAuthn::RelyingParty.new(
        allowed_origins: ["https://admin.example.test", "https://other.example.test"],
        allowed_top_origins: ["https://app.example.test"],
        id: "admin.example.test",
        name: "Admin",
        algorithms: ["RS256", "ES256"],
        acceptable_attestation_types: ["None", "Basic"]
      )

      expect(described_class.from_relying_party(original).fingerprint)
        .to eq(described_class.from_relying_party(reordered).fingerprint)
    end

    it "changes when a flow-defining field changes" do
      original = described_class.from_relying_party(relying_party)
      relying_party.allowed_origins = ["https://changed.example.test"]

      expect(described_class.from_relying_party(relying_party).fingerprint).not_to eq(original.fingerprint)
    end
  end

  describe "serialization" do
    it "round-trips through a hash" do
      snapshot = described_class.from_relying_party(relying_party)
      restored = described_class.from_h(snapshot.to_h)

      expect(restored.to_h).to eq(snapshot.to_h)
      expect(restored.fingerprint).to eq(snapshot.fingerprint)
    end

    it "round-trips through JSON" do
      snapshot = described_class.from_relying_party(relying_party)
      restored = described_class.from_json(snapshot.to_json)

      expect(restored.to_h).to eq(snapshot.to_h)
    end

    it "rejects a tampered fingerprint" do
      hash = described_class.from_relying_party(relying_party).to_h
      hash["rp_id"] = "attacker.example.test"

      expect { described_class.from_h(hash) }
        .to raise_error(WebAuthn::ConfigurationSnapshot::FingerprintMismatchError)
    end
  end

  describe "#explain" do
    it "includes the encoder and verification policy used for the ceremony" do
      explanation = described_class.from_relying_party(relying_party).explain

      expect(explanation[:rp_id]).to eq("admin.example.test")
      expect(explanation[:encoding]).to eq("base64url")
      expect(explanation[:encoder]).to eq("WebAuthn::Encoders::Base64UrlEncoder")
      expect(explanation[:verification][:algorithms]).to eq(["ES256"])
      expect(explanation[:fingerprint]).to match(/\A[0-9a-f]{64}\z/)
    end
  end

  describe "#ensure_complete!" do
    it "accepts a snapshot whose RP ID can be derived from a single origin" do
      snapshot = described_class.new(allowed_origins: ["https://admin.example.test"])

      expect { snapshot.ensure_complete! }.not_to raise_error
    end

    it "rejects snapshots without allowed origins" do
      snapshot = described_class.new(rp_id: "admin.example.test")

      expect { snapshot.ensure_complete! }
        .to raise_error(WebAuthn::ConfigurationSnapshot::IncompleteError)
    end

    it "rejects snapshots with multiple origins and no explicit RP ID" do
      snapshot = described_class.new(
        allowed_origins: ["https://admin.example.test", "https://other.example.test"]
      )

      expect { snapshot.ensure_complete! }
        .to raise_error(WebAuthn::ConfigurationSnapshot::IncompleteError)
    end
  end
end
