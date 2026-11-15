# frozen_string_literal: true

require "spec_helper"

require "securerandom"
require "webauthn/authenticator_assertion_response"
require "webauthn/configuration"
require "webauthn/public_key_credential_with_assertion"
require "webauthn/u2f_migrator"
require "support/seeds"

RSpec.describe "PublicKeyCredentialWithAssertion" do
  describe "#verify" do
    let(:client) { WebAuthn::FakeClient.new(origin, encoding: false) }
    let(:challenge) { WebAuthn::Encoders::Base64UrlEncoder.encode(raw_challenge) }
    let(:raw_challenge) { fake_challenge }
    let(:origin) { fake_origin }

    let!(:credential) { create_credential(client: client) }
    let(:credential_raw_id) { credential[0] }
    let(:credential_id) { WebAuthn::Encoders::Base64UrlEncoder.encode(credential_raw_id) }
    let(:credential_type) { "public-key" }
    let(:credential_authenticator_attachment) { 'platform' }
    let(:credential_public_key) { WebAuthn::Encoders::Base64UrlEncoder.encode(credential[1]) }
    let(:credential_sign_count) { credential[2] }

    let(:assertion_response) do
      response = client.get(challenge: raw_challenge, sign_count: 1)["response"]

      WebAuthn::AuthenticatorAssertionResponse.new(
        authenticator_data: response["authenticatorData"],
        client_data_json: response["clientDataJSON"],
        signature: response["signature"]
      )
    end

    let(:public_key_credential) do
      WebAuthn::PublicKeyCredentialWithAssertion.new(
        type: credential_type,
        id: credential_id,
        raw_id: credential_raw_id,
        authenticator_attachment: credential_authenticator_attachment,
        response: assertion_response
      )
    end

    before do
      WebAuthn.configuration.allowed_origins = [origin]
    end

    it "works" do
      expect(
        public_key_credential.verify(challenge, public_key: credential_public_key, sign_count: credential_sign_count)
      ).to be_truthy

      expect(public_key_credential.id).not_to be_empty
      expect(public_key_credential.user_handle).to be_nil
      expect(public_key_credential.sign_count).to eq(credential_sign_count + 1)
    end

    context "when type is invalid" do
      context "because it is missing" do
        let(:credential_type) { nil }

        it "fails" do
          expect do
            public_key_credential.verify(
              challenge,
              public_key: credential_public_key,
              sign_count: credential_sign_count
            )
          end.to raise_error(RuntimeError)
        end
      end

      context "because it is something else" do
        let(:credential_type) { "password" }

        it "fails" do
          expect do
            public_key_credential.verify(
              challenge,
              public_key: credential_public_key,
              sign_count: credential_sign_count
            )
          end.to raise_error(RuntimeError)
        end
      end
    end

    context "when id is invalid" do
      context "because it is missing" do
        let(:credential_id) { nil }

        it "fails" do
          expect do
            public_key_credential.verify(
              challenge,
              public_key: credential_public_key,
              sign_count: credential_sign_count
            )
          end.to raise_error(RuntimeError)
        end
      end

      context "because it is not the base64url of raw id" do
        let(:credential_id) { WebAuthn::Encoders::Base64UrlEncoder.encode(credential_raw_id + "a") }

        it "fails" do
          expect do
            public_key_credential.verify(
              challenge,
              public_key: credential_public_key,
              sign_count: credential_sign_count
            )
          end.to raise_error(RuntimeError)
        end
      end
    end

    context "when challenge class is invalid" do
      it "raise error" do
        expect do
          public_key_credential.verify(
            nil,
            public_key: credential_public_key,
            sign_count: credential_sign_count
          )
        end.to raise_error(WebAuthn::PublicKeyCredential::InvalidChallengeError)
      end
    end

    context "when challenge is invalid" do
      let(:challenge) { WebAuthn::Encoders::Base64UrlEncoder.encode("another challenge") }

      it "fails" do
        expect do
          public_key_credential.verify(
            challenge,
            public_key: credential_public_key,
            sign_count: credential_sign_count
          )
        end.to raise_error(WebAuthn::ChallengeVerificationError)
      end
    end

    context "when clientExtensionResults" do
      context "is not received" do
        let(:public_key_credential) do
          WebAuthn::PublicKeyCredentialWithAssertion.new(
            type: credential_type,
            id: credential_id,
            raw_id: credential_raw_id,
            client_extension_outputs: nil,
            response: assertion_response
          )
        end

        it "works" do
          expect(
            public_key_credential.verify(
              challenge,
              public_key: credential_public_key,
              sign_count: credential_sign_count
            )
          ).to be_truthy

          expect(public_key_credential.client_extension_outputs).to be_nil
        end
      end

      context "is received" do
        let(:public_key_credential) do
          WebAuthn::PublicKeyCredentialWithAssertion.new(
            type: credential_type,
            id: credential_id,
            raw_id: credential_raw_id,
            client_extension_outputs: { "txAuthSimple" => "Could you please verify yourself?" },
            response: assertion_response
          )
        end

        it "works" do
          expect(
            public_key_credential.verify(
              challenge,
              public_key: credential_public_key,
              sign_count: credential_sign_count
            )
          ).to be_truthy

          expect(public_key_credential.client_extension_outputs)
            .to eq({ "txAuthSimple" => "Could you please verify yourself?" })
        end
      end
    end

    context "when authentication extension input" do
      context "is not received" do
        let(:assertion_response) do
          response = client.get(challenge: raw_challenge, extensions: nil)["response"]

          WebAuthn::AuthenticatorAssertionResponse.new(
            authenticator_data: response["authenticatorData"],
            client_data_json: response["clientDataJSON"],
            signature: response["signature"]
          )
        end

        it "works" do
          expect(
            public_key_credential.verify(
              challenge,
              public_key: credential_public_key,
              sign_count: credential_sign_count
            )
          ).to be_truthy

          expect(public_key_credential.authenticator_extension_outputs).to be_nil
        end
      end

      context "is received" do
        let(:assertion_response) do
          response = client.get(
            challenge: raw_challenge,
            extensions: { "txAuthSimple" => "Could you please verify yourself?" }
          )["response"]

          WebAuthn::AuthenticatorAssertionResponse.new(
            authenticator_data: response["authenticatorData"],
            client_data_json: response["clientDataJSON"],
            signature: response["signature"]
          )
        end

        it "works" do
          expect(
            public_key_credential.verify(
              challenge,
              public_key: credential_public_key,
              sign_count: credential_sign_count
            )
          ).to be_truthy

          expect(public_key_credential.authenticator_extension_outputs)
            .to eq({ "txAuthSimple" => "Could you please verify yourself?" })
        end
      end
    end

    context "when verifying a migrated U2F credential" do
      let!(:credential) do
        migrated_credential = WebAuthn::U2fMigrator.new(**seeds[:u2f_migration][:stored_credential])

        [
          migrated_credential.credential.id,
          migrated_credential.credential.public_key,
          migrated_credential.authenticator_data.sign_count
        ]
      end

      let(:public_key_credential) do
        WebAuthn::PublicKeyCredentialWithAssertion.new(
          type: credential_type,
          id: credential_id,
          raw_id: credential_raw_id,
          client_extension_outputs: client_extension_outputs,
          response: assertion_response
        )
      end

      let(:assertion_response) do
        WebAuthn::AuthenticatorAssertionResponse.new(
          **seeds[:u2f_migration][:assertion][:response].transform_values do |v|
            WebAuthn::Encoders::Base64Encoder.decode(v)
          end
        )
      end

      let(:origin) { seeds[:u2f_migration][:assertion][:origin] }
      let(:challenge) { seeds[:u2f_migration][:assertion][:challenge] }

      let(:verify_assertion) do
        lambda do
          public_key_credential.verify(
            challenge,
            public_key: credential_public_key,
            sign_count: credential_sign_count
          )
        end
      end

      # The seed assertion's rpIdHash is the hash of the legacy FIDO AppID, not the RP ID, so it can
      # only verify through the legacy AppID compatibility path.
      context "when the server requested the configured legacy AppID" do
        before do
          WebAuthn.configuration.legacy_u2f_appid = seeds[:u2f_migration][:stored_credential][:app_id]
        end

        context "and the appid extension output is the boolean true" do
          let(:client_extension_outputs) { { "appid" => true } }

          it "verifies the rpIdHash against the configured AppID and works" do
            expect(verify_assertion.call).to be_truthy
          end
        end

        context "and the appid extension output is the boolean false" do
          let(:client_extension_outputs) { { "appid" => false } }

          it "does not use the AppID and fails the RP ID hash check" do
            expect { verify_assertion.call }.to raise_error(WebAuthn::RpIdVerificationError)
          end
        end

        context "and the appid extension output is not present" do
          let(:client_extension_outputs) { {} }

          it "does not use the AppID and fails the RP ID hash check" do
            expect { verify_assertion.call }.to raise_error(WebAuthn::RpIdVerificationError)
          end
        end

        context "and the appid extension output is the string \"false\"" do
          let(:client_extension_outputs) { { "appid" => "false" } }

          it "treats it as not the boolean true and fails the RP ID hash check" do
            expect { verify_assertion.call }.to raise_error(WebAuthn::RpIdVerificationError)
          end
        end

        context "and the appid extension output is a number" do
          let(:client_extension_outputs) { { "appid" => 1 } }

          it "treats it as not the boolean true and fails the RP ID hash check" do
            expect { verify_assertion.call }.to raise_error(WebAuthn::RpIdVerificationError)
          end
        end

        context "and the appid extension output is an untrusted AppID URL" do
          let(:client_extension_outputs) { { "appid" => "https://attacker.example/appid" } }

          it "never reads the AppID from the client and fails the RP ID hash check" do
            expect { verify_assertion.call }.to raise_error(WebAuthn::RpIdVerificationError)
          end
        end
      end

      context "when the server did not request a legacy AppID" do
        context "and the appid extension output is the boolean true" do
          let(:client_extension_outputs) { { "appid" => true } }

          it "ignores the unsolicited extension and fails the RP ID hash check" do
            expect { verify_assertion.call }.to raise_error(WebAuthn::RpIdVerificationError)
          end
        end

        context "and the appid extension output is a truthy non-boolean value" do
          let(:client_extension_outputs) { { "appid" => "false" } }

          it "ignores the unsolicited extension and fails the RP ID hash check" do
            expect { verify_assertion.call }.to raise_error(WebAuthn::RpIdVerificationError)
          end
        end

        context "and the appid extension output is not present" do
          let(:client_extension_outputs) { {} }

          it "fails the RP ID hash check" do
            expect { verify_assertion.call }.to raise_error(WebAuthn::RpIdVerificationError)
          end
        end
      end
    end

    context "when verifying a normal WebAuthn credential" do
      let(:rp_id) { URI.parse(origin).host }
      let(:client) { WebAuthn::FakeClient.new(origin, encoding: false) }

      let!(:credential) { create_credential(client: client) }

      let(:assertion_response) do
        response = client.get(challenge: raw_challenge, rp_id: rp_id, sign_count: 1)["response"]

        WebAuthn::AuthenticatorAssertionResponse.new(
          authenticator_data: response["authenticatorData"],
          client_data_json: response["clientDataJSON"],
          signature: response["signature"]
        )
      end

      let(:public_key_credential) do
        WebAuthn::PublicKeyCredentialWithAssertion.new(
          type: credential_type,
          id: credential_id,
          raw_id: credential_raw_id,
          client_extension_outputs: client_extension_outputs,
          response: assertion_response
        )
      end

      before do
        WebAuthn.configuration.allowed_origins = [origin]
        WebAuthn.configuration.rp_id = rp_id
      end

      context "when the server requested the configured legacy AppID" do
        before do
          WebAuthn.configuration.legacy_u2f_appid = "https://legacy-u2f.example.com"
        end

        context "and no appid extension output is present" do
          let(:client_extension_outputs) { {} }

          it "verifies the rpIdHash against the regular RP ID and works" do
            expect(
              public_key_credential.verify(
                challenge,
                public_key: credential_public_key,
                sign_count: credential_sign_count
              )
            ).to be_truthy
          end
        end

        context "and an unauthorized appid=true extension output is present" do
          let(:client_extension_outputs) { { "appid" => true } }

          it "does not turn the RP-hash-mismatching response into a loginable credential" do
            expect do
              public_key_credential.verify(
                challenge,
                public_key: credential_public_key,
                sign_count: credential_sign_count
              )
            end.to raise_error(WebAuthn::RpIdVerificationError)
          end
        end

        context "and an appid=false extension output is present" do
          let(:client_extension_outputs) { { "appid" => false } }

          it "keeps verifying against the regular RP ID and works" do
            expect(
              public_key_credential.verify(
                challenge,
                public_key: credential_public_key,
                sign_count: credential_sign_count
              )
            ).to be_truthy
          end
        end

        context "and the appid extension output is a non-boolean truthy value" do
          let(:client_extension_outputs) { { "appid" => "false" } }

          it "does not switch to the AppID and keeps verifying against the regular RP ID" do
            expect(
              public_key_credential.verify(
                challenge,
                public_key: credential_public_key,
                sign_count: credential_sign_count
              )
            ).to be_truthy
          end
        end
      end

      context "when the server did not request a legacy AppID" do
        context "and an appid=true extension output is present" do
          let(:client_extension_outputs) { { "appid" => true } }

          it "ignores the unsolicited extension and keeps verifying against the regular RP ID" do
            expect(
              public_key_credential.verify(
                challenge,
                public_key: credential_public_key,
                sign_count: credential_sign_count
              )
            ).to be_truthy
          end
        end
      end
    end

    context "when user_presence" do
      context "is not set" do
        it "correcly delegates its value to the response" do
          expect(assertion_response).to receive(:verify).with(anything, hash_including(user_presence: nil))

          public_key_credential.verify(challenge, public_key: credential_public_key, sign_count: credential_sign_count)
        end
      end

      context "is set to false" do
        it "correcly delegates its value to the response" do
          expect(assertion_response).to receive(:verify).with(anything, hash_including(user_presence: false))

          public_key_credential.verify(
            challenge,
            public_key: credential_public_key,
            sign_count: credential_sign_count,
            user_presence: false
          )
        end
      end

      context "is set to true" do
        it "correcly delegates its value to the response" do
          expect(assertion_response).to receive(:verify).with(anything, hash_including(user_presence: true))

          public_key_credential.verify(
            challenge,
            public_key: credential_public_key,
            sign_count: credential_sign_count,
            user_presence: true
          )
        end
      end
    end
  end
end
