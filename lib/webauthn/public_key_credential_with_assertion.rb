# frozen_string_literal: true

require "webauthn/authenticator_assertion_response"
require "webauthn/public_key_credential"

module WebAuthn
  class PublicKeyCredentialWithAssertion < PublicKeyCredential
    def self.response_class
      WebAuthn::AuthenticatorAssertionResponse
    end

    def verify(challenge, public_key:, sign_count:, user_presence: nil, user_verification: nil)
      super

      response.verify(
        encoder.decode(challenge),
        public_key: encoder.decode(public_key),
        sign_count: sign_count,
        user_presence: user_presence,
        user_verification: user_verification,
        rp_id: appid_extension_output? ? legacy_u2f_appid : nil
      )

      true
    end

    def user_handle
      if raw_user_handle
        encoder.encode(raw_user_handle)
      end
    end

    def raw_user_handle
      response.user_handle
    end

    private

    # The legacy FIDO AppID compatibility path is only valid when all of the following hold:
    #
    #   1. The Relying Party configured a legacy U2F AppID, which is what makes the server request
    #      the `appid` extension when building the authentication options. Without it the extension
    #      was never requested for this ceremony.
    #   2. The client extension output is the boolean `true`. The WebAuthn `appid` extension output
    #      is a boolean, so the string `"false"`, numbers or any other truthy value are not accepted
    #      and must not switch RP ID hash verification to the AppID.
    #
    # See https://www.w3.org/TR/webauthn-2/#sctn-appid-extension
    def appid_extension_output?
      legacy_u2f_appid && client_extension_outputs && client_extension_outputs['appid'] == true
    end

    def legacy_u2f_appid
      appid = relying_party.legacy_u2f_appid or return

      URI.parse(appid).to_s
    end
  end
end
