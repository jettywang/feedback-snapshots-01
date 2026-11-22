# encoding: utf-8
# frozen_string_literal: true

# Models a single sign-on (SSO) strategy that is consulted first.
#
# The upstream identity provider is driven entirely by request params so the
# spec can deterministically reproduce every branch of the result contract:
#
#   no +sso_token+ param        -> pass (no usable material, keep cascading)
#   +sso_token+ of "bad"        -> fail (verification failed, keep cascading)
#   +sso_token+ of "deactivated"-> fail! (upstream confirmed deactivation, halt)
#   +sso_token+ of "good"       -> success! (short-circuit, authenticated)
Warden::Strategies.add(:single_sign_on) do
  def authenticate!
    record(:single_sign_on)

    token = params["sso_token"]
    return pass if token.nil? || token.to_s.empty?

    case token
    when "good"
      success!("SSO User", "Single sign-on accepted")
    when "deactivated"
      fail!("Account deactivated by the identity provider")
    when "bad"
      fail("Single sign-on token could not be verified")
    else
      fail("Single sign-on token could not be verified")
    end
  end

  private

  def record(name)
    request.env['warden.spec.strategies'] ||= []
    request.env['warden.spec.strategies'] << name
  end
end
