# encoding: utf-8
# frozen_string_literal: true

# Backwards-compatible password strategy for older clients that do not carry
# SSO credentials. It is only reached once the single sign-on strategy passes or
# soft-fails, preserving the historical password semantics when no new SSO
# configuration is present.
Warden::Strategies.add(:legacy_password) do
  def authenticate!
    record(:legacy_password)

    if params["password"] || params["username"]
      if params["password"] == "sekrit" && params["username"] == "fred"
        success!("Legacy User")
      else
        fail!("Username or password is incorrect")
      end
    else
      pass
    end
  end

  private

  def record(name)
    request.env['warden.spec.strategies'] ||= []
    request.env['warden.spec.strategies'] << name
  end
end
