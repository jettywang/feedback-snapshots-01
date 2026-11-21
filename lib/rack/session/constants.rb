# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2022-2023, by Samuel Williams.
# Copyright, 2022, by Jeremy Evans.

module Rack
  module Session
    RACK_SESSION                        = 'rack.session'
    RACK_SESSION_OPTIONS                = 'rack.session.options'
    RACK_SESSION_UNPACKED_COOKIE_DATA   = 'rack.session.unpacked_cookie_data'

    # Per-request input used by applications to mark a response as a business
    # success (true, commits are allowed) or a business failure (false, staged
    # session data must not be committed). The commit policy can also read the
    # marker directly from the request environment.
    RACK_SESSION_BUSINESS_SUCCESS       = 'rack.session.business_success'
    RACK_SESSION_BUSINESS_FAILURE       = 'rack.session.business_failure'
    RACK_SESSION_BUSINESS_SUCCESS_HEADER = 'x-rack-session-business-success'

    # Per-request input which explicitly allows (true) or denies (false) the
    # session commit, regardless of the configured policy.
    RACK_SESSION_COMMIT                 = 'rack.session.commit'
    RACK_SESSION_COMMIT_MARKER          = 'rack.session.commit_marker'

    # Per-request override for the configured commit policy.
    RACK_SESSION_COMMIT_POLICY          = 'rack.session.commit_policy'

    # Output written by the middleware. `committed` and `persisted` describe
    # session storage, while `business_success` describes the application's
    # response. They are intentionally independent: a request can be a
    # business success even if writing the session failed.
    RACK_SESSION_COMMIT_RESULT          = 'rack.session.commit_result'
    RACK_SESSION_COMMITTED              = 'rack.session.committed'
    RACK_SESSION_PERSISTED              = 'rack.session.persisted'
    RACK_SESSION_COMMIT_STATUS          = 'rack.session.commit_status'
    RACK_SESSION_COMMIT_ERROR           = 'rack.session.commit_error'
  end
end
