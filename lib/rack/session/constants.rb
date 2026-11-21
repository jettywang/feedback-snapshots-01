# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2022-2023, by Samuel Williams.
# Copyright, 2022, by Jeremy Evans.

module Rack
  module Session
    RACK_SESSION                        = 'rack.session'
    RACK_SESSION_OPTIONS                = 'rack.session.options'
    RACK_SESSION_UNPACKED_COOKIE_DATA   = 'rack.session.unpacked_cookie_data'

    # Set this request environment entry to explicitly select the session
    # partition for the current request, for example +:direct+ or
    # +:embedded+. It is consulted before the configured partition strategy.
    RACK_SESSION_PARTITION              = 'rack.session.partition'

    # Internal request environment entry recording the partition that was
    # resolved for the current request.
    RACK_SESSION_PARTITION_CURRENT      = 'rack.session.partition.current'

    # Internal cookie data key recording the partition a persisted session
    # belongs to. It is never exposed through Rack::Session::Abstract::SessionHash.
    RACK_SESSION_PARTITION_DATA         = 'session_partition'
  end
end
