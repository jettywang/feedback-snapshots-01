# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2022-2023, by Samuel Williams.
# Copyright, 2022, by Jeremy Evans.

module Rack
  module Session
    autoload :Cookie, "rack/session/cookie"
    autoload :Pool, "rack/session/pool"
    autoload :CommitPolicy, "rack/session/commit_policy"
    autoload :CommitResult, "rack/session/commit_policy"
    autoload :CommitContext, "rack/session/commit_policy"
    autoload :CommitBody, "rack/session/commit_policy"
  end
end
