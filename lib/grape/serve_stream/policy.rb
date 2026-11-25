# frozen_string_literal: true

module Grape
  module ServeStream
    # The authorization a streamed response was approved under, frozen when the
    # response was set up. A stream checks it before every line: a policy whose
    # +version+ no longer matches the one the response started with stops the
    # body, and a record the policy denies is never rendered.
    #
    # +version+ names the policy revision (a deployment, a permission set, an
    # ETag -- anything that changes when the decision would). +permitted+ takes
    # the projected record and answers whether it may be disclosed; without it
    # every record passes and only the version is enforced.
    #
    #   policy = Grape::ServeStream::Policy.new(version: 'v3', permitted: ->(row) { row[:tenant] == current_tenant })
    class Policy
      attr_reader :version

      def initialize(version:, permitted: nil)
        @version = version&.to_s&.freeze
        @permitted = permitted
        freeze
      end

      def permitted?(record)
        return true unless @permitted

        @permitted.call(record)
      end
    end
  end
end
