# frozen_string_literal: true

require 'rack/request'

require_relative 'abstract/id'
require_relative 'constants'

module Rack
  module Session
    # Observation provides a restricted, read-only view of the session
    # state of a request, suitable for diagnostics and support tooling.
    #
    # It reports one of the following statuses:
    #
    # [+:unloaded+] The session was prepared by the middleware, but the
    #               session data has not been loaded from the store.
    # [+:prepared+] The session data has been loaded and is available.
    # [+:invalid+]  The request presented session credentials (such as a
    #               cookie) that could not be resolved to a session.
    # [+:rejected+] The session cannot be committed because the request
    #               does not meet the security requirements, e.g. a
    #               :secure session over an insecure connection.
    #
    # Observing a request never forces the session to be loaded, and
    # never exposes session values: only the keys explicitly approved
    # using the :allow option are reported, along with the
    # classification (class name) of their values.
    #
    # Example:
    #
    #   observation = Rack::Session::Observation.new(request, allow: [:user_id])
    #   observation.status # => :prepared
    #   observation.to_h # => {status: :prepared, keys: ["user_id"], classification: {"user_id" => "Integer"}}
    #
    class Observation
      UNLOADED = :unloaded
      PREPARED = :prepared
      INVALID = :invalid
      REJECTED = :rejected

      STATUSES = [UNLOADED, PREPARED, INVALID, REJECTED].freeze

      attr_reader :status

      def self.observe(request, **options)
        new(request, **options)
      end

      def initialize(request, allow: [])
        request = Rack::Request.new(request) unless request.respond_to?(:get_header)

        @request = request
        @allow = allow.map(&:to_s)
        @session = request.get_header(RACK_SESSION)
        @status = classify
      end

      # The approved keys that are present in the session. Empty unless
      # the session is loaded; never forces the session to be loaded.
      def keys
        return [] unless loaded?

        @allow & @session.keys
      end

      # The classification (class name) of the values of the approved
      # keys that are present in the session.
      def classification
        keys.each_with_object({}) do |key, hash|
          hash[key] = @session[key].class.name
        end
      end

      # A restricted record of the observation, safe to log.
      def to_h
        {
          status: @status,
          keys: keys,
          classification: classification,
        }
      end

      private

      def loaded?
        @session.is_a?(Abstract::SessionHash) && @session.loaded?
      end

      def classify
        return UNLOADED unless @session.is_a?(Abstract::SessionHash)
        return INVALID if invalid?
        return REJECTED if rejected?
        return PREPARED if @session.loaded?

        UNLOADED
      end

      def invalid?
        @session.presented? && !@session.exists?
      end

      def rejected?
        @session.options[:secure] && !@request.ssl?
      end
    end
  end
end
