# encoding: utf-8
# frozen_string_literal: true
module Warden
  module Strategies
    # A strategy is a place where you can put logic related to authentication. Any strategy inherits
    # from Warden::Strategies::Base.
    #
    # The Warden::Strategies.add method is a simple way to provide custom strategies.
    # You _must_ declare an @authenticate!@ method.
    # You _may_ provide a @valid?@ method.
    # The valid method should return true or false depending on if the strategy is a valid one for the request.
    #
    # The parameters for Warden::Strategies.add method are:
    #   <label: Symbol> The label is the name given to a strategy.  Use the label to refer to the strategy when authenticating
    #   <strategy: Class|nil> The optional strategy argument if set _must_ be a class that inherits from Warden::Strategies::Base and _must_
    #                         implement an @authenticate!@ method
    #   <block> The block acts as a convenient way to declare your strategy.  Inside is the class definition of a strategy.
    #
    # Examples:
    #
    #   Block Declared Strategy:
    #    Warden::Strategies.add(:foo) do
    #      def authenticate!
    #        # authentication logic
    #      end
    #    end
    #
    #    Class Declared Strategy:
    #      Warden::Strategies.add(:foo, MyStrategy)
    #
    class Base
      # == Result contract
      #
      # A strategy reports the outcome of +authenticate!+ through a small, fixed
      # set of terminal helpers. The framework only inspects two things once the
      # strategy has run: the +result+ (+nil+, +:success+, +:failure+,
      # +:redirect+ or +:custom+) and whether the strategy was halted. Express
      # your intent through the helpers below instead of setting those directly.
      #
      # +pass+ (or returning without any helper)::
      #   +result+ is +nil+ and the strategy is not halted. There is no usable
      #   material for this strategy, so Warden cascades to the next strategy and
      #   treats the request as unauthenticated when none remains. Use this for a
      #   missing credential rather than a rejection.
      #
      # +fail+(message)::
      #   +result+ is +:failure+, the strategy is not halted and +failed?+ is
      #   true. A soft, recoverable failure, such as an upstream check that could
      #   not be verified. Warden records the message and keeps cascading; the
      #   message of the last failing strategy wins.
      #
      # +fail!+(message)::
      #   +result+ is +:failure+, the strategy is halted and +failed?+ is true.
      #   A definitive rejection where the upstream positively confirmed the
      #   identity must not be accepted (for example a deactivated account).
      #   Warden stops cascading immediately and renders the failure response.
      #
      # +success!+(user, message = nil)::
      #   +result+ is +:success+, the strategy is halted, +user+ is assigned and
      #   +successful?+ is true. Warden short-circuits the remaining strategies
      #   and logs the user in.
      #
      # +redirect!+(url, ...) / +custom!+(response)::
      #   Halted terminal outcomes (+:redirect+ / +:custom+) that take effect
      #   together with +throw(:warden)+.
      #
      # In short: a missing credential +pass+es and cascades, an unverifiable
      # answer soft-+fail+s and still cascades, a confirmed refusal +fail!+s and
      # terminates, and +success!+ terminates with an authenticated user.
      #
      # :api: public
      attr_accessor :user, :message

      # :api: private
      attr_accessor :result, :custom_response

      # :api: public
      attr_reader :env, :scope, :status

      include ::Warden::Mixins::Common

      # :api: private
      def initialize(env, scope=nil) # :nodoc:
        @env, @scope = env, scope
        @status, @headers = nil, {}
        @halted, @performed = false, false
        @result = nil
      end

      # The method that is called from above. This method calls the underlying authenticate! method
      # :api: private
      def _run! # :nodoc:
        @performed = true
        authenticate!
        self
      end

      # Returns if this strategy was already performed.
      # :api: private
      def performed? #:nodoc:
        @performed
      end

      # Marks this strategy as not performed.
      # :api: private
      def clear!
        @performed = false
      end

      # Acts as a guarding method for the strategy.
      # If #valid? responds false, the strategy will not be executed
      # Overwrite with your own logic
      # :api: overwritable
      def valid?; true; end

      # Provides access to the headers hash for setting custom headers
      # :api: public
      def headers(header = {})
        @headers ||= {}
        @headers.merge! header
        @headers
      end

      # Access to the errors object.
      # :api: public
      def errors
        @env['warden'].errors
      end

      # Cause the processing of the strategies to stop and cascade no further
      # :api: public
      def halt!
        @halted = true
      end

      # Checks to see if a strategy was halted
      # :api: public
      def halted?
        !!@halted
      end

      # Checks to see if a strategy should result in a permanent login
      # :api: public
      def store?
        true
      end

      # A simple method to return from authenticate! if you want to ignore this strategy
      # :api: public
      def pass; end

      # Returns true only if the result is a success and a user was assigned.
      def successful?
        @result == :success && !user.nil?
      end

      # Returns true only if the result is a failure, whether the strategy was
      # halted (+fail!+) or merely soft-failed (+fail+). A strategy that simply
      # +pass+ed returns false because it never produced a failure result.
      # :api: public
      def failed?
        @result == :failure
      end

      # Whenever you want to provide a user object as "authenticated" use the +success!+ method.
      # This will halt the strategy, and set the user in the appropriate scope.
      # It is the "login" method
      #
      # Parameters:
      #   user - The user object to login.  This object can be anything you have setup to serialize in and out of the session
      #
      # :api: public
      def success!(user, message = nil)
        halt!
        @user = user
        @message = message
        @result = :success
      end

      # This causes the strategy to fail.  It does not throw a :warden symbol to drop the request out to the failure application
      # You must throw a :warden symbol somewhere in the application to enforce this
      # Halts the strategies so that this is the last strategy checked
      # :api: public
      def fail!(message = "Failed to Login")
        halt!
        @message = message
        @result = :failure
      end

      # Causes the strategy to fail, but not halt.  The strategies will cascade after this failure and warden will check the next strategy.  The last strategy to fail will have it's message displayed.
      # :api: public
      def fail(message = "Failed to Login")
        @message = message
        @result = :failure
      end

      # Causes the authentication to redirect.  A :warden symbol must be thrown to actually execute this redirect
      #
      # Parameters:
      #  url <String> - The string representing the URL to be redirected to
      #  params <Hash> - Any parameters to encode into the URL
      #  opts <Hash> - Any options to redirect with.
      #    available options: permanent => (true || false)
      #
      # :api: public
      def redirect!(url, params = {}, opts = {})
        halt!
        @status = opts[:permanent] ? 301 : 302
        headers["Location"] = url.dup
        headers["Location"] << "?" << Rack::Utils.build_query(params) unless params.empty?
        headers["Content-Type"] = opts[:content_type] || 'text/plain'

        @message = opts[:message] || "You are being redirected to #{headers["Location"]}"
        @result = :redirect

        headers["Location"]
      end

      # Return a custom rack array.  You must throw an :warden symbol to activate this
      # :api: public
      def custom!(response)
        halt!
        @custom_response = response
        @result = :custom
      end

    end # Base
  end # Strategies
end # Warden
