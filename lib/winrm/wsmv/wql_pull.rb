require 'securerandom'
require_relative 'base'
require_relative 'wql_enumeration'

module WinRM
  module WSMV
    # WSMV message to 'pull' rest of enumeration results from Windows via WQL
    #
    # A Pull is always issued for one specific WqlEnumerationContext. The
    # session endpoint and the context namespace/resource URI must match, so a
    # pull cannot accidentally target a different connection or WMI class.
    class WqlPull < Base
      attr_reader :context, :message_id, :session_opts, :enumeration_context

      def initialize(session_opts, namespace, enumeration_context, context: nil)
        @session_opts = session_opts
        @context = context
        @namespace = context ? context.namespace : namespace
        @requested_namespace = namespace
        @enumeration_context = enumeration_context
        @message_id = SecureRandom.uuid.to_s.upcase
        validate_context!
      end

      # Parses a Pull response and returns its body hash. Correlation checks
      # happen in WqlQuery, which keeps the full parsed envelope.
      def process_response(response)
        WqlResponse.new(response).body
      end

      protected

      def create_header(header)
        header << Gyoku.xml(wql_header)
      end

      def create_body(body)
        body.tag!("#{NS_ENUM}:Pull") { |en| en << Gyoku.xml(wql_body) }
      end

      private

      def validate_context!
        return if @context.nil?

        if @context.endpoint != WqlEnumerationContext.normalize_endpoint(@session_opts[:endpoint])
          raise WqlContextMismatchError,
                "pull for query #{@context.query_id} cannot be sent to endpoint " \
                "#{@session_opts[:endpoint].inspect}; the context belongs to #{@context.endpoint.inspect}"
        end
        unless @context.namespace == @requested_namespace
          raise WqlContextMismatchError,
                "pull for query #{@context.query_id} targets namespace #{@requested_namespace.inspect}, " \
                "but the context is bound to #{@context.namespace.inspect}"
        end

        return if @enumeration_context.nil?

        @context.assert_current_token!(@enumeration_context)
      end

      def wql_header
        merge_headers(
          shared_headers(@session_opts, message_id: @message_id),
          resource_uri_wmi(@namespace),
          action_enumerate_pull
        )
      end

      def wql_body
        {
          "#{NS_ENUM}:EnumerationContext" => @enumeration_context,
          "#{NS_WSMAN_DMTF}:OptimizeEnumeration" => nil,
          "#{NS_ENUM}:MaxElements" => '32000',
          "#{NS_WSMAN_MSFT}:SessionId" => "uuid:#{@session_opts[:session_id]}"
        }
      end
    end
  end
end
