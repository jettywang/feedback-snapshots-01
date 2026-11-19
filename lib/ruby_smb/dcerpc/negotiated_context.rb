module RubySMB
  module Dcerpc
    # Represents the negotiation result of a single presentation context.
    #
    # A Bind (or AlterContext) request can propose several presentation
    # contexts. Each result returned in the BindAck (or AlterContextResp)
    # packet is positionally tied to the context that was proposed at the same
    # index, so this class keeps the original abstract and transfer syntaxes
    # next to the negotiated result. Keeping them together is what makes it
    # possible to verify that an accepted context is actually usable instead of
    # assuming the first result represents the whole negotiation.
    class NegotiatedContext
      # @return [Integer] the presentation context identifier (p_cont_id)
      attr_reader :p_cont_id
      # @return [PSyntaxIdT] the abstract syntax proposed for the context
      attr_reader :abstract_syntax
      # @return [Array<PSyntaxIdT>] the transfer syntaxes proposed for the context
      attr_reader :proposed_transfer_syntaxes
      # @return [Integer] the negotiation result code
      attr_reader :result
      # @return [Integer] the rejection reason code
      attr_reader :reason
      # @return [PSyntaxIdT] the transfer syntax selected by the server
      attr_reader :transfer_syntax

      # @param context [PContElemT] the presentation context proposed by the client
      # @param p_result [PResultT] the matching negotiation result returned by the server
      def initialize(context, p_result)
        @p_cont_id = context.p_cont_id.to_i
        @abstract_syntax = context.abstract_syntax
        @proposed_transfer_syntaxes = context.transfer_syntaxes.to_a
        @result = p_result.result.to_i
        @reason = p_result.reason.to_i
        @transfer_syntax = p_result.transfer_syntax
      end

      # @return [Boolean] whether the server accepted this context
      def accepted?
        result == BindAck::ACCEPTANCE
      end

      # @return [Boolean] whether the selected transfer syntax is one the client
      #   actually proposed. This makes a swapped or spoofed result fail instead
      #   of silently being decoded with the default NDR engine.
      def transfer_syntax_supported?
        proposed_transfer_syntaxes.any? do |syntax|
          syntax.if_uuid == transfer_syntax.if_uuid &&
            syntax.if_ver_major == transfer_syntax.if_ver_major &&
            syntax.if_ver_minor == transfer_syntax.if_ver_minor
        end
      end

      # @return [Boolean] whether this context can be used to send requests
      def usable?
        accepted? && transfer_syntax_supported?
      end

      # @param endpoint [Module] an endpoint defining UUID, VER_MAJOR and VER_MINOR
      # @return [Boolean] whether this context negotiates the given endpoint abstract syntax
      def for_endpoint?(endpoint)
        abstract_syntax.if_uuid == endpoint::UUID &&
          abstract_syntax.if_ver_major == endpoint::VER_MAJOR &&
          abstract_syntax.if_ver_minor == endpoint::VER_MINOR
      end
    end
  end
end
