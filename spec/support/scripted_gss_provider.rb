# A GSS provider that runs entirely in memory, with no network or real authentication protocol behind it. It is used to
# drive the multi-provider routing and state machine deterministically: each received token is recorded, the step
# counter is exposed, and the Result each step returns can be scripted. Two providers with distinct mechanism OIDs can
# be offered through a RubySMB::Gss::Provider::Multi to exercise selection, continuation, failure and reset.
class ScriptedGssProvider < RubySMB::Gss::Provider::Base
  # One recorded interaction with a scripted authenticator.
  Call = Struct.new(:step, :kind, :buffer, :result, keyword_init: true)

  # The authenticator created per client. Instances register themselves with the owning provider so a spec can assert
  # that a provider which was advertised but never selected was never instantiated.
  class Authenticator < RubySMB::Gss::Provider::Authenticator::Base
    attr_reader :calls, :resets

    def initialize(provider, server_client)
      @calls = []
      @resets = 0
      @step = 0
      super
      @provider.authenticators << self
    end

    def reset!
      super
      @resets += 1
      @step = 0
    end

    def process(request_buffer = nil)
      return RubySMB::Gss::Provider::Result.new(
        RubySMB::Gss.gss_neg_token_init(@provider.mech_types),
        WindowsError::NTStatus::STATUS_SUCCESS
      ) if request_buffer.nil?

      @step += 1
      kind = request_buffer.b.getbyte(0) == 0x60 ? :init : :continuation
      result = @provider.scripted_result(@step, kind, request_buffer, self)
      @calls << Call.new(step: @step, kind: kind, buffer: request_buffer, result: result)
      result
    end
  end

  # @return [Array<Authenticator>] every authenticator this provider has created, across all clients.
  attr_reader :authenticators

  # @return [String] the (single) mechanism OID this provider advertises and handles.
  attr_reader :oid

  #
  # @param [String] oid the dotted OID of the mechanism this provider offers, e.g. '1.2.3.4'.
  # @param [Proc, nil] block an optional script, see {#script}.
  def initialize(oid, &block)
    @oid = oid
    @mech_type = OpenSSL::ASN1::ObjectId.new(oid)
    @authenticators = []
    @script = block
    @allow_anonymous = false
    @allow_guests = false
  end

  def new_authenticator(server_client)
    Authenticator.new(self, server_client)
  end

  def mech_types
    [@mech_type]
  end

  #
  # Provide the Result for a received token. The block is called with the 1-based step number, the token kind
  # (:init or :continuation), the raw buffer and the authenticator. With no block set, every token continues the
  # exchange (STATUS_MORE_PROCESSING_REQUIRED), which is enough to model a multi-leg negotiation.
  #
  # @return [void]
  def script(&block)
    @script = block
  end

  # Invoked by the authenticator to obtain the Result it should return for a token.
  #
  # @return [Gss::Provider::Result]
  def scripted_result(step, kind, buffer, authenticator)
    if @script
      result = @script.call(step, kind, buffer, authenticator)
      return result if result.is_a?(RubySMB::Gss::Provider::Result)
    end

    RubySMB::Gss::Provider::Result.new(
      "#{@oid}:#{step}:#{kind}",
      WindowsError::NTStatus::STATUS_MORE_PROCESSING_REQUIRED
    )
  end
end
