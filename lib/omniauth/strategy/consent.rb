module OmniAuth
  module Strategy
    # An optional approval for sharing data for one or more purposes,
    # separate from the sign-in itself. A strategy opts in by calling
    # #request_consent in its request phase, with the same key it gives
    # #remember_sign_in, and by overriding #consent_decision to return the
    # provider's answer in the callback.
    #
    # The purposes are stored in the sign-in, so a callback gets only the
    # purposes registered by the request that it completes, never another
    # sign-in's. A login that doesn't call #request_consent has no receipt.
    module Consent
      APPROVED = 'approved'.freeze
      PENDING = 'pending'.freeze
      CANCELLED = 'cancelled'.freeze
      STATUSES = [APPROVED, PENDING, CANCELLED].freeze

      # Registers the purposes and the claims requested for them under the
      # sign-in keyed by key, which the provider sends back to the callback.
      # purposes maps a purpose to the claims requested for it, as strings
      # or symbols; an array of purposes requests them without claims. data,
      # if given, holds the strategy's own values for the sign-in, as with
      # #remember_sign_in, and is merged with any values already remembered
      # for this key. Call it after any other #remember_sign_in for the same
      # key, or pass that data here.
      def request_consent(key, purposes, data = nil)
        return unless key.is_a?(String) && !key.empty?

        sign_in = remembered_sign_ins[key]
        sign_in = sign_in ? sign_in.dup : {}
        sign_in = sign_in.merge(data) if data
        sign_in['consent'] = {
          'provider' => name,
          'purposes' => normalize_consent_purposes(purposes)
        }
        remember_sign_in(key, sign_in)
      end

      # The provider's answer to #request_consent, as a hash from purpose
      # to its decision, for a strategy that requests consent to override.
      # A decision is a status, an array of the approved claims, or a hash
      # with a status and its approved and declined claims:
      #
      #   {'directory' => {'status' => 'approved',
      #                    'claims' => ['organization_name'],
      #                    'declined_claims' => ['contact_email']}}
      #
      # The status is 'approved', 'pending', or 'cancelled'. A purpose
      # without a decision stays pending. OmniAuth ignores a purpose or
      # claim that wasn't requested at the start, so the callback can't
      # widen the approval.
      def consent_decision
        {}
      end

      # The receipt for this callback's consent request, or nil when the
      # request that this callback completes didn't request consent. The
      # default #callback_phase puts it in env['omniauth.consent']; a
      # strategy that overrides #callback_phase can pass it to the app
      # itself. It's the same object for the whole callback.
      def consent_receipt
        return @consent_receipt if instance_variable_defined?(:@consent_receipt) && !@consent_receipt.nil?

        @consent_receipt = (@consent_request ? build_consent_receipt(@consent_request) : nil)
      end

    protected

      # Builds the receipt from the consent registered for the callback's
      # sign-in. Approvals are honored only when the callback's auth hash
      # names the registered provider and has a uid, so a login that doesn't
      # confirm the identity leaves every purpose pending.
      def build_consent_receipt(consent)
        provider = consent['provider']
        requested = consent['purposes'].is_a?(Hash) ? consent['purposes'] : {}
        # Reuse the auth hash the app gets, so the claims are attributed to
        # the identity the callback actually delivers.
        auth = env['omniauth.auth'] || auth_hash
        uid = auth.uid
        uid = uid.to_s unless uid.nil?
        confirmed = !uid.to_s.empty? && auth.provider.to_s.eql?(provider.to_s)
        decision = confirmed ? consent_decision : {}
        purposes = normalize_consent_decision(requested, decision)
        purposes.each_value { |entry| entry['provider'] = provider }
        ConsentReceipt.new(:provider => provider, :uid => uid, :identity_confirmed => confirmed, :purposes => purposes)
      end

    private

      # A hash of purpose name to its requested claims, in strings, leaving
      # out a blank purpose and a repeated claim. An array of purposes means
      # no claims were requested for them.
      def normalize_consent_purposes(purposes)
        pairs = purposes.is_a?(Hash) ? purposes : Array(purposes).collect { |purpose| [purpose, []] }
        pairs.each_with_object({}) do |(purpose, claims), normalized|
          name = purpose.to_s
          normalized[name] = normalize_consent_claims(claims) unless name.empty?
        end
      end

      # The purpose's decision, looked up by string or symbol, normalized to
      # a hash with its status and claim lists. Only claims requested at the
      # start can appear in any of them, so the callback can't widen the
      # approval.
      def normalize_consent_decision(requested, decision)
        decision = {} unless decision.is_a?(Hash)
        requested.each_with_object({}) do |(purpose, requested_claims), normalized|
          entry = normalize_consent_entry(consent_value(decision, purpose))
          status = normalize_consent_status(entry['status'])
          approved, declined = consent_claims_for(status, entry, requested_claims)
          normalized[purpose] = {
            'status' => status,
            'requested_claims' => requested_claims,
            'claims' => approved,
            'declined_claims' => declined,
            'pending_claims' => requested_claims - approved - declined
          }
        end
      end

      # The value under key in a hash that may use strings or symbols.
      def consent_value(hash, key)
        hash.key?(key) ? hash[key] : hash[key.to_sym]
      end

      # A decision can be a status, an array of approved claims, or a hash
      # with a status and its approved and declined claims.
      def normalize_consent_entry(raw)
        case raw
        when Array
          {'status' => APPROVED, 'claims' => raw, 'declined_claims' => nil}
        when Hash
          {
            'status' => consent_value(raw, 'status'),
            'claims' => consent_value(raw, 'claims'),
            'declined_claims' => consent_value(raw, 'declined_claims')
          }
        when String, Symbol
          {'status' => raw, 'claims' => nil, 'declined_claims' => nil}
        else
          {'status' => PENDING, 'claims' => nil, 'declined_claims' => nil}
        end
      end

      # An unrecognized status is treated as pending, the conservative
      # choice: nothing is shared until the provider clearly approves it.
      def normalize_consent_status(status)
        name = status.to_s
        STATUSES.include?(name) ? name : PENDING
      end

      # The requested claims the decision approves and declines. Declining
      # the purpose declines all of its requested claims. Approving it can
      # still report some claims as declined, as when the user allows an
      # organization name but not contact details.
      def consent_claims_for(status, entry, requested)
        return [[], requested] if status.eql?(CANCELLED)
        return [[], []] unless status.eql?(APPROVED)

        declined = requested & normalize_consent_claims(entry['declined_claims'])
        [consent_approved_claims(entry['claims'], requested) - declined, declined]
      end

      # Without an explicit list, approving the purpose approves every
      # requested claim it doesn't decline.
      def consent_approved_claims(claims, requested)
        return requested if claims.nil?

        requested & normalize_consent_claims(claims)
      end

      # The claims as a list of non-empty strings, without repeats. A single
      # claim can be given without an array.
      def normalize_consent_claims(claims)
        list = claims.is_a?(Array) ? claims : [claims]
        list.collect(&:to_s).reject(&:empty?).uniq
      end
    end
  end
end
