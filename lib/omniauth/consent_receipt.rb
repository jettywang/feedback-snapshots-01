module OmniAuth
  # The outcome of a strategy's optional request to share data for one or
  # more purposes, handed to the app as env['omniauth.consent'] on the
  # callback. It's kept apart from the auth hash, so a login and an
  # additional approval stay independent: an ordinary login has no receipt,
  # and confirming the identity doesn't grant any purpose.
  #
  # Each purpose has a status and the claims approved for it. A purpose the
  # provider approved is in #approved, with only the claims that were both
  # requested at the start and returned as approved. A purpose the user
  # declined is in #cancelled, and one the provider didn't answer is in
  # #pending.
  class ConsentReceipt
    # The provider that registered the request, the uid of the identity that
    # confirmed it (or nil), whether that identity is confirmed, and the
    # normalized result for each purpose.
    attr_reader :provider, :uid, :purposes

    def initialize(provider:, uid:, identity_confirmed:, purposes:)
      @provider = provider
      @uid = uid
      @identity_confirmed = identity_confirmed
      @purposes = purposes
    end

    # True when the callback's auth hash names the registered provider and
    # has a uid. Login succeeds separately from the consent decision, so
    # this can be true while every purpose is still pending.
    def identity_confirmed?
      @identity_confirmed
    end
    alias confirmed? identity_confirmed?

    # The approved purposes, each mapped to the provider that registered
    # the request and the claims it approved.
    def approved
      purposes.each_with_object({}) do |(purpose, entry), result|
        next unless entry['status'].eql?('approved')

        result[purpose] = {'provider' => entry['provider'], 'claims' => entry['claims']}
      end
    end

    # The purposes the provider didn't answer, which still need consent.
    def pending
      purposes.keys.select { |purpose| purposes[purpose]['status'].eql?('pending') }
    end

    # The purposes the user declined.
    def cancelled
      purposes.keys.select { |purpose| purposes[purpose]['status'].eql?('cancelled') }
    end

    # The status of one purpose: 'approved', 'pending', 'cancelled', or nil
    # when the request never included it.
    def status_for(purpose)
      entry = purpose_entry(purpose)
      entry && entry['status']
    end

    # The claims approved for one purpose, or an empty array.
    def claims_for(purpose)
      purpose_entry(purpose)['claims']
    end

    # The requested claims the user declined for one purpose. They weren't
    # approved, even when the purpose as a whole was approved.
    def declined_claims_for(purpose)
      purpose_entry(purpose)['declined_claims']
    end

    # The requested claims the provider didn't answer for one purpose.
    def pending_claims_for(purpose)
      purpose_entry(purpose)['pending_claims']
    end

    def approved?(purpose)
      status_for(purpose).eql?('approved')
    end

    def cancelled?(purpose)
      status_for(purpose).eql?('cancelled')
    end

    def pending?(purpose)
      status_for(purpose).eql?('pending')
    end

    # The status of every requested purpose, without the claim details.
    def statuses
      purposes.each_with_object({}) do |(purpose, entry), result|
        result[purpose] = entry['status']
      end
    end

    def to_hash
      {
        'identity' => {
          'confirmed' => identity_confirmed?,
          'provider' => provider,
          'uid' => uid
        },
        'approved' => approved,
        'pending' => pending,
        'cancelled' => cancelled,
        'purposes' => purposes
      }
    end
    alias to_h to_hash

  private

    # A blank entry for a purpose the request didn't include, so a caller
    # gets empty lists and a nil status without checking.
    def purpose_entry(purpose)
      purposes[purpose.to_s] || {'claims' => [], 'declined_claims' => [], 'pending_claims' => []}
    end
  end
end
