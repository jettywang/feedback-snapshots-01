RSpec.describe RubySMB::Gss::Provider::Multi do
  let(:username) { 'RubySMB' }
  let(:domain) { 'WORKGROUP' }
  let(:password) { 'password' }
  let(:ntlm_provider) do
    RubySMB::Gss::Provider::NTLM.new.tap { |provider| provider.put_account(username, password, domain: domain) }
  end
  let(:other_authenticator) { double('authenticator', process: nil, reset!: nil, session_key: nil) }
  # a stand-in for any non-NTLM mechanism, so the routing can be exercised without a second real provider
  let(:other_provider) do
    authenticator = other_authenticator
    Class.new(RubySMB::Gss::Provider::Base) do
      define_method(:mech_types) do
        [RubySMB::Gss::OID_KERBEROS_5, RubySMB::Gss::OID_MICROSOFT_KERBEROS_5]
      end

      define_method(:new_authenticator) { |_server_client| authenticator }
    end.new
  end
  let(:server_client) { double('server_client', logger: Logger.new(IO::NULL)) }

  # referenced explicitly rather than via described_class, which resolves to the authenticator inside the nested group
  subject(:provider) { RubySMB::Gss::Provider::Multi.new([other_provider, ntlm_provider]) }

  describe '#initialize' do
    it 'requires at least one provider' do
      expect { RubySMB::Gss::Provider::Multi.new([]) }.to raise_error(ArgumentError)
      expect { RubySMB::Gss::Provider::Multi.new(nil) }.to raise_error(ArgumentError)
    end
  end

  describe '#mech_types' do
    it 'advertises every mechanism of every provider' do
      expect(provider.mech_types.map(&:oid)).to eq(
        [
          RubySMB::Gss::OID_KERBEROS_5.oid,
          RubySMB::Gss::OID_MICROSOFT_KERBEROS_5.oid,
          RubySMB::Gss::OID_NTLMSSP.oid
        ]
      )
    end

    it 'preserves the order the providers were given in' do
      reversed = RubySMB::Gss::Provider::Multi.new([ntlm_provider, other_provider])
      expect(reversed.mech_types.first.oid).to eq(RubySMB::Gss::OID_NTLMSSP.oid)
    end

    it 'advertises a mechanism supported by two providers only once' do
      duplicated = RubySMB::Gss::Provider::Multi.new([ntlm_provider, RubySMB::Gss::Provider::NTLM.new])
      expect(duplicated.mech_types.length).to eq(1)
    end
  end

  describe '#provider_for' do
    it 'finds the provider that handles the mechanism' do
      expect(provider.provider_for(RubySMB::Gss::OID_KERBEROS_5)).to be(other_provider)
      expect(provider.provider_for(RubySMB::Gss::OID_NTLMSSP)).to be(ntlm_provider)
    end

    it 'is nil when no provider handles the mechanism' do
      expect(provider.provider_for(RubySMB::Gss::OID_NEGOEX)).to be_nil
    end
  end

  describe 'access policy' do
    it 'does not aggregate anonymous or guest policy across providers' do
      permissive = RubySMB::Gss::Provider::NTLM.new(allow_anonymous: true, allow_guests: true)
      strict = RubySMB::Gss::Provider::NTLM.new
      multi = described_class.new([permissive, strict])

      # a permissive provider must not make the Multi provider permissive on its behalf
      expect(multi.allow_anonymous).to be_falsey
      expect(multi.allow_guests).to be_falsey
      # and the strict provider keeps its own, stricter policy
      expect(strict.allow_anonymous).to be false
      expect(strict.allow_guests).to be false
    end

    it 'still exposes the Base accessors on the Multi provider itself' do
      multi = described_class.new([ntlm_provider])
      multi.allow_anonymous = true
      multi.allow_guests = true
      expect(multi.allow_anonymous).to be true
      expect(multi.allow_guests).to be true
    end
  end

  describe RubySMB::Gss::Provider::Multi::Authenticator do
    subject(:authenticator) { provider.new_authenticator(server_client) }

    describe '#process' do
      context 'when building the advertisement' do
        it 'offers all of the mechanisms' do
          buffer = authenticator.process(nil).buffer
          expect(buffer).to eq(RubySMB::Gss.gss_neg_token_init(provider.mech_types))
        end

        it 'matches the underlying provider when only one is held' do
          single = described_class.new(RubySMB::Gss::Provider::Multi.new([ntlm_provider]), server_client)
          expect(single.process(nil).buffer).to eq(ntlm_provider.new_authenticator(server_client).process(nil).buffer)
        end

        it 'succeeds' do
          expect(authenticator.process(nil).nt_status).to eq(WindowsError::NTStatus::STATUS_SUCCESS)
        end
      end

      context 'when the client selects a mechanism' do
        it 'routes the token to the provider that handles it' do
          expect(other_authenticator).to receive(:process)
          authenticator.process(gss_init(RubySMB::Gss::OID_KERBEROS_5))
        end

        it 'routes an NTLM token to the NTLM provider' do
          type1 = Net::NTLM::Message::Type1.new.tap { |msg| msg.domain = domain }
          result = authenticator.process(RubySMB::Gss.gss_type1(type1.serialize))
          expect(result.nt_status).to eq(WindowsError::NTStatus::STATUS_MORE_PROCESSING_REQUIRED)
        end

        it 'refuses a mechanism no provider handles' do
          expect(authenticator.process(gss_init(RubySMB::Gss::OID_NEGOEX))).to be_nil
        end
      end

      context 'when the client continues an exchange' do
        it 'refuses a continuation before a mechanism has been selected' do
          # a NegTokenResp carries no mechanism OID, so there is nothing to route on
          expect(authenticator.process(RubySMB::Gss.gss_type3('anything'))).to be_nil
        end
      end

      it 'returns nil for a malformed request' do
        expect(authenticator.process('not asn1 at all')).to be_nil
      end
    end

    describe 'a complete NTLM exchange' do
      it 'authenticates the same as the NTLM provider on its own' do
        expect(complete_ntlm_exchange(authenticator)).to eq(
          complete_ntlm_exchange(ntlm_provider.new_authenticator(server_client))
        )
      end

      it 'succeeds for a known account' do
        status, identity = complete_ntlm_exchange(authenticator)
        expect(status).to eq(WindowsError::NTStatus::STATUS_SUCCESS)
        expect(identity).to eq("#{domain}\\#{username}")
      end

      it 'exposes the session key of the mechanism that authenticated' do
        complete_ntlm_exchange(authenticator)
        expect(authenticator.session_key).to_not be_nil
      end
    end

    describe '#reset!' do
      it 'forgets the selected mechanism' do
        complete_ntlm_exchange(authenticator)
        authenticator.reset!
        expect(authenticator.session_key).to be_nil
        # with no mechanism selected, a continuation token has nothing to route to
        expect(authenticator.process(RubySMB::Gss.gss_type3('anything'))).to be_nil
      end
    end
  end

  # Two fully offline providers, each advertising a distinct mechanism, used to drive the multi-provider state machine
  # without any network or real authentication protocol.
  describe 'multi-provider mechanism routing and state', order: :defined do
    let(:mech_a) { '1.2.3.4.1' }
    let(:mech_b) { '1.2.3.4.2' }
    let(:provider_a) { ScriptedGssProvider.new(mech_a) }
    let(:provider_b) { ScriptedGssProvider.new(mech_b) }
    let(:multi) { RubySMB::Gss::Provider::Multi.new([provider_a, provider_b]) }
    let(:server_client) { double('server_client', logger: Logger.new(IO::NULL)) }
    let(:authenticator) { multi.new_authenticator(server_client) }

    def init_token(oid)
      OpenSSL::ASN1::ASN1Data.new(
        [
          RubySMB::Gss::OID_SPNEGO,
          OpenSSL::ASN1::ASN1Data.new(
            [
              OpenSSL::ASN1::Sequence.new(
                [
                  OpenSSL::ASN1::ASN1Data.new([OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::ObjectId.new(oid)])], 0, :CONTEXT_SPECIFIC),
                  OpenSSL::ASN1::ASN1Data.new([OpenSSL::ASN1::OctetString.new('')], 2, :CONTEXT_SPECIFIC)
                ]
              )
            ], 0, :CONTEXT_SPECIFIC)
        ], 0, :APPLICATION
      ).to_der
    end

    def continuation_token(payload = 'continuation')
      RubySMB::Gss.gss_type3(payload)
    end

    describe 'advertising and selection' do
      it 'advertises both mechanisms in provider order' do
        expect(authenticator.process(nil).buffer).to eq(
          RubySMB::Gss.gss_neg_token_init(multi.mech_types)
        )
        expect(multi.mech_types.map(&:oid)).to eq([mech_a, mech_b])
      end

      it 'instantiates only the provider whose mechanism is selected' do
        authenticator.process(init_token(mech_b))
        expect(provider_a.authenticators).to be_empty
        expect(provider_b.authenticators.size).to eq(1)
        expect(authenticator.selected_provider).to be(provider_b)
      end

      it 'refuses a mechanism no provider handles without instantiating anything' do
        expect(authenticator.process(init_token(RubySMB::Gss::OID_NEGOEX.oid))).to be_nil
        expect(provider_a.authenticators).to be_empty
        expect(provider_b.authenticators).to be_empty
        expect(authenticator.selected_provider).to be_nil
      end

      it 'does not disturb an in-progress negotiation when a later init names an unsupported mechanism' do
        authenticator.process(init_token(mech_a))
        expect(authenticator.process(init_token(RubySMB::Gss::OID_NEGOEX.oid))).to be_nil

        # the selected mechanism and its partial state survive, and continuations still reach it
        expect(authenticator.selected_provider).to be(provider_a)
        authenticator.process(continuation_token)
        expect(provider_a.authenticators.first.calls.map(&:kind)).to eq(%i[init continuation])
        expect(provider_b.authenticators).to be_empty
      end
    end

    describe 'continuation routing' do
      it 'delivers every continuation to the previously selected provider only' do
        authenticator.process(init_token(mech_a))
        authenticator.process(continuation_token('one'))
        authenticator.process(continuation_token('two'))

        calls = provider_a.authenticators.first.calls
        expect(calls.map(&:kind)).to eq(%i[init continuation continuation])
        expect(calls.map(&:step)).to eq([1, 2, 3])
        expect(calls.first.buffer).to eq(init_token(mech_a))
        expect(calls.drop(1).map { |call| call.buffer }).to eq(
          [continuation_token('one'), continuation_token('two')]
        )
        expect(provider_b.authenticators).to be_empty
      end

      it 'never re-tries a continuation against the other provider' do
        authenticator.process(init_token(mech_a))
        # a token whose contents look like the other mechanism is still a continuation of A
        authenticator.process(continuation_token(init_token(mech_b)))
        expect(provider_b.authenticators).to be_empty
        expect(provider_a.authenticators.first.calls.last.kind).to eq(:continuation)
      end

      it 'refuses a continuation before any mechanism has been selected' do
        expect(authenticator.process(continuation_token)).to be_nil
        expect(provider_a.authenticators).to be_empty
        expect(provider_b.authenticators).to be_empty
      end
    end

    describe 'failure and the re-negotiation boundary' do
      it 'keeps routing continuations to the selected mechanism after a failure result' do
        provider_a.script do |step, _kind, _buffer, _auth|
          status = step == 2 ? WindowsError::NTStatus::STATUS_LOGON_FAILURE : WindowsError::NTStatus::STATUS_MORE_PROCESSING_REQUIRED
          RubySMB::Gss::Provider::Result.new("a-#{step}", status)
        end

        authenticator.process(init_token(mech_a))
        failure = authenticator.process(continuation_token)
        expect(failure.nt_status).to eq(WindowsError::NTStatus::STATUS_LOGON_FAILURE)

        # the failure does not move the client onto the other provider
        expect(authenticator.selected_provider).to be(provider_a)
        expect(provider_b.authenticators).to be_empty

        # a continuation is still a continuation of the same, failed mechanism
        authenticator.process(continuation_token)
        expect(provider_a.authenticators.first.calls.size).to eq(3)
        expect(provider_b.authenticators).to be_empty
      end

      it 'only a fresh NegTokenInit starts a new exchange, and resets the old one first' do
        authenticator.process(init_token(mech_a))
        authenticator.process(continuation_token)
        original_a = provider_a.authenticators.first
        expect(original_a.calls.size).to eq(2)

        authenticator.process(init_token(mech_b))

        # the discarded authenticator was reset and is no longer the selected one
        expect(original_a.resets).to be >= 1
        expect(authenticator.selected_provider).to be(provider_b)
        expect(provider_b.authenticators.size).to eq(1)
        # re-selecting provider A builds a fresh authenticator rather than reviving the discarded one
        authenticator.process(init_token(mech_a))
        expect(provider_a.authenticators.size).to eq(2)
        expect(authenticator.selected_provider).to be(provider_a)
        active_a = provider_a.authenticators.last
        expect(active_a).to_not be(original_a)
        expect(active_a.calls.map(&:step)).to eq([1])
      end
    end

    describe 'switching mechanisms mid-negotiation' do
      it 'does not carry partial state from the first mechanism into the second' do
        authenticator.process(init_token(mech_a))
        authenticator.process(continuation_token('a-leg-1'))
        authenticator.process(init_token(mech_a))

        # re-selecting the same mechanism starts from step one on a brand new authenticator, not the stale one
        new_a = provider_a.authenticators.last
        expect(new_a.calls.size).to eq(1)
        expect(new_a.calls.first.step).to eq(1)
        expect(new_a.calls.first.kind).to eq(:init)
        expect(provider_a.authenticators.size).to eq(2)
      end

      it 'isolates the session key to the mechanism that authenticated' do
        provider_a.script do |step, _kind, _buffer, auth|
          auth.session_key = 'key-a' if step == 2
          RubySMB::Gss::Provider::Result.new("a-#{step}", WindowsError::NTStatus::STATUS_SUCCESS)
        end

        authenticator.process(init_token(mech_a))
        authenticator.process(continuation_token)
        expect(authenticator.session_key).to eq('key-a')

        authenticator.process(init_token(mech_b))
        # the new mechanism has not authenticated yet, so the old key is not exposed through it
        expect(authenticator.session_key).to be_nil
      end
    end

    describe '#reset!' do
      it 'discards every sub-authenticator and the selected mechanism' do
        authenticator.process(init_token(mech_a))
        authenticator.process(continuation_token)
        original_a = provider_a.authenticators.first
        resets_before = original_a.resets

        authenticator.reset!

        expect(original_a.resets).to eq(resets_before + 1)
        expect(authenticator.selected_provider).to be_nil
        expect(authenticator.session_key).to be_nil
        expect(authenticator.process(continuation_token)).to be_nil

        # a later selection builds a fresh authenticator rather than reviving the discarded one
        authenticator.process(init_token(mech_a))
        expect(provider_a.authenticators.size).to eq(2)
        expect(provider_a.authenticators.last.calls.size).to eq(1)
      end
    end

    describe 'two interleaved clients' do
      let(:client_one) { multi.new_authenticator(server_client) }
      let(:client_two) { multi.new_authenticator(server_client) }

      it 'keeps each client routed to its own mechanism with its own calls' do
        client_one.process(init_token(mech_a))
        client_two.process(init_token(mech_b))

        client_one.process(continuation_token('c1-1'))
        client_two.process(continuation_token('c2-1'))
        client_one.process(continuation_token('c1-2'))

        auth_a = provider_a.authenticators.first
        auth_b = provider_b.authenticators.first
        expect(auth_a.calls.map(&:kind)).to eq(%i[init continuation continuation])
        expect(auth_b.calls.map(&:kind)).to eq(%i[init continuation])
        expect(auth_a.calls.first.buffer).to eq(init_token(mech_a))
        expect(auth_a.calls.drop(1).map(&:buffer)).to eq(
          [continuation_token('c1-1'), continuation_token('c1-2')]
        )
        expect(auth_b.calls.last.buffer).to eq(continuation_token('c2-1'))

        expect(client_one.selected_provider).to be(provider_a)
        expect(client_two.selected_provider).to be(provider_b)
      end

      it 'gives each client an independent authenticator instance and session identity' do
        provider_a.script do |step, _kind, _buffer, auth|
          auth.session_key = "key-one-#{step}"
          RubySMB::Gss::Provider::Result.new('ok', WindowsError::NTStatus::STATUS_SUCCESS,
                                             "domain\\user-a-#{step}", false)
        end
        provider_b.script do |step, _kind, _buffer, auth|
          auth.session_key = "key-two-#{step}"
          RubySMB::Gss::Provider::Result.new('ok', WindowsError::NTStatus::STATUS_SUCCESS,
                                             "domain\\user-b-#{step}", false)
        end

        result_one = client_one.process(init_token(mech_a))
        result_two = client_two.process(init_token(mech_b))

        expect(result_one.identity).to eq('domain\user-a-1')
        expect(result_two.identity).to eq('domain\user-b-1')
        expect(client_one.session_key).to eq('key-one-1')
        expect(client_two.session_key).to eq('key-two-1')
        expect(provider_a.authenticators).to_not include(provider_b.authenticators.first)
      end

      it 'resetting one client does not touch the other' do
        client_one.process(init_token(mech_a))
        client_two.process(init_token(mech_b))
        auth_a = provider_a.authenticators.first
        auth_b = provider_b.authenticators.first
        resets_a_before = auth_a.resets
        resets_b_before = auth_b.resets
        client_one.reset!

        expect(client_one.selected_provider).to be_nil
        expect(client_two.selected_provider).to be(provider_b)
        client_two.process(continuation_token('still-b'))
        expect(auth_b.calls.size).to eq(2)
        expect(auth_a.resets).to eq(resets_a_before + 1)
        expect(auth_b.resets).to eq(resets_b_before)
      end
    end

    describe 'guest isolation across two providers handling the same mechanism' do
      let(:strict_ntlm) { RubySMB::Gss::Provider::NTLM.new }
      let(:guest_ntlm) { RubySMB::Gss::Provider::NTLM.new(allow_guests: true) }

      def ntlm_logon(authenticator)
        authenticator.process(nil)
        type1 = Net::NTLM::Message::Type1.new.tap { |msg| msg.domain = domain }
        challenge = authenticator.process(RubySMB::Gss.gss_type1(type1.serialize))
        raw_type2 = RubySMB::Gss.asn1dig(OpenSSL::ASN1.decode(challenge.buffer), 0, 2, 0).value
        type2 = Net::NTLM::Message.parse(raw_type2)
        type3 = type2.response({ user: 'UnknownUser', password: 'whatever', domain: domain }, { ntlmv2: true })
        authenticator.process(RubySMB::Gss.gss_type3(type3.serialize))
      end

      it 'does not downgrade a logon against the strict provider to a guest' do
        # the strict provider is first, so it handles the shared NTLM mechanism; the guest-enabled provider is never
        # consulted, and its more permissive policy must not rescue the strict provider's failure
        strict_first = RubySMB::Gss::Provider::Multi.new([strict_ntlm, guest_ntlm])
        result = ntlm_logon(strict_first.new_authenticator(server_client))

        expect(result.nt_status).to eq(WindowsError::NTStatus::STATUS_LOGON_FAILURE)
        expect(result.identity).to be_nil
        # a failure carries no guest or anonymous identity
        expect(result.is_guest).to be_falsey
        expect(result.is_anonymous).to be false
      end

      it 'grants a guest only when the selected provider itself allows guests' do
        guest_first = RubySMB::Gss::Provider::Multi.new([guest_ntlm, strict_ntlm])
        result = ntlm_logon(guest_first.new_authenticator(server_client))

        expect(result.nt_status).to eq(WindowsError::NTStatus::STATUS_SUCCESS)
        expect(result.is_guest).to be true
        expect(result.is_anonymous).to be false
        expect(result.identity).to eq("#{domain}\\UnknownUser")
      end
    end
  end

  # Build a NegTokenInit that selects the specified mechanism, with an empty mechToken.
  def gss_init(mech_type)
    OpenSSL::ASN1::ASN1Data.new(
      [
        RubySMB::Gss::OID_SPNEGO,
        OpenSSL::ASN1::ASN1Data.new(
          [
            OpenSSL::ASN1::Sequence.new(
              [
                OpenSSL::ASN1::ASN1Data.new([OpenSSL::ASN1::Sequence.new([mech_type])], 0, :CONTEXT_SPECIFIC),
                OpenSSL::ASN1::ASN1Data.new([OpenSSL::ASN1::OctetString.new('')], 2, :CONTEXT_SPECIFIC)
              ]
            )
          ], 0, :CONTEXT_SPECIFIC
        )
      ], 0, :APPLICATION
    ).to_der
  end

  # Drive a full NTLM negotiation through the authenticator, returning the final status and identity.
  def complete_ntlm_exchange(authenticator)
    authenticator.process(nil)
    type1 = Net::NTLM::Message::Type1.new.tap { |msg| msg.domain = domain }
    challenge_result = authenticator.process(RubySMB::Gss.gss_type1(type1.serialize))
    raw_type2 = RubySMB::Gss.asn1dig(OpenSSL::ASN1.decode(challenge_result.buffer), 0, 2, 0).value
    type2 = Net::NTLM::Message.parse(raw_type2)
    type3 = type2.response({ user: username, password: password, domain: domain }, { ntlmv2: true })
    result = authenticator.process(RubySMB::Gss.gss_type3(type3.serialize))
    [result.nt_status, result.identity]
  end
end
