# frozen_string_literal: true

require 'base64'
require 'digest'
require 'openssl'
require 'monitor'
require 'securerandom'
require 'time'

module Sorcery
  module Model
    # A generation-scoped lifecycle policy for password reset credentials.
    #
    # The policy signs each reset token with the secret of the generation that
    # issued it. Tokens issued by an older generation remain verifiable while
    # that generation is explicitly admitted (for example during a short grace
    # period), and stop verifying once the generation is retired. New tokens are
    # always issued by the current generation.
    #
    # The policy never writes credentials, token digests or generation secrets to
    # its diagnostics. Diagnostics contain generation identifiers, event names
    # and outcomes only.
    class ResetPasswordTokenPolicy
      # Raised for invalid policy configuration or lifecycle transitions.
      class Error < Sorcery::Error; end

      TOKEN_PREFIX = 'rp1'
      TOKEN_PATTERN = /\A#{TOKEN_PREFIX}\.([A-Za-z0-9_-]{1,64})\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\z/.freeze
      GENERATION_ID_PATTERN = /\A[A-Za-z0-9_-]{1,64}\z/.freeze
      STATES = %i[active pending retiring retired].freeze

      # A single rotation generation. Secrets are intentionally excluded from
      # #to_h and #inspect so the object can be logged safely.
      class Generation
        attr_reader :id, :state, :retire_at

        def initialize(id:, secret:, state: :active, retire_at: nil)
          @id = id.to_s
          @secret = secret.to_s
          @state = state.to_s.to_sym
          @retire_at = normalize_time(retire_at)

          raise Error, 'generation id must match [A-Za-z0-9_-]{1,64}' unless GENERATION_ID_PATTERN.match?(@id)
          raise Error, "generation #{@id.inspect} must have a non-empty secret" if @secret.empty?
          raise Error, "generation #{@id.inspect} has an invalid state #{@state.inspect}" unless STATES.include?(@state)
        end

        def secret
          @secret
        end

        def active?
          state == :active
        end

        def pending?
          state == :pending
        end

        def retiring?
          state == :retiring
        end

        def retired?
          state == :retired
        end

        def issueable?
          state == :active
        end

        def admitted?(now = Time.now)
          return true if state == :active || state == :pending
          return false unless retiring?

          retire_at.nil? || now < retire_at
        end

        def transition!(new_state, retire_at: nil)
          new_state = new_state.to_sym
          raise Error, "invalid generation state #{new_state.inspect}" unless STATES.include?(new_state)

          @state = new_state
          @retire_at = normalize_time(retire_at)
          self
        end

        def to_h
          { id: id, state: state, retire_at: retire_at&.utc&.iso8601(6) }
        end

        def inspect
          "#<#{self.class.name} id=#{id.inspect} state=#{state.inspect}>"
        end

        private

        def normalize_time(value)
          return value if value.nil? || value.is_a?(Time)
          return value.to_time if value.respond_to?(:to_time)

          raise Error, "invalid retire_at value #{value.inspect}"
        end
      end

      # A credential prepared for persistence. The credential is available to
      # the caller that needs to put it in an email, but is never present in
      # #to_h, #inspect or diagnostics.
      class Issuance
        attr_reader :credential, :generation_id, :issued_at

        def initialize(credential:, generation_id:, issued_at:)
          @credential = credential
          @generation_id = generation_id
          @issued_at = issued_at
          freeze
        end

        def to_h
          { generation_id: generation_id, issued_at: issued_at.utc.iso8601(6) }
        end

        def inspect
          "#<#{self.class.name} generation_id=#{generation_id.inspect}>"
        end
      end

      # Result of classifying a presented credential. Does not include the
      # credential itself.
      class Resolution
        attr_reader :status, :generation_id

        def initialize(status:, generation_id: nil, legacy: false)
          @status = status
          @generation_id = generation_id
          @legacy = legacy
        end

        def ok?
          %i[ok legacy].include?(status)
        end

        def legacy?
          @legacy
        end

        def to_h
          { status: status, generation_id: generation_id, legacy: legacy? }
        end

        def inspect
          "#<#{self.class.name} status=#{status.inspect} generation_id=#{generation_id.inspect}>"
        end
      end

      attr_reader :current_id, :legacy_generation_id

      # Updates the legacy admission rule without rebuilding the policy. Accepts
      # true/false, a callable receiving the presented credential, or an array of
      # SHA-256 digests of admitted legacy credentials.
      def admit_legacy=(value)
        @mutex.synchronize { @admit_legacy = normalize_admission(value) }
      end

      def admit_legacy?
        @admit_legacy != false && !legacy_retired?
      end

      attr_reader :legacy_admitted_until

      # Sets or clears the moment after which legacy credentials are no longer
      # admitted. Nil keeps the current admission rule without a time bound.
      def legacy_admitted_until=(value)
        @mutex.synchronize { @legacy_admitted_until = normalize_time(value) }
      end

      def initialize(generations:, current: nil, admit_legacy: false, legacy_admitted_until: nil,
                     token_randomness: 15, diagnostic_limit: 100, clock: nil, logger: nil,
                     legacy_generation_id: 'legacy')
        @generations = {}
        generation_specs(generations).each { |spec| add_generation(spec) }
        raise Error, 'at least one generation is required' if @generations.empty?

        @current_id = select_current_id(current)
        @admit_legacy = normalize_admission(admit_legacy)
        @legacy_admitted_until = normalize_time(legacy_admitted_until)
        @token_randomness = Integer(token_randomness)
        @diagnostic_limit = Integer(diagnostic_limit)
        @legacy_generation_id = legacy_generation_id.to_s
        raise Error, 'token_randomness must be positive' unless @token_randomness.positive?
        raise Error, 'diagnostic_limit must be positive' unless @diagnostic_limit.positive?
        raise Error, "legacy generation id #{@legacy_generation_id.inspect} collides with a real generation" if @generations.key?(@legacy_generation_id)
        @clock = clock || -> { Time.now }
        @logger = logger
        @mutex = Monitor.new
        @registry = {}
        @diagnostics = []
        @redeemed_legacy = {}
      end

      def generation_ids
        @mutex.synchronize { @generations.keys }
      end

      # Returns the generation that new credentials are signed with, or nil when
      # no generation is currently allowed to issue.
      def current_generation
        generation = @generations[current_id]
        generation if generation&.issueable?
      end

      # Prepares a signed credential without persisting or registering it.
      # Returns nil when no generation is allowed to issue.
      def build_issuance
        refresh!
        generation = current_generation
        return nil unless generation

        build_issuance_for(generation)
      end

      # Prepares a signed credential for a specific generation. Used by
      # #rotate_with_retiring_issuance! to finish in-flight work.
      def build_issuance_for(generation)
        raw = SecureRandom.urlsafe_base64(@token_randomness).tr('lIO0', 'sxyz')
        credential = "#{TOKEN_PREFIX}.#{generation.id}.#{raw}.#{sign(generation, raw)}"
        Issuance.new(credential: credential, generation_id: generation.id, issued_at: current_time)
      end

      # Records a successfully persisted issuance in the registry.
      def record_issued(issuance)
        @mutex.synchronize do
          stat = (@registry[issuance.generation_id] ||= { issued_count: 0, first_issued_at: nil, last_issued_at: nil })
          stat[:issued_count] += 1
          stat[:first_issued_at] ||= issuance.issued_at
          stat[:last_issued_at] = issuance.issued_at
        end
        event(:issued, generation_id: issuance.generation_id)
      end

      # Records an issuance that did not persist. Accepts nil when no generation
      # could issue. No credential is accepted or logged.
      def record_issue_failure(issuance, reason:)
        event(:issue_failed, generation_id: issuance&.generation_id, reason: reason)
      end

      # Classifies a credential and reports the generation that signed it.
      # The presented credential is never stored in the resolution.
      def resolve(token)
        refresh!
        return Resolution.new(status: :invalid_token) if token.nil? || token.to_s.empty?

        match = TOKEN_PATTERN.match(token.to_s)
        return resolve_legacy(token) unless match

        generation_id, raw, mac = match.captures
        generation = @generations[generation_id]
        return Resolution.new(status: :unknown_generation) unless generation
        return Resolution.new(status: :invalid_signature, generation_id: generation.id) unless valid_signature?(generation, raw, mac)
        return Resolution.new(status: :token_retired, generation_id: generation.id) unless generation.admitted?(current_time)

        Resolution.new(status: :ok, generation_id: generation.id)
      end

      # Marks an admitted legacy token as redeemed. Returns false when it was
      # already redeemed, so a concurrent replay cannot both win.
      def redeem_legacy!(token)
        digest = Digest::SHA256.hexdigest(token.to_s)
        @mutex.synchronize do
          return false if @redeemed_legacy[digest]

          @redeemed_legacy[digest] = current_time
          event(:legacy_redeemed, generation_id: legacy_generation_id)
          true
        end
      end

      # Records a lookup outcome. Successful non-legacy lookups are not logged
      # to keep diagnostics focused on lifecycle transitions and rejections.
      def record_lookup(resolution)
        case resolution.status
        when :legacy
          event(:legacy_admitted, generation_id: resolution.generation_id)
        when :token_retired, :legacy_not_admitted, :legacy_already_used, :unknown_generation, :invalid_signature
          event(:lookup_rejected, generation_id: resolution.generation_id, reason: resolution.status)
        end
      end

      # Moves the current marker to +generation_id+. The previous current
      # generation is retired immediately, or enters a short retiring grace
      # period when +grace_period+ is given.
      def rotate!(generation_id, grace_period: nil)
        @mutex.synchronize do
          previous_id = promote_current!(generation_id, grace_period)
          event(:rotated, generation_id: current_id, previous_generation_id: previous_id)
        end
        self
      end

      # Rotates to +generation_id+ while returning an issuance prepared by the
      # generation that was current before the rotation. Callers that already
      # started issuing are not left without a usable credential when another
      # thread refreshes the policy mid-flight.
      def rotate_with_retiring_issuance!(generation_id, grace_period: nil)
        previous_issuance = nil
        @mutex.synchronize do
          previous_generation = current_generation
          previous_issuance = build_issuance_for(previous_generation) if previous_generation
          previous_id = promote_current!(generation_id, grace_period)
          event(:rotated, generation_id: current_id, previous_generation_id: previous_id)
        end
        previous_issuance
      end

      # Retires a generation immediately, or schedules its retirement after
      # +after+ seconds. A retiring generation still verifies credentials until
      # its retire_at moment.
      def retire!(generation_id, after: nil)
        @mutex.synchronize do
          generation = @generations[generation_id.to_s]
          raise Error, "unknown generation #{generation_id.inspect}" unless generation

          if after
            generation.transition!(:retiring, retire_at: current_time + after)
            event(:retirement_scheduled, generation_id: generation.id, retire_at: generation.retire_at)
          else
            generation.transition!(:retired, retire_at: current_time)
            event(:retired, generation_id: generation.id)
          end

          @current_id = newest_active_id if @current_id == generation.id
        end
        self
      end

      # Applies time-based retirement to retiring generations. Safe to call
      # before issuance, lookup and status reads.
      def refresh!
        moment = current_time
        @mutex.synchronize do
          @generations.each_value do |generation|
            next unless generation.retiring? && generation.retire_at && generation.retire_at <= moment

            generation.transition!(:retired, retire_at: generation.retire_at)
            event(:retired, generation_id: generation.id)
          end
        end
        self
      end

      # Safe, token-free registration of generations and issuance counts.
      def registry
        @mutex.synchronize do
          entries = @generations.values.map do |generation|
            stat = @registry[generation.id] || {}
            generation.to_h.merge(
              current: generation.id == current_id,
              issued_count: stat[:issued_count] || 0,
              first_issued_at: stat[:first_issued_at]&.utc&.iso8601(6),
              last_issued_at: stat[:last_issued_at]&.utc&.iso8601(6)
            )
          end
          entries << legacy_registry_entry
        end
      end

      # Token-free lifecycle events.
      def diagnostics
        @mutex.synchronize { @diagnostics.map(&:dup) }
      end

      def inspect
        "#<#{self.class.name} current=#{current_id.inspect} generations=#{@generations.keys.inspect} " \
          "admit_legacy=#{@admit_legacy == true}>"
      end

      private

      def add_generation(spec)
        generation = case spec
                     when Generation then spec
                     when Hash then Generation.new(**spec.transform_keys(&:to_sym))
                     else raise Error, "invalid generation specification #{spec.inspect}"
                     end

        raise Error, "duplicate generation #{generation.id.inspect}" if @generations.key?(generation.id)

        @generations[generation.id] = generation
      end

      def select_current_id(requested)
        return newest_active_id if requested.nil?

        generation = @generations[requested.to_s]
        raise Error, "unknown current generation #{requested.inspect}" unless generation
        raise Error, "current generation #{generation.id.inspect} is not active" unless generation.state == :active

        generation.id
      end

      def generation_specs(specs)
        if specs.is_a?(Hash)
          return [specs.transform_keys(&:to_sym)] if specs.key?(:id) || specs.key?('id')

          return specs.map do |id, value|
            value.is_a?(Hash) ? value.merge(id: id) : { id: id, secret: value }
          end
        end

        Array(specs)
      end

      def newest_active_id
        @generations.values.reverse.find { |generation| generation.state == :active }&.id
      end

      # Promotes +generation_id+, demotes the previous current generation, and
      # returns the previous generation id.
      def promote_current!(generation_id, grace_period)
        target = @generations[generation_id.to_s]
        raise Error, "unknown generation #{generation_id.inspect}" unless target
        raise Error, "generation #{target.id.inspect} is retired" if target.retired?

        previous_id = @current_id
        previous = @generations[previous_id]
        if previous && previous.id != target.id
          if grace_period
            previous.transition!(:retiring, retire_at: current_time + grace_period)
          else
            previous.transition!(:retired, retire_at: current_time)
          end
        end

        target.transition!(:active, retire_at: nil)
        @current_id = target.id
        previous_id
      end

      def normalize_admission(value)
        case value
        when true then true
        when false, nil then false
        when Proc then value
        else Array(value)
        end
      end

      def resolve_legacy(token)
        digest = Digest::SHA256.hexdigest(token.to_s)
        @mutex.synchronize do
          return Resolution.new(status: :legacy_already_used, generation_id: legacy_generation_id, legacy: true) if @redeemed_legacy[digest]
          return Resolution.new(status: :legacy_not_admitted, generation_id: legacy_generation_id, legacy: true) unless legacy_admitted?(token)

          Resolution.new(status: :legacy, generation_id: legacy_generation_id, legacy: true)
        end
      end

      def legacy_admitted?(token)
        return false if legacy_retired?

        presented = token.to_s
        case @admit_legacy
        when true then true
        when false then false
        when Proc then !!@admit_legacy.call(presented)
        else @admit_legacy.include?(presented) || @admit_legacy.include?(Digest::SHA256.hexdigest(presented))
        end
      end

      def legacy_retired?
        !@legacy_admitted_until.nil? && current_time >= @legacy_admitted_until
      end

      def legacy_registry_entry
        admitted = @admit_legacy != false && !legacy_retired?
        {
          id: legacy_generation_id,
          state: admitted ? :legacy : :retired,
          retire_at: @legacy_admitted_until&.utc&.iso8601(6),
          current: false,
          admitted: admitted,
          issued_count: 0,
          first_issued_at: nil,
          last_issued_at: nil
        }
      end

      def valid_signature?(generation, raw, mac)
        expected = sign(generation, raw)
        return false unless expected.bytesize == mac.bytesize

        secure_compare(expected, mac)
      end

      def secure_compare(left, right)
        if OpenSSL.respond_to?(:fixed_length_secure_compare)
          OpenSSL.fixed_length_secure_compare(left, right)
        else
          left.bytes.zip(right.bytes).reduce(0) { |accumulator, (a, b)| accumulator | (a ^ b) }.zero?
        end
      end

      def sign(generation, raw)
        message = "#{TOKEN_PREFIX}.#{generation.id}.#{raw}"
        Base64.urlsafe_encode64(OpenSSL::HMAC.digest('SHA256', generation.secret, message), padding: false)
      end

      def current_time
        @clock.call
      end

      def normalize_time(value)
        return value if value.nil? || value.is_a?(Time)
        return value.to_time if value.respond_to?(:to_time)

        raise Error, "invalid time value #{value.inspect}"
      end

      def event(name, **fields)
        payload = { event: name, at: current_time.utc.iso8601(6) }.merge(fields.compact).freeze
        @mutex.synchronize do
          @diagnostics.shift if @diagnostics.size >= @diagnostic_limit
          @diagnostics << payload
        end
        @logger&.info("[sorcery.reset_password] #{payload.inspect}")
        payload
      end
    end
  end
end

module Sorcery
  # Convenience alias for the reset password credential lifecycle policy.
  ResetPasswordTokenPolicy = Model::ResetPasswordTokenPolicy
end
