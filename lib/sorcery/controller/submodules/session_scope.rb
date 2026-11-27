# frozen_string_literal: true

module Sorcery
  module Controller
    module Submodules
      # SessionScope provides a narrow, session-bound authorization grant.
      #
      # A signed-in user (for example, a support agent) can be given a small set
      # of actions on one resource (for example, one organization) for the
      # lifetime of one login session. Grants live in the session only; they are
      # deliberately not written to the user or any other persistent model.
      #
      # Read access never implies write access. Each call to
      # +session_scope_decision+ re-evaluates the current grant, so a write must
      # be authorized at the moment it is submitted, not reused from the
      # decision that allowed an earlier read.
      #
      # Revoking an action keeps the session, the login and activity logging
      # untouched. It only removes that action from the narrow grant.
      module SessionScope
        GRANTS_SESSION_KEY = :sorcery_session_scope_grants
        TERMINATION_SESSION_KEY = :sorcery_session_ended_reason

        DECISION_REASONS = %i[
          allowed
          no_grant
          not_authenticated
          subject_changed
          session_expired
          session_invalidated
          grant_expired
          out_of_scope
          ambiguous_scope
          action_not_granted
          action_revoked
          scope_revoked
        ].freeze

        # Raised when a scope grant is requested without an authenticated user.
        class NotAuthenticated < Sorcery::Error; end

        # Raised by +authorize_session_scope!+ when the decision is not allowed.
        class Denied < Sorcery::Error
          attr_reader :decision

          def initialize(decision)
            @decision = decision
            super("Session scope denied #{decision.action.inspect} for #{decision.resource.inspect}: #{decision.reason}")
          end

          def reason
            decision.reason
          end
        end

        # An immutable view over one grant stored in the session.
        class Grant
          attr_reader :data

          def initialize(data)
            @data = data
          end

          def subject_class
            data['subject_class']
          end

          def subject_id
            data['subject_id']
          end

          def subject?(user)
            return false unless user
            return false unless subject_id == user.id.to_s

            subject_class.nil? || user.class.ancestors.map(&:name).include?(subject_class)
          end

          def resource
            data['resource']
          end

          def resource_type
            data['resource_type']
          end

          def actions
            Array(data['actions']).map(&:to_sym)
          end

          def revoked_actions
            Array(data['revoked_actions']).map(&:to_sym)
          end

          def granted_at
            Time.at(data['granted_at']) if data['granted_at']
          end

          def expires_at
            Time.at(data['expires_at']) if data['expires_at']
          end

          def expired?(now = Time.now)
            expires_at.present? && now >= expires_at
          end

          def revoked?
            data['revoked_at'].present?
          end

          def revision
            data['revision']
          end

          def to_h
            data.dup
          end
        end

        # The result of checking one action against the current session grant.
        class Decision
          attr_reader :reason, :action, :resource, :grant

          def initialize(reason:, action:, resource:, grant: nil)
            @reason = reason
            @action = action
            @resource = resource
            @grant = grant
          end

          def allowed?
            reason == :allowed
          end

          def denied?
            !allowed?
          end

          # A suggested HTTP status for controllers that render the decision.
          def http_status
            case reason
            when :allowed
              :ok
            when :not_authenticated, :session_expired, :session_invalidated
              :unauthorized
            else
              :forbidden
            end
          end

          def to_h
            {
              allowed: allowed?,
              reason: reason,
              action: action.to_s,
              resource: resource
            }
          end
        end

        def self.included(base)
          base.send(:include, InstanceMethods)
          Config.module_eval do
            class << self
              # Optional lifetime, in seconds, for newly granted scopes.
              # When nil, the grant lives as long as the session does.
              attr_accessor :session_scope_default_ttl

              def merge_session_scope_defaults!
                @defaults.merge!(:@session_scope_default_ttl => nil)
              end
            end
            merge_session_scope_defaults!
          end

          Config.after_login << :sync_session_scope_after_login
        end

        module InstanceMethods
          # Gives the current session a narrow grant of +actions+ on +resource+.
          # A grant replaces any previous grant for the same resource, so
          # granting again can either narrow or deliberately widen it.
          #
          # @param resource [Object, String, Symbol, Numeric] an organization, its
          #   id, or any other opaque resource identifier.
          # @param actions [Array<Symbol, String>] operations allowed by the grant.
          # @param expires_at [Time, nil] optional explicit expiry.
          # @return [Grant]
          def grant_session_scope!(resource, actions:, expires_at: nil)
            raise NotAuthenticated, 'Cannot grant a session scope without an authenticated user' unless current_user

            actions = normalize_session_scope_actions(actions)
            raise ArgumentError, 'at least one action is required' if actions.empty?

            key = session_scope_resource_key(resource)
            raise ArgumentError, 'a resource is required' if key.nil?

            grants = session_scope_raw_grants
            grants[key] = build_session_scope_grant(resource, actions, expires_at)
            session[GRANTS_SESSION_KEY] = grants
            session.delete(TERMINATION_SESSION_KEY)
            Grant.new(grants[key])
          end

          # Returns the grant for +resource+, or the only grant when resource is
          # omitted. Returns nil when there is no matching (or unambiguous) grant.
          #
          # @return [Grant, nil]
          def session_scope_grant(resource = nil)
            key = session_scope_resource_key(resource)
            grants = session_scope_raw_grants

            if key.nil?
              return nil unless grants.size == 1

              key = grants.keys.first
            end

            data = grants[key]
            data && Grant.new(data)
          end

          # All grants for this session, keyed by resource.
          #
          # @return [Hash{String => Grant}]
          def session_scope_grants
            session_scope_raw_grants.transform_values { |data| Grant.new(data) }
          end

          # Evaluates +action+ against the session grant for +resource+.
          # This is a fresh evaluation on every call and is never memoized.
          #
          # @return [Decision]
          def session_scope_decision(action, resource: nil)
            raise ArgumentError, 'an action is required' if action.nil?

            action = action.to_s
            key = session_scope_resource_key(resource)
            grants = session_scope_raw_grants

            if grants.empty?
              termination_reason = session_scope_termination_reason
              return session_scope_decision_for(termination_reason, action, key) if termination_reason

              reason = current_user ? :no_grant : :not_authenticated
              return session_scope_decision_for(reason, action, key)
            end

            key ||= sole_session_scope_key(grants)
            return session_scope_decision_for(:ambiguous_scope, action, nil) if key.nil?

            data = grants[key]
            return session_scope_decision_for(:out_of_scope, action, key) unless data

            grant = Grant.new(data)
            return session_scope_decision_for(:not_authenticated, action, key, grant) unless current_user
            return session_scope_decision_for(:subject_changed, action, key, grant) unless grant.subject?(current_user)
            return session_scope_decision_for(:scope_revoked, action, key, grant) if grant.revoked?
            return session_scope_decision_for(:grant_expired, action, key, grant) if grant.expired?

            return session_scope_decision_for(:action_revoked, action, key, grant) if grant.data['revoked_actions'].include?(action)
            return session_scope_decision_for(:allowed, action, key, grant) if grant.data['actions'].include?(action)

            session_scope_decision_for(:action_not_granted, action, key, grant)
          end

          # @return [Boolean]
          def session_scope_allows?(action, resource: nil)
            session_scope_decision(action, resource: resource).allowed?
          end

          # Authorizes +action+ and raises Denied when it is not allowed.
          # The returned Decision carries the business-readable reason.
          #
          # @return [Decision]
          # @raise [Denied]
          def authorize_session_scope!(action, resource: nil)
            decision = session_scope_decision(action, resource: resource)
            raise Denied, decision unless decision.allowed?

            decision
          end

          # Uses the request method to choose the conventional read/write action.
          # Safe (read-only) requests map to :read; all others map to :write.
          def session_scope_request_action
            request.get? || request.head? ? :read : :write
          end

          def session_scope_allows_request?(resource: nil)
            session_scope_allows?(session_scope_request_action, resource: resource)
          end

          def authorize_session_scope_request!(resource: nil)
            authorize_session_scope!(session_scope_request_action, resource: resource)
          end

          # Revokes one or more actions from the grant for +resource+. With no
          # actions it revokes the whole grant but leaves the login session and
          # its activity record intact.
          #
          # @return [Boolean] whether anything was revoked.
          def revoke_session_scope!(actions = nil, resource: nil)
            key = session_scope_resource_key(resource)
            grants = session_scope_raw_grants

            if key.nil?
              return false if grants.empty?

              key = sole_session_scope_key(grants)
              raise ArgumentError, 'resource is required when several grants exist' if key.nil?
            end

            data = grants[key]
            return false unless data

            if actions.nil?
              return false if data['revoked_at'].present?

              data['revoked_actions'] = (Array(data['revoked_actions']) + Array(data['actions'])).uniq
              data['actions'] = []
              data['revoked_at'] = Time.now.to_f
            else
              actions = normalize_session_scope_actions(actions)
              revoked = actions.select { |action| data['actions'].include?(action) }
              return false if revoked.empty?

              data['actions'] -= revoked
              data['revoked_actions'] = (Array(data['revoked_actions']) + revoked).uniq
            end

            data['revision'] = data['revision'].to_i + 1
            grants[key] = data
            session[GRANTS_SESSION_KEY] = grants
            true
          end

          # Revokes every grant in the current session without ending the login.
          #
          # @return [Boolean]
          def revoke_all_session_scopes!
            grants = session_scope_raw_grants
            return false if grants.empty?

            now = Time.now.to_f
            grants.each_value do |data|
              next if data['revoked_at'].present?

              data['revoked_actions'] = (Array(data['revoked_actions']) + Array(data['actions'])).uniq
              data['actions'] = []
              data['revoked_at'] = now
              data['revision'] = data['revision'].to_i + 1
            end
            session[GRANTS_SESSION_KEY] = grants
            true
          end

          # Why the session ended, when it ended because of a timeout. Other
          # reasons (for example an explicit logout) simply remove the grants.
          #
          # @return [Symbol, nil] one of DECISION_REASONS, or nil.
          def session_scope_termination_reason
            reason = session[TERMINATION_SESSION_KEY].to_s.to_sym
            DECISION_REASONS.include?(reason) ? reason : nil
          end

          protected

          # Runs after a successful login. A grant belongs to the subject that
          # received it; if another subject logs in on the same session, the
          # grant is dropped and the session records why. Logging in again as
          # the same subject keeps the grant, and any stale timeout marker is
          # cleared.
          def sync_session_scope_after_login(user = nil, _credentials = nil)
            grants = session_scope_raw_grants
            subject_changed = grants.any? do |_resource, data|
              user.nil? || !Grant.new(data).subject?(user)
            end

            if subject_changed
              session.delete(GRANTS_SESSION_KEY)
              session[TERMINATION_SESSION_KEY] = :subject_changed
            else
              session.delete(TERMINATION_SESSION_KEY)
            end
          end

          private

          def session_scope_raw_grants
            grants = session[GRANTS_SESSION_KEY]
            grants.is_a?(Hash) ? grants : {}
          end

          def sole_session_scope_key(grants)
            grants.size == 1 ? grants.keys.first : nil
          end

          def normalize_session_scope_actions(actions)
            Array(actions).map { |action| action.to_s }.reject(&:empty?).uniq
          end

          def session_scope_resource_key(resource)
            return nil if resource.nil?

            if resource.respond_to?(:to_param)
              resource.to_param.to_s
            else
              resource.to_s
            end
          end

          def build_session_scope_grant(resource, actions, expires_at)
            expires_at = default_session_scope_expiry if expires_at.nil?
            key = session_scope_resource_key(resource)
            {
              'subject_class' => current_user.class.name,
              'subject_id' => current_user.id.to_s,
              'resource' => key,
              'resource_type' => session_scope_resource_type(resource),
              'resource_id' => key,
              'actions' => actions,
              'revoked_actions' => [],
              'granted_at' => Time.now.to_f,
              'expires_at' => expires_at&.to_f,
              'revoked_at' => nil,
              'revision' => 1
            }
          end

          def session_scope_resource_type(resource)
            return nil if resource.is_a?(String) || resource.is_a?(Symbol) || resource.is_a?(Numeric)

            resource.class.name
          end

          def default_session_scope_expiry
            ttl = Config.session_scope_default_ttl
            ttl && Time.now + ttl
          end

          def session_scope_decision_for(reason, action, resource, grant = nil)
            Decision.new(reason: reason, action: action, resource: resource, grant: grant)
          end
        end
      end
    end
  end
end
