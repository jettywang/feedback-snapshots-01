module OmniAuth
  # Registry of plugin callbacks, each with its own auth-view policy.
  class IdentityCallbacks
    Registration = Struct.new(:name, :view, :handler, :failure_handler, :keyword_init => true) do
      def deliver(view, env)
        case arity
        when 0
          handler.call
        when 1, -1
          handler.call(view)
        else
          handler.call(view, env)
        end
      end

      private

      def arity
        handler.respond_to?(:arity) ? handler.arity : handler.method(:call).arity
      end
    end

    class Registry
      attr_reader :callbacks

      def initialize
        @callbacks = {}
      end

      # rubocop:disable Metrics/ParameterLists
      def register(name, callback = nil, fields: nil, allowed: nil, view: nil, on_failure: nil, &block)
        handler = block || callback
        raise ArgumentError, 'an identity callback must be callable' unless handler.respond_to?(:call)

        policy = view || AuthView.new(:fields => fields || allowed || [])
        registration = Registration.new(
          :name => name.to_sym,
          :view => policy,
          :handler => handler,
          :failure_handler => on_failure
        )
        @callbacks[registration.name] = registration
      end
      # rubocop:enable Metrics/ParameterLists

      alias add register
      alias []= register

      def [](name)
        @callbacks.fetch(name.to_sym)
      end

      def key?(name)
        @callbacks.key?(name.to_sym)
      end

      def names
        @callbacks.keys
      end

      def empty?
        @callbacks.empty?
      end

      def clear
        @callbacks.clear
        self
      end

      def dispatch(env, correlation_id:, strategy: nil)
        IdentityDispatcher.new(self, env, correlation_id, strategy).call
      end
    end
  end
end
