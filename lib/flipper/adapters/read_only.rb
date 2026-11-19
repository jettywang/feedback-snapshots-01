require 'flipper'

module Flipper
  module Adapters
    # Public: Adapter that wraps another adapter and raises for any writes.
    class ReadOnly < Wrapper
      WRITE_METHODS = %i[import add remove clear enable disable sync_version= reap_expired_actors]

      class WriteAttempted < Error
        def initialize(message = nil)
          super(message || 'write attempted while in read only mode')
        end
      end

      def read_only?
        true
      end

      def reap_expired_actors(now: nil, feature: nil)
        raise WriteAttempted
      end

      private

      def wrap(method, *args, **kwargs)
        raise WriteAttempted if WRITE_METHODS.include?(method)

        yield
      end
    end
  end
end
