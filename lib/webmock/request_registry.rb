# frozen_string_literal: true

module WebMock

  class RequestRegistry
    # The global registry, used when no TestScope is active.
    include Singleton

    # When a TestScope is active, request counts are recorded in that scope's
    # registry; otherwise they go to the global one. Assertions made inside a
    # scope therefore only see the requests made by the same test group.
    def self.instance
      scope = TestScope.current
      scope ? scope.request_registry : super
    end

    # Fresh, non-global registry used to back an isolated TestScope.
    def self.build
      send(:new)
    end

    attr_accessor :requested_signatures

    def initialize
      reset!
    end

    def reset!
      self.requested_signatures = Util::HashCounter.new
    end

    def times_executed(request_pattern)
      self.requested_signatures.select do |request_signature|
        request_pattern.matches?(request_signature)
      end.inject(0) { |sum, (_, times_executed)| sum + times_executed }
    end

    def to_s
      if requested_signatures.hash.empty?
        "No requests were made."
      else
        text = "".dup
        self.requested_signatures.each do |request_signature, times_executed|
          text << "#{request_signature} was made #{times_executed} time#{times_executed == 1 ? '' : 's' }\n"
        end
        text
      end
    end

  end
end
