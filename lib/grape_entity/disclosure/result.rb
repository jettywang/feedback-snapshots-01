# frozen_string_literal: true

module Grape
  class Entity
    module Disclosure
      # Payload plus the receipt produced by the same rendering pass.
      class Result
        attr_reader :payload, :receipt

        def initialize(payload:, receipt:)
          @payload = payload
          @receipt = receipt
        end

        def to_a
          [payload, receipt]
        end

        def deconstruct
          to_a
        end
      end
    end
  end
end
