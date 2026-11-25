# frozen_string_literal: true

module Grape
  class Entity
    module Publication
      # Sentinel returned by an exposure that was intentionally dropped by the
      # optional-field degradation policy. Output builders remove it instead of
      # writing a key with nil.
      OMITTED = Object.new
      OMITTED.freeze

      def self.omitted?(value)
        value.equal?(OMITTED)
      end
    end
  end
end
