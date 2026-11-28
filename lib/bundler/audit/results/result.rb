module Bundler
  module Audit
    module Results
      #
      # @abstract
      #
      class Result

        #
        # The stable correlation ID for this finding.
        #
        # @return [String]
        #
        # @abstract
        #
        def correlation_id
          raise(NotImplementedError,"#{self.class}#correlation_id not implemented!")
        end

        #
        # @return [Hash{Symbol => Object}]
        #
        # @abstract
        #
        def to_h
          raise(NotImplementedError,"#{self.class}#to_h not implemented!")
        end

      end
    end
  end
end
