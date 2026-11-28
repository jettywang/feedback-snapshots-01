module Bundler
  module Audit
    module Results
      #
      # @abstract
      #
      class Result

        #
        # The disposition of the result.
        #
        # * `:blocked` - the finding prevents the release.
        # * `:undetermined` - the finding prevents the release because there is
        #   not enough evidence to clear it.
        # * `:approved` - the finding was explicitly approved for release.
        #
        # @return [:blocked, :undetermined, :approved, nil]
        #
        def disposition
          nil
        end

        #
        # The reason for the disposition.
        #
        # @return [String, nil]
        #
        def reason
          nil
        end

        #
        # Determines whether the result prevents the release.
        #
        # @return [Boolean]
        #
        def blocks_release?
          case disposition
          when :blocked, :undetermined then true
          else false
          end
        end

        #
        # Determines whether the result was approved for release.
        #
        # @return [Boolean]
        #
        def approved?
          disposition == :approved
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
