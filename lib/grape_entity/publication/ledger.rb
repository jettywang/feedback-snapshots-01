# frozen_string_literal: true

module Grape
  class Entity
    module Publication
      # Stores the last successfully published representation per stable key so
      # a failed publication can hand review callers the previous approved view
      # instead of exposing a half-built object.
      class Ledger
        def initialize
          @entries = {}
          @mutex = Mutex.new
        end

        def fetch(key)
          @mutex.synchronize { @entries[key] }
        end

        def store(key, representation)
          @mutex.synchronize { @entries[key] = representation }
          representation
        end

        def delete(key)
          @mutex.synchronize { @entries.delete(key) }
        end

        def clear
          @mutex.synchronize { @entries.clear }
          self
        end

        def keys
          @mutex.synchronize { @entries.keys }
        end

        def empty?
          @mutex.synchronize { @entries.empty? }
        end
      end
    end
  end
end
