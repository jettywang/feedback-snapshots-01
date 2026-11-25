# frozen_string_literal: true

module Grape
  class Entity
    module Publication
      # Internal record of a field that did not format successfully. It is
      # converted into a public Error before it reaches callers.
      FieldFailure = Struct.new(:field, :code, :original, :mandatory) do
        def mandatory?
          mandatory
        end

        def to_error
          Error.new(code, field: field, mandatory: mandatory, original: original)
        end
      end
    end
  end
end
