# frozen_string_literal: true

module Grape
  module Formatter
    # Renders JSON Lines (https://jsonlines.org): one JSON value per line, each
    # line ended by a newline. An Array renders one line per element, and any
    # other object one line. A String is served as it is, taken to be JSON
    # Lines already.
    #
    # An Enumerator renders as it is read rather than up front, so the server
    # streams each line as the enumerator yields its element:
    #
    #   get :export do
    #     User.find_each # without a block, an Enumerator
    #   end
    #
    # An Enumerator is also where the disclosure decision has to hold for the
    # whole response. Pass a {Grape::ServeStream::Representation} and the body
    # renders every element through that frozen field set; a +jsonl+ route
    # builds the body -- and the ledger that accounts for it -- before the
    # first line is sent:
    #
    #   get :export do
    #     jsonl User.find_each, fields: %i[id name]
    #   end
    class Jsonl < Base
      class << self
        def call(object, env)
          return object if object.is_a?(String)
          return stream(object, env) if object.is_a?(Enumerator)
          return object.to_ary.map { |element| line(element, env) }.join if object.respond_to?(:to_ary)

          line(object, env)
        end

        # A plain Enumerator is served through the same audited body a `jsonl`
        # route builds, with no field restriction: every record is rendered as
        # it is, but the response still keeps a ledger and closes its source.
        # A route that needs a frozen disclosure builds the body itself with
        # the `jsonl` helper.
        def stream(object, env)
          body = Grape::ServeStream::JsonlBody.new(object, representation: Grape::ServeStream::Representation.new, env:)
          Grape::ServeStream::StreamResponse.new(body)
        end

        private

        def line(object, env)
          "#{Formatter::Json.call(object, env)}\n"
        end
      end
    end
  end
end
