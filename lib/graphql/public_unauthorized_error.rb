# frozen_string_literal: true
#--
# typed: true
module GraphQL
  # A client-facing error for an authorization failure.
  #
  # It's raised by [Schema.unauthorized_object](rdoc-ref:Schema.unauthorized_object)
  # when the schema's [authorization error strategy](rdoc-ref:Schema.authorization_error_strategy)
  # is `:public`.
  #
  # This error's `"message"` intentionally omits the unauthorized object and its
  # GraphQL type, so that clients don't learn about records they can't access. The
  # original [GraphQL::UnauthorizedError](rdoc-ref:GraphQL::UnauthorizedError) is
  # still available as {#original_error} for server-side logging and investigation.
  class PublicUnauthorizedError < GraphQL::ExecutionError
    # **Returns**
    #
    # - `GraphQL::UnauthorizedError` — The original authorization failure, including
    #   the denied `object` and its `type`. Do not send this object's details to clients.
    attr_reader :original_error

    # **Returns**
    #
    # - `Object` — The application object that failed the authorization check
    attr_reader :object

    # **Returns**
    #
    # - `Class` — The GraphQL type whose authorization check failed
    attr_reader :type

    # The default message returned to clients.
    DEFAULT_MESSAGE = "You are not authorized to access this resource"

    def initialize(original_error, message: DEFAULT_MESSAGE, extensions: nil)
      @original_error = original_error
      @object = original_error.object
      @type = original_error.type
      extensions ||= { "code" => "UNAUTHORIZED" }
      super(message, extensions: extensions)
    end

    # Keep the original error's `path` in sync with the client-facing one,
    # so server-side records point at the denied selection (including list indexes).
    def path=(new_path)
      @original_error.path = new_path
      super
    end
  end
end
