# Authorization

While a query is running, you can check each object to see whether the current user is authorized to interact with that object. If the user is _not_ authorized, you can handle the case with an error.

## Adding Authorization Checks

Schema members have `authorized?` methods which will be called during execution:

- Type classes have `.authorized?(object, context)` class methods
- Fields have `#authorized?(object, args, context)` instance methods
- Arguments have `#authorized?(object, arg_value, context)` instance methods
- Mutations and Resolvers have `.authorized?(object, context)` class methods and `#authorized?(args)` instance methods
- Enum values have `#authorized?(context)` instance methods

These methods are called with:

- `object`: the object from your application which was returned from a field
- `args`/`arg_value`: The arguments for a field, or the value of an argument
- `context`: the query context, based on the hash passed as `context:`

#### Object Authorization

When you implement this method to return `false`, the query will be halted, for example:

```ruby
class Types::Friendship < Types::BaseObject
  # You can only see the details on a `Friendship`
  # if you're one of the people involved in it.
  def self.authorized?(object, context)
    super && (object.to_friend == context[:viewer] || object.from_friend == context[:viewer])
  end
end
```

(Always call `super` to get the default checks, too.)

Now, whenever an object of type `Friendship` is going to be returned to the client, it will first go through the `.authorized?` method. If that method returns false, the field will get `nil` instead of the original object, and you may handle that case with an error (see below).

#### Field Authorization

Field `#authorized?` methods are called before resolving a field, for example:

```ruby
class Types::BaseField < GraphQL::Schema::Field
  # Pass `field ..., require_admin: true` to reject non-admin users from a given field
  def initialize(*args, require_admin: false, **kwargs, &block)
    @require_admin = require_admin
    super(*args, **kwargs, &block)
  end

  def authorized?(obj, args, ctx)
    # if `require_admin:` was given, then require the current user to be an admin
    super && (@require_admin ? ctx[:viewer]&.admin? : true)
  end
end
```

For this to work, the base field class must be [configured with other GraphQL types](/type_definitions/extensions.html#customizing-fields).

#### Argument Authorization

Argument `#authorized?` hooks are called before resolving the field that the argument belongs to. For example:

```ruby
class Types::BaseArgument < GraphQL::Schema::Argument
  def initialize(*args, require_logged_in: false, **kwargs, &block)
    @require_logged_in = require_logged_in
    super(*args, **kwargs, &block)
  end

  def authorized?(obj, arg_value, ctx)
    super && if @require_logged_in
      ctx[:viewer].present?
    else
      true
    end
  end
end
```

For this to work, the base argument class must be [configured with other GraphQL types](/type_definitions/extensions.html#customizing-arguments).

## Mutation Authorization

See [Mutation Authorization](/mutations/mutation_authorization.html#can-this-user-perform-this-action) in the Mutation Guides.

## Enum Value Authorization

[GraphQL::Schema::EnumValue#authorized?](rdoc-ref:GraphQL::Schema::EnumValue#authorized?) is called when client input is received and when the schema returns values to the client.

For authorizing input, if a value's `#authorized?` method returns false, then a [GraphQL::UnauthorizedEnumValueError](rdoc-ref:GraphQL::UnauthorizedEnumValueError) is raised. It passed to your schema's `.unauthorized_object` hook, where you can handle it another way if you want.

For authorizing return values, if an outgoing value's `#authorized?` method returns false, then a [GraphQL::Schema::Enum::UnresolvedValueError](rdoc-ref:GraphQL::Schema::Enum::UnresolvedValueError) is raised, which crashes the query. In this case, you should modify your field or resolver to _not_ return this value to an unauthorized viewer. (In this case, the error isn't returned to the viewer because the viewer can't do anything about it -- it's a developer-facing issue instead.)

## Handling Unauthorized Objects

By default, GraphQL-Ruby silently replaces unauthorized objects with `nil`, as if they didn't exist. You can customize this behavior by implementing [Schema.unauthorized_object](rdoc-ref:GraphQL::Schema.unauthorized_object) in your schema class, for example:

```ruby
class MySchema < GraphQL::Schema
  # Override this hook to handle cases when `authorized?` returns false for an object:
  def self.unauthorized_object(error)
    # Add a top-level error to the response instead of returning nil:
    raise GraphQL::ExecutionError, "An object of type #{error.type.graphql_name} was hidden due to permissions"
  end
end
```

Now, the custom hook will be called instead of the default one.

If `.unauthorized_object` returns a non-`nil` object (and doesn't `raise` an error), then that object will be used in place of the unauthorized object.

A similar hook is available for unauthorized fields:

```ruby
class MySchema < GraphQL::Schema
  # Override this hook to handle cases when `authorized?` returns false for a field:
  def self.unauthorized_field(error)
    # Add a top-level error to the response instead of returning nil:
    raise GraphQL::ExecutionError, "The field #{error.field.graphql_name} on an object of type #{error.type.graphql_name} was hidden due to permissions"
  end
end
```

### Public Authorization Errors

If your API sends errors to clients outside your organization, you may not want to include the unauthorized object or its GraphQL type in the response -- those details could reveal records that the viewer can't access (for example, primary keys or internal type names).

Use [Schema.authorization_error_strategy](rdoc-ref:GraphQL::Schema.authorization_error_strategy) with `:public` to return a generic, client-safe error for every denied object or field:

```ruby
class MySchema < GraphQL::Schema
  authorization_error_strategy(:public)
end
```

With that setting, denied selections return an error like this:

```json
{
  "message": "You are not authorized to access this resource",
  "path": ["documents", 1],
  "locations": [{ "line": 1, "column": 3 }],
  "extensions": { "code": "UNAUTHORIZED" }
}
```

The `path` still identifies which selection was denied (including list indexes), but the message omits the object and its type. The field is replaced with `nil`, just like the default behavior.

Meanwhile, the original failure is still available to the server for logging and investigation:

- [Query::Context#unauthorized_errors](rdoc-ref:GraphQL::Query::Context#unauthorized_errors) returns the original [GraphQL::UnauthorizedError](rdoc-ref:GraphQL::UnauthorizedError) objects, with their `object`, `type`, and `path`.
- Each response error is a [GraphQL::PublicUnauthorizedError](rdoc-ref:GraphQL::PublicUnauthorizedError), whose `#original_error` holds the same details.

```ruby
result = MySchema.execute(query, context: { current_user: current_user })
result.context.unauthorized_errors.each do |err|
  MyLogger.info("Denied #{err.type.graphql_name}: #{err.object.inspect} at #{err.path.inspect}")
end
```

The default strategy is `:custom`, which preserves the historical behavior: return `nil` (or whatever your `.unauthorized_object` / `.unauthorized_field` hooks return). If you override those hooks, your implementations take precedence over the `:public` strategy.
