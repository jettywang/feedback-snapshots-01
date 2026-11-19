# Triggers

From your application, you can push updates to GraphQL clients with `.trigger`.

Events are triggered _by name_, and the name must match fields on your [Subscription Type](/subscriptions/subscription_type)

```ruby
# Update the system with the new blog post:
MySchema.subscriptions.trigger(:post_added, {}, new_post)
```

The arguments are:

- `name`, which corresponds to the field on subscription type
- `arguments`, which corresponds to the arguments on subscription type (for example, if you subscribe to comments on a certain post, the arguments would be `{post_id: comment.post_id}`.)
- `object`, which will be the root object of the subscription update
- `scope:` (shown below) for implicitly scoping the clients who will receive updates.

## Scope

To send updates to _certain clients only_, you can use `scope:` to narrow the trigger's reach.

Scopes are based on query context: a value in `context:` is used as the scope; an equivalent value must be passed with `.trigger(... scope:)` to update that client. (The value is serialized with `GraphQL::Subscriptions::Serialize`.)

To specify that a topic is scoped, add a `subscription_scope` option to the Subscription class:

```ruby
class Subscriptions::CommentAdded < Subscription::BaseSubscription
  description "A comment was added to one of the viewer's posts"
  # For a given viewer, this will be triggered
  # whenever one of their posts gets a new comment
  subscription_scope :current_user_id
  # ...
end
```

(Read more in the [Subscription Classes guide](/subscriptions/subscription_classes#scope).)

Then, subscription operations should have a `context: { current_user_id: ... }` value, for example:

```ruby
# current_user_id will be the scope for some subscriptions:
MySchema.execute(query_string, context: { current_user_id: current_user.id })
```

Finally, when events happen in your app, you should provide the scoping value as `scope:`, for example:

```ruby
# A new comment is added
comment = post.comments.create!(attrs)
# notify the author
author_id = post.author.id
MySchema.subscriptions.trigger(:comment_added, {}, comment, scope: author_id)
```

Since this trigger has a `scope:`, only subscribers with a matching scope value will be updated.

## Validation

By default, subscriptions are re-validated when a trigger causes them to send updates. To disable this, you can pass `validate_update: false` when hooking up subscriptions to your schema. For example:

```ruby
use SomeSubscriptions, validate_update: false
```

If you're sure you won't be releasing breaking changes to your schema, this setting can reduce overhead in evaluating updates.

## Re-authorizing updates

Subscriptions can live for a long time (for example, a report subscription that stays open for days). During that time, a viewer's permissions may change. By default, authorization is only checked when the subscription is first created.

To re-check permissions before every update, opt in with `authorize_update:`:

```ruby
use MySubscriptions, authorize_update: true
```

Then implement `#authorize_update?` in your subscriptions class. It's called after the saved subscription is loaded and _before_ the update query runs, so no application data is fetched or delivered when the check doesn't pass:

```ruby
class MySubscriptions < GraphQL::Subscriptions
  def authorize_update?(subscription_id:, context:, **rest)
    case PermissionService.check(context[:current_user_id], context[:report_id])
    when :allowed   then GraphQL::Subscriptions::AUTHORIZED
    when :denied    then GraphQL::Subscriptions::REVOKED
    else                 GraphQL::Subscriptions::DEFERRED
    end
  end
end
```

Instead of `authorize_update: true`, you can pass a callable (it receives the same keywords) or the name of a method to call:

```ruby
use MySubscriptions, authorize_update: ->(context:, **) {
  context[:viewer].can_read_reports? ? GraphQL::Subscriptions::AUTHORIZED : GraphQL::Subscriptions::REVOKED
}

# or:
use MySubscriptions, authorize_update: :check_report_permission
```

Pass `authorize_update: false` to disable a check inherited from a superclass.

There are three possible results:

- `GraphQL::Subscriptions::AUTHORIZED` (or `true`) — the subscriber is still allowed: execute and deliver the update.
- `GraphQL::Subscriptions::DEFERRED` (or `nil`) — permission couldn't be confirmed right now (for example, an authorization service timed out): skip this update but _keep_ the subscription. A later update may be delivered if the check passes then.
- `GraphQL::Subscriptions::REVOKED` (or `false`) — permission was definitively removed: skip this update and delete the subscription. For transports with a close signal (such as ActionCable), the client is also told the subscription is over (`more: false`).

Any other return value is treated as `DEFERRED`, so an unexpected value never sends data.

The check also runs for replies that would otherwise be broadcast: when `authorize_update` is enabled, each subscription is evaluated separately, so one subscriber's result is never sent to another subscriber. This also means [broadcastable](/subscriptions/broadcast) subscriptions aren't batched while the check is enabled, since their permissions may differ.
