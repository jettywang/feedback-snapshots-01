# Pre-Checks

Consider a typical situation when you start most—or even all—of your rules with the same predicates.

For example, when you have a super-user role in the application:

```ruby
class PostPolicy < ApplicationPolicy
  def show?
    user.super_admin? || record.published
  end

  def update?
    user.super_admin? || (user.id == record.user_id)
  end

  # more rules
end
```

Action Policy allows you to extract the common parts from rules into _pre-checks_:

```ruby
class PostPolicy < ApplicationPolicy
  pre_check :allow_admins

  def show?
    record.published
  end

  def update?
    user.id == record.user_id
  end

  private

  def allow_admins
    allow! if user.super_admin?
  end
end
```

Pre-checks act like _callbacks_: you can add multiple pre-checks, specify `except` and `only` options, and skip already defined pre-checks if necessary:

```ruby
class UserPolicy < ApplicationPolicy
  skip_pre_check :allow_admins, only: :destroy?

  def destroy?
    user.admin? && !record.admin?
  end
end
```

To halt the authorization process within a pre-check, you must return either `allow!` or `deny!` call value. When any other value is returned, the pre-check is ignored, and the rule is called (or next pre-check).

## Mandatory pre-checks

Some checks must run for every policy in the inheritance chain (e.g., security-related ones). You can declare such a pre-check as _mandatory_ to prevent subclasses from skipping it:

```ruby
class ApplicationPolicy < ActionPolicy::Base
  pre_check :deny_disabled_accounts, mandatory: true

  private

  def deny_disabled_accounts
    deny! if user.disabled?
  end
end
```

Mandatory pre-checks can still be scoped to particular actions via `only` / `except` (matched against the resolved rule, so aliases are taken into account), but calling `skip_pre_check` for them raises an `ArgumentError` at class definition time:

```ruby
class PostPolicy < ApplicationPolicy
  # raises ArgumentError: "Couldn't skip mandatory pre-check: deny_disabled_accounts (defined in ApplicationPolicy)"
  skip_pre_check :deny_disabled_accounts
end
```

**NOTE**: pre-checks are available only if you inherit from `ActionPolicy::Base` or include `ActionPolicy::Policy::PreCheck` into your `ApplicationPolicy`.
