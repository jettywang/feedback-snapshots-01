# JSONP Callback Injection

A JSONP response wraps a JSON payload in a caller-supplied callback
expression:

```ruby
render json: { name: "widget" }, callback: params[:cb]
```

produces a response body such as

```javascript
someCallback({"name":"widget"})
```

The JSON payload is correctly encoded, but that does not make the response
safe. The callback name is emitted verbatim as executable JavaScript. If an
attacker controls the callback value, they can inject arbitrary JavaScript
that runs in the origin of the application, which is a cross-site scripting
issue.

## What Is Considered Safe

Brakeman only treats a callback as safe when its value is one of:

* A fixed literal name, e.g. `callback: "cb"` or `callback: :cb`.
* A value provably drawn from a finite set of literal names, e.g. a value
  guarded by an allowlist (`["cb", "update"].include?(params[:cb]) ? ...`)
  or sampled from a literal collection (`NAMES.sample`).
* The return value of a helper method that itself resolves to one of the
  safe forms above.

## What Is Reported

Arbitrary, unconstrained user text is reported, including:

* A parameter, cookie, or request header used directly.
* Input that only had a few characters filtered (for example
  `params[:cb].gsub("(", "")`), which still leaves an unbounded set of
  values.
* Input concatenated or interpolated back into a larger string
  (`"cb_#{params[:cb]}"`).
* A free-text value merged into the render options hash
  (`render opts.merge(callback: params[:cb])`).
* The untrusted return value of a helper method.

The warning is placed on the callback source expression rather than the JSON
payload, because encoding the body correctly does not constrain the
callback wrapper.

## Remediation

Use a fixed callback name, or validate the supplied value against a strict
allowlist before passing it to `:callback`. Reject any value that does not
match an identifier pattern such as `/\A[a-zA-Z_$][a-zA-Z0-9_$]*\z/`.
