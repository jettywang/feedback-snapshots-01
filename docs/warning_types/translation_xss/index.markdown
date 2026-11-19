# Translation XSS

Rails internationalization (`I18n`) exposes the `t`/`translate` helper in views
and `I18n.t` in code. Whether the returned string is HTML-escaped on output
depends on the **capability** of the translation key, not just on the fixed text
stored in the locale file.

## Text keys vs. HTML keys

A normal key is rendered through ordinary auto-escaping, so a translation such
as

```yaml
en:
  greetings:
    plain: "Hello %{name}"
```

is safe to use with a user-controlled `name` interpolation.

A key whose name ends in `_html` (or has an `.html` segment) is treated as
trusted HTML. Its value is emitted without escaping, and **interpolation
arguments are inserted as-is**:

```yaml
en:
  greetings:
    bold_html: "<b>Hello %{name}</b>"
```

```erb
<%= t('greetings.bold_html', name: params[:name]) %>
```

Here `params[:name]` reaches the page unescaped and is a real XSS sink, even
though the `<b>...</b>` text itself is trusted. Trusted translation text does
not imply that the interpolation parameters are safe.

## Fallback and default chains

`I18n.t` accepts a `:default`, which may be a symbol naming another key, a
string used as inline text, or an array tried in order. Each leg can carry a
different capability:

```erb
<%= t('greetings.missing_plain',
      default: :'fallback.html_tail_html',
      name: params[:name]) %>
```

The primary key looks like plain text, but the fallback resolves to an HTML key,
so the "text is escaped" conclusion cannot be reused for the fallback leg. A
string default is inline (escaped) text; a symbol default inherits the named
key's capability.

## Dynamic keys

When the key itself is dynamic (`t(params[:key])`), the effective capability
cannot be resolved statically. The check warns that an HTML-capable key may be
selected at runtime.

## `raw` output

Wrapping an otherwise safe text translation in `raw`/`html_safe` bypasses
auto-escaping for any interpolated value:

```erb
<%= raw t('pages.title', name: params[:name]) %>
```

The check is purely static: it parses `config/locales/*.yml`, resolves keys and
fallback chains, tracks user-controlled interpolation, and inspects the output
context without executing any translation code.
