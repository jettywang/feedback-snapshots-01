User input used as the *source* of a Ruby template that is evaluated is VERY dangerous. Brakeman tracks request input (parameters, cookies, request headers) as it flows into a known template engine (`ERB`, `Erubi`, `Erubis`, `Haml::Engine`, `Slim::Template`) and then follows the compiled template object to see whether it is executed.

```ruby
  ERB.new(user_input).result
```

The check distinguishes the template *source* (the first argument, which is compiled as code) from template *variables* (the `binding`/`result_with_hash` arguments, which are only data). It also:

- Follows local/instance variable aliases and helper methods that compile or render the template, including argument-passing across helper layers.
- Reports high confidence when the compiled template is provably executed (for example via `result`, `result_with_hash`, or `render`), and medium confidence when a request-controlled template is constructed but no execution is observed.
- Does not flag constant template source, even when it is executed.
- Does not treat HTML escaping (e.g. `ERB::Util.html_escape`) as making a string safe to use as template language source; escaping output is different from interpreting a value as a template.
- Does not flag request data that is only rendered as plain text or passed as a template variable.
