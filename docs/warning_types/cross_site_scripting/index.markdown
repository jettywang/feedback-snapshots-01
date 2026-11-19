Cross-site scripting (or XSS) is #3 on the 2013 [OWASP Top Ten](https://www.owasp.org/index.php/Top_10_2013-A3-Cross-Site_Scripting_(XSS\)) web security risks and it pops up nearly everywhere.

XSS occurs when a user-controlled value is displayed on a web page without properly escaping it, allowing someone to inject Javascript or HTML into the page which will be interpreted and executed by the browser..

In Rails 2.x, values need to be explicitly escaped (e.g., by using the `h` method). Since Rails 3.x, auto-escaping in views is enabled by default. However, one can still use the `raw` or `html_safe` methods to output a value directly.

See [the Ruby Security Guide](http://guides.rubyonrails.org/security.html#cross-site-scripting-xss) for more details.

### Query Parameters and Cookies

ERB example:

    <%= params[:query].html_safe %>

Brakeman looks for several situations that can allow XSS. The simplest is like the example above: a value from the `params` or `cookies` is being directly output to a view. In such cases, it will issue a warning like:

    Unescaped parameter value near line 3: params[:query]

By default, Brakeman will also warn when a parameter or cookie value is used as an argument to a method, the result of which is output unescaped to a view.

For example:

    <%= raw some_method(cookie[:name]) %>

This raises a warning like:

    Unescaped cookie value near line 5: some_method(cookies[:oreo])

However, the confidence level for this warning will be weak, because it is not directly outputting the cookie value.

Some methods are known to Brakeman to either be dangerous (`link_to` is one) or safe (`escape_once`). Users can specify safe methods using the `--safe-methods` option. Alternatively, Brakeman can be set to _only_ warn when values are used directly with the `--report-direct` option.

### Model Attributes

Because (many) models come from database values, Brakeman mistrusts them by default.

For example, if `@user` is an instance of a model set in an action like

    def set_user
      @user = User.first
    end

and there is a view with

    <%= @user.name.html_safe %>

Brakeman will raise a warning like

    Unescaped model attribute near line 3: User.first.name

If you trust all your data (although you probably shouldn't), this can be disabled with `--ignore-model-output`.

### JavaScript Contexts

Values output inside `<script>` elements are not HTML nodes. Brakeman classifies the
output position from the compiled template text and reports separately for:

* a quoted JavaScript string (`var x = "<%= ... %>"`)
* a JavaScript expression (`var x = <%= ... %>`)
* JSON data (`<script type="application/json">`)

The template engine's HTML escaping is enough to keep a value inside a quoted
JavaScript string, but it is not enough in expression position, where characters
such as `;` and `(` are unchanged. Values marked HTML-safe with `raw`, `html_safe`,
or a helper returning a `SafeBuffer` bypass that escaping entirely.

`j`/`escape_javascript` only escapes text that will become the contents of a
JavaScript string. It is treated as safe in a quoted string (and in JSON string
data), but not as a JavaScript expression:

    var ok = "<%= j params[:name] %>";   # no warning
    var bad = <%= j params[:name] %>;    # warning

Serialized JSON (`to_json`) is safe in expression position when HTML entity
escaping is enabled, which is the default in Rails 4 and later:

    var data = <%= raw params[:data].to_json %>;  # no warning

When the surrounding template text does not determine the context (for example
when the tag name or a conditional branch is dynamic), Brakeman reports the
value as unknown rather than assuming it is safe.
