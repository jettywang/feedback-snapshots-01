require 'brakeman/checks/base_check'

#Detects server-side request forgery (SSRF) in calls that perform outbound
#HTTP requests where a user-controlled value influences the destination URL.
#
#This is a deliberately limited, source-to-sink data flow check. It only
#considers HTTP/open-uri calls it can identify syntactically, and it classifies
#which part of the URL the user input can control:
#
#  * :full  - input can supply or replace the scheme and/or host, so the
#             request can be redirected to an arbitrary destination
#  * :path  - scheme and host are fixed in source; input only reaches the
#             path, query string, or fragment
#
#Static analysis cannot prove how a value is parsed at runtime, whether a
#redirect is followed, or what a host name resolves to. Those behaviors are
#documented as limitations rather than assumed safe.
class Brakeman::CheckSSRF < Brakeman::BaseCheck
  Brakeman::Checks.add self

  @description = "Checks for server-side request forgery in HTTP requests with user-controlled URLs"

  #Outbound HTTP call targets and the methods that initiate a request.
  #Faraday.new is handled separately because the URL is a keyword option.
  HTTP_SINKS = {
    :'Net::HTTP' => [:start, :new, :get, :get_response, :get_print, :post, :post_form, :request],
    :HTTParty => [:get, :post, :put, :patch, :delete, :head, :options],
    :Faraday => [:get, :post, :put, :patch, :delete, :head, :options],
    :RestClient => [:get, :post, :put, :patch, :delete, :head, :options, :execute, :request],
    :'RestClient::Request' => [:execute, :request],
    :URI => [:open, :read],
  }.freeze

  #Methods that build or parse a URI but do not perform a request themselves.
  URI_BUILDERS = [:parse, :join, :URI].freeze

  #Methods which only unwrap or stringify a value, so taint passes through.
  TRANSPARENT_METHODS = [:to_s, :to_str, :to_uri, :freeze, :strip, :chomp, :presence].freeze

  PART_MESSAGES = {
    :full => "can control the scheme and/or host of the request URL",
    :path => "only reaches the path, query, or fragment of a URL with a fixed scheme and host",
  }.freeze

  def run_check
    @helper_cache = {}
    @helper_visiting = Set.new
    @location_class = nil

    HTTP_SINKS.each do |target, methods|
      tracker.find_call(:target => target, :methods => methods).each do |result|
        process_http_sink result
      end
    end

    # Kernel#open / Kernel.open / open-uri's open, which fetch absolute URLs.
    tracker.find_call(:target => nil, :method => :open).each do |result|
      process_open_sink result
    end

    # Faraday.new(url: ...) establishes the connection base URL. It is often
    # nested inside the request chain (Faraday.new(...).get), so nested calls
    # must be included.
    tracker.find_call(:target => :Faraday, :method => :new, :nested => true).each do |result|
      process_faraday_new result
    end
  end

  private

  def process_http_sink result
    return unless original? result

    with_location(result) do
      call = result[:call]
      method = call.method

      if method == :start or method == :new
        # Net::HTTP.start(host, port, ...) / Net::HTTP.new(host, port)
        host = call.first_arg

        if host and match = taint_match(host)
          warn_ssrf result, call, match, :full
        end
      else
        url = url_argument(call)

        if url and match = taint_match(url)
          warn_ssrf result, call, match, classify_part(url)
        end
      end
    end
  end

  def process_open_sink result
    return unless original? result

    with_location(result) do
      call = result[:call]
      url = call.first_arg

      next unless url

      match = taint_match(url)
      next unless match

      # Only treat open() as an SSRF sink when the value is (or could be) an
      # absolute URL with a scheme. A relative path with user input is a file
      # access concern, covered by CheckFileAccess, not SSRF.
      next unless looks_like_url?(url)

      warn_ssrf result, call, match, classify_part(url)
    end
  end

  def process_faraday_new result
    return unless original? result

    with_location(result) do
      call = result[:call]
      url = faraday_url_option(call)

      next unless url

      if match = taint_match(url)
        warn_ssrf result, call, match, classify_part(url)
      end
    end
  end

  #Runs the block with @location_class set to the class or template that
  #contains the call site, used to resolve helper methods in scope.
  def with_location result
    location = result[:location]
    @location_class = location[:class] || location[:template]
    yield
  ensure
    @location_class = nil
  end

  #Extracts the URL positional argument from an HTTP client request call,
  #including RestClient::Request.execute(url: ...) style keyword arguments.
  def url_argument call
    first = call.first_arg

    if hash? first and url = hash_access(first, :url)
      return url
    end

    first
  end

  def faraday_url_option call
    call.each_arg do |arg|
      if hash? arg and url = hash_access(arg, :url)
        return url
      end
    end

    nil
  end

  #Returns a Match when the expression contains user-controlled input,
  #otherwise nil.
  def taint_match exp
    return unless sexp? exp

    has_immediate_user_input?(exp) || include_user_input?(exp) || nil
  end

  #Determines which part of the URL the user input can control.
  #
  #Returns :full when input can reach the scheme or authority, and :path when
  #a scheme and authority are fixed before any interpolation.
  def classify_part exp, depth = 0
    return :path unless sexp? exp
    return :full if depth > 3

    case exp.node_type
    when :str
      :path
    when :dstr
      classify_dstr exp, depth
    when :call, :safe_call
      classify_call exp, depth
    when :if
      max_part(classify_part(exp.then_clause, depth + 1),
               classify_part(exp.else_clause, depth + 1))
    when :or
      max_part(classify_part(exp.lhs, depth + 1),
               classify_part(exp.rhs, depth + 1))
    when :splat, :kwsplat
      classify_part(exp.value, depth + 1)
    else
      :full
    end
  end

  #Returns the more permissive part, since a branch that can control the
  #scheme or host is enough to make the whole expression fully controllable.
  def max_part first, second
    if first == :full or second == :full
      :full
    else
      :path
    end
  end

  def classify_dstr exp, depth
    static_prefix = static_string_prefix(exp)

    if static_prefix.empty?
      # Interpolated value sits at the very start, so it can supply a scheme
      # or a scheme-relative "//host" value.
      :full
    elsif static_prefix.include?("://")
      # A scheme is present, but the host is only fixed when it is fully
      # spelled out before the interpolation. An interpolation in the
      # userinfo or host position (e.g. "https://#{x}@host/") can still
      # redirect the request.
      authority_fixed?(static_prefix) ? :path : :full
    elsif static_prefix.start_with?("//")
      # Scheme-relative reference: the host is still open to user input.
      :full
    else
      # A fixed domain-looking prefix without a scheme (e.g. "example.com/x")
      # is not treated as a fixed authority, because URL parsing of the final
      # value cannot be proven here.
      :full
    end
  end

  #Given the literal prefix of a string that already contains "://", reports
  #whether the authority (userinfo, host, and port) is complete before any
  #interpolation. The first "/" after the scheme terminates the authority; a
  #"?", "#", or end of string does too. An "@" before that point means an
  #interpolated value could still be supplying or altering the host.
  def authority_fixed? prefix
    after_scheme = prefix.split("://", 2).last
    authority = after_scheme.split(/[\/?#]/, 2).first

    return false if authority.nil? or authority.empty?
    return false if authority.include?("@")
    return false if authority.end_with?(":") # port left open for interpolation

    true
  end

  def classify_call exp, depth
    target = exp.target
    method = exp.method

    if target.nil? and method == :URI
      classify_part(exp.first_arg, depth + 1)
    elsif target == :URI and method == :parse
      classify_part(exp.first_arg, depth + 1)
    elsif target == :URI and method == :join
      classify_uri_join exp, depth
    elsif TRANSPARENT_METHODS.include?(method)
      classify_part(target, depth + 1)
    elsif method == :+ or method == :<<
      classify_concat exp, depth
    elsif helper_return = resolve_helper(exp, depth)
      classify_part(helper_return, depth + 1)
    else
      # An unrecognized call returning a value used as the URL may still be
      # user influenced, and no fixed authority is visible at the call site.
      :full
    end
  end

  #Returns the positional arguments of a call sexp. Unlike Sexp#args followed
  #by sexp_body, this keeps every argument (Sexp#args is untyped and has no
  #node-type symbol to drop).
  def call_arguments call
    call[3..] || []
  end

  # URI.join(base, *others). A tainted base means the whole reference is
  # controllable. Tainted later arguments can be absolute and replace the
  # base authority, which cannot be ruled out statically.
  def classify_uri_join exp, depth
    args = call_arguments(exp)

    if args.empty?
      return :full
    end

    base = args.first

    if taint_match(base)
      return :full
    end

    if args[1..].any? { |arg| taint_match(arg) }
      return :full
    end

    classify_part(base, depth + 1)
  end

  def classify_concat exp, depth
    if string?(exp.target) or string_interp?(exp.target)
      classify_part(exp.target, depth + 1)
    else
      :full
    end
  end

  #Concatenates the literal string nodes at the front of a :dstr, stopping at
  #the first interpolated value.
  def static_string_prefix dstr
    prefix = +""

    dstr.sexp_body.each do |node|
      if node.is_a? String
        prefix << node
      elsif sexp?(node) and node.node_type == :str
        prefix << node.value
      elsif sexp? node
        break
      end
    end

    prefix
  end

  #open() only fetches a network resource when given an absolute URL. A bare
  #relative literal is a local file operation; user-controlled values cannot be
  #proven relative at runtime, so they are treated as URL-capable.
  def looks_like_url? exp
    return true unless sexp? exp

    case exp.node_type
    when :str
      exp.value.include?("://") or exp.value.start_with?("//")
    when :dstr
      prefix = static_string_prefix(exp)
      prefix.include?("://") or prefix.start_with?("//") or prefix.empty?
    when :call, :safe_call
      target = exp.target
      method = exp.method

      if request_value?(exp)
        return true
      elsif (target.nil? and method == :URI) or
            (target == :URI and URI_BUILDERS.include?(method)) or
            TRANSPARENT_METHODS.include?(method)
        return true
      end

      if helper_return = resolve_helper(exp, 0)
        return looks_like_url?(helper_return)
      end

      false
    else
      false
    end
  end

  #Attempts to resolve the return value of a helper method in scope,
  #substituting the call-site arguments. Resolution is bounded and does not
  #attempt cross-file runtime behavior; nil means nothing could be proven.
  def resolve_helper exp, depth
    return nil if depth > 2
    return nil unless call? exp
    return nil if exp.target

    method_name = exp.method
    return nil unless method_name.is_a? Symbol

    key = [method_name, call_arguments(exp).inspect, depth]
    return @helper_cache[key] if @helper_cache.key?(key)

    @helper_cache[key] = nil

    definition = helper_definition(method_name)
    return @helper_cache[key] unless definition and node_type?(definition, :defn)

    unless @helper_visiting.add?([method_name, depth])
      return @helper_cache[key]
    end

    begin
      body = definition.body_list.deep_clone
      env = build_helper_env(definition, exp)
      processed = Brakeman::AliasProcessor.new(tracker).process_safely(body, env)
      return_value = Brakeman::FindReturnValue.return_value(processed)

      @helper_cache[key] = return_value unless node_type?(return_value, :nil)
    ensure
      @helper_visiting.delete([method_name, depth])
    end

    @helper_cache[key]
  end

  #Looks up an instance method definition, first in the surrounding class or
  #module, then across controllers and libraries. Returns the raw :defn sexp.
  def helper_definition method_name
    if @location_class and method_info = tracker.find_method(method_name, @location_class)
      return method_info.src
    end

    tracker.controllers.each_value do |controller|
      method_info = controller.get_method(method_name)
      return method_info.src if method_info
    end

    tracker.libs.each_value do |lib|
      method_info = lib.get_method(method_name)
      return method_info.src if method_info
    end

    nil
  end

  def build_helper_env definition, call
    env = SexpProcessor::Environment.new

    param_names = definition.formal_args.sexp_body.select { |param| param.is_a? Symbol }
    args = call_arguments(call)

    param_names.each_with_index do |param, index|
      value = args[index]

      env[s(:lvar, param)] = value.deep_clone if value
    end

    env
  end

  def warn_ssrf result, call, match, part
    confidence = part == :full ? :high : :weak

    warn :result => result,
      :warning_type => "SSRF",
      :warning_code => :ssrf,
      :message => msg("Possible SSRF: ", msg_input(match), " #{PART_MESSAGES[part]}"),
      :code => call,
      :user_input => match,
      :confidence => confidence,
      :cwe_id => [918]
  end
end
