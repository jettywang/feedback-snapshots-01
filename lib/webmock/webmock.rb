# frozen_string_literal: true

module WebMock

  def self.included(clazz)
    WebMock::Deprecation.warning("include WebMock is deprecated. Please include WebMock::API instead")
    if clazz.instance_methods.map(&:to_s).include?('request')
      warn "WebMock#request was not included in #{clazz} to avoid name collision"
    else
      clazz.class_eval do
        def request(method, uri)
          WebMock::Deprecation.warning("WebMock#request is deprecated. Please use WebMock::API#a_request method instead")
          WebMock.a_request(method, uri)
        end
      end
    end
  end

  include WebMock::API
  extend WebMock::API

  class << self
    alias :request :a_request
  end

  def self.version
    VERSION
  end

  def self.disable!(options = {})
    except = [options[:except]].flatten.compact
    HttpLibAdapterRegistry.instance.each_adapter do |name, adapter|
      adapter.enable!
      adapter.disable! unless except.include?(name)
    end
  end

  def self.enable!(options = {})
    except = [options[:except]].flatten.compact
    HttpLibAdapterRegistry.instance.each_adapter do |name, adapter|
      adapter.disable!
      adapter.enable! unless except.include?(name)
    end
  end

  def self.allow_net_connect!(options = {})
    Config.instance.allow_net_connect = true
    Config.instance.net_http_connect_on_start = options[:net_http_connect_on_start]
  end

  def self.disable_net_connect!(options = {})
    Config.instance.allow_net_connect = false
    Config.instance.allow_localhost = options[:allow_localhost]
    Config.instance.allow = options[:allow]
    Config.instance.net_http_connect_on_start = options[:net_http_connect_on_start]
  end

  class << self
    alias :enable_net_connect!   :allow_net_connect!
    alias :disallow_net_connect! :disable_net_connect!
  end

  # Opens an isolated net-connect permission scope. Rules configured inside the
  # scope apply only while it is the active scope, leaving the global
  # configuration and any other open scope untouched. Without a block the scope
  # is returned and stays open until +#close+ is called; with a block the scope
  # is active for the block and closed automatically afterwards.
  #
  #   WebMock.net_connect_scope(allow: "api.example.com") do |scope|
  #     Net::HTTP.get(URI("http://api.example.com/health"))
  #   end
  def self.net_connect_scope(options = {}, &block)
    scope = WebMock::NetConnectScope.new(
      allow_net_connect: options.fetch(:allow_net_connect, false),
      allow_localhost: options[:allow_localhost],
      allow: options[:allow],
      net_http_connect_on_start: options[:net_http_connect_on_start]
    )

    if block
      scope.activate(&block)
    else
      WebMock::NetConnectScopeRegistry.instance.register(scope)
      scope
    end
  end

  # Opens a scope in which real connections are allowed. Accepts the same
  # options as WebMock.allow_net_connect!, scoped to the block or returned
  # scope.
  def self.allow_net_connect_scope(options = {}, &block)
    net_connect_scope(options.merge(allow_net_connect: true), &block)
  end

  # Opens a scope in which real connections are denied, with the same
  # allowlist options as WebMock.disable_net_connect!, scoped to the block or
  # returned scope.
  def self.disable_net_connect_scope(options = {}, &block)
    net_connect_scope(options.merge(allow_net_connect: false), &block)
  end

  def self.net_connect_allowed?(uri = nil)
    NetConnectScopeRegistry.instance.net_connect_allowed?(uri)
  end

  def self.net_http_connect_on_start?(uri)
    NetConnectScopeRegistry.instance.net_http_connect_on_start?(uri)
  end

  def self.net_connect_explicit_allowed?(allowed, uri=nil)
    case allowed
    when Array
      allowed.any? { |allowed_item| net_connect_explicit_allowed?(allowed_item, uri) }
    when Regexp
      allowed.match?(uri.to_s) ||
      (uri.port == uri.default_port && allowed.match?(uri.omit(:port).to_s))
    when String
      allowed == uri.host ||
      allowed == "#{uri.host}:#{uri.port}" ||
      net_connect_allowed_url?(allowed, uri)
    else
      if allowed.respond_to?(:call)
        allowed.call(uri)
      end
    end
  end

  def self.net_connect_allowed_url?(allowed, uri)
    return false unless allowed.match?(%r{\Ahttps?://}i)

    # Normalization turns an empty path into "/", so check the original URL.
    allowed_uri = Addressable::URI.parse(allowed)
    allow_any_path = allowed_uri.path.empty? && allowed_uri.query.nil?

    # Connection URIs have no request path to match yet.
    return false if uri.path.empty? && !allowed_uri.path.empty?

    allowed_uri = WebMock::Util::URI.normalize_uri(allowed_uri)
    request_uri = WebMock::Util::URI.normalize_uri(uri)

    return false unless allowed_uri.origin == request_uri.origin
    return true if allow_any_path

    allowed_uri.path == request_uri.path && allowed_uri.query == request_uri.query
  rescue Addressable::URI::InvalidURIError
    false
  end
  private_class_method :net_connect_allowed_url?

  def self.show_body_diff!
    Config.instance.show_body_diff = true
  end

  def self.hide_body_diff!
    Config.instance.show_body_diff = false
  end

  def self.show_body_diff?
    Config.instance.show_body_diff
  end

  def self.hide_stubbing_instructions!
    Config.instance.show_stubbing_instructions = false
  end

  def self.show_stubbing_instructions!
    Config.instance.show_stubbing_instructions = true
  end

  def self.show_stubbing_instructions?
    Config.instance.show_stubbing_instructions
  end

  def self.reset!
    WebMock::RequestRegistry.instance.reset!
    WebMock::StubRegistry.instance.reset!
    WebMock::NetConnectScopeRegistry.instance.reset!
  end

  def self.reset_webmock
    WebMock::Deprecation.warning("WebMock.reset_webmock is deprecated. Please use WebMock.reset! method instead")
    reset!
  end

  def self.reset_callbacks
    WebMock::CallbackRegistry.reset
  end

  def self.after_request(options={}, &block)
    WebMock::CallbackRegistry.add_callback(options, block)
  end

  def self.registered_request?(request_signature)
    WebMock::StubRegistry.instance.registered_request?(request_signature)
  end

  def self.print_executed_requests
    puts WebMock::RequestExecutionVerifier.executed_requests_message
  end

  def self.globally_stub_request(order = :before_local_stubs, &block)
    WebMock::StubRegistry.instance.register_global_stub(order, &block)
  end

  %w(
    allow_net_connect!
    disable_net_connect!
    net_connect_allowed?
    reset_webmock
    reset_callbacks
    after_request
    registered_request?
  ).each do |method|
    self.class_eval(%Q(
                      def #{method}(*args, &block)
                        WebMock::Deprecation.warning("WebMock##{method} instance method is deprecated. Please use WebMock.#{method} class method instead")
                        WebMock.#{method}(*args, &block)
                          end
    ))
  end
end
