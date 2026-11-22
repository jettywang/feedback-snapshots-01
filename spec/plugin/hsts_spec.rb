require_relative "../spec_helper"

describe "default_headers plugin" do
  def app(opts={})
    super(:bare) do
      plugin :hsts, **opts
      route do |r|
        ''
      end
    end
  end

  it "sets appropriate headers for the response" do
    app
    req[1][RodaResponseHeaders::STRICT_TRANSPORT_SECURITY].must_equal "max-age=63072000; includeSubDomains"
  end

  it "supports :preload option" do
    app(preload: true)
    req[1][RodaResponseHeaders::STRICT_TRANSPORT_SECURITY].must_equal "max-age=63072000; includeSubDomains; preload"
  end

  it "supports subdomains: false option" do
    app(subdomains: false)
    req[1][RodaResponseHeaders::STRICT_TRANSPORT_SECURITY].must_equal "max-age=63072000"
  end
end

describe "hsts plugin managed per-site policy" do
  HSTS = RodaResponseHeaders::STRICT_TRANSPORT_SECURITY
  DEFAULT_HSTS = "max-age=63072000; includeSubDomains"
  APPROVED_HOST = "www.example.com"
  UNKNOWN_HOST = "evil.example.net"
  TLS_DIRECT = {"HTTP_HOST" => APPROVED_HOST, "HTTPS" => "on"}
  TLS_PROXY = {"HTTP_HOST" => APPROVED_HOST, "HTTP_X_FORWARDED_PROTO" => "https", "rack.url_scheme" => "http"}
  PLAINTEXT = {"HTTP_HOST" => APPROVED_HOST, "rack.url_scheme" => "http"}
  UNCONFIRMED_TLS = {"HTTP_HOST" => UNKNOWN_HOST, "HTTPS" => "on"}

  def managed_app(opts={})
    app(:bare) do
      plugin :error_handler do |e|
        e.message
      end
      plugin :hsts, hosts: "www.example.com", **opts

      route do |r|
        r.get "boom" do
          raise ArgumentError, "route failure"
        end
        "ok"
      end
    end
  end

  it "sends the HSTS header for an approved host on a direct TLS response" do
    managed_app

    res = req("/", TLS_DIRECT)
    res[0].must_equal 200
    res[1][HSTS].must_equal DEFAULT_HSTS
  end

  it "sends the HSTS header when a trusted proxy terminates TLS" do
    managed_app

    res = req("/", TLS_PROXY)
    res[0].must_equal 200
    res[1][HSTS].must_equal DEFAULT_HSTS
  end

  it "uses the same HSTS policy for error routes of the main app" do
    managed_app

    res = req("/boom", TLS_DIRECT)
    res[0].must_equal 500
    res[1][HSTS].must_equal DEFAULT_HSTS

    res = req("/boom", TLS_PROXY)
    res[0].must_equal 500
    res[1][HSTS].must_equal DEFAULT_HSTS
  end

  it "does not send the HSTS header over a direct plaintext connection" do
    managed_app

    res = req("/", PLAINTEXT)
    res[0].must_equal 200
    res[1].wont_include(HSTS)

    res = req("/boom", PLAINTEXT)
    res[0].must_equal 500
    res[1].wont_include(HSTS)
  end

  it "does not send the HSTS header for an unconfirmed site, even over TLS" do
    managed_app

    res = req("/", UNCONFIRMED_TLS)
    res[0].must_equal 200
    res[1].wont_include(HSTS)

    res = req("/boom", UNCONFIRMED_TLS)
    res[0].must_equal 500
    res[1].wont_include(HSTS)
  end

  it "ignores the request port when comparing hosts" do
    managed_app

    res = req("/", "HTTP_HOST" => "#{APPROVED_HOST}:8443", "HTTPS" => "on")
    res[1][HSTS].must_equal DEFAULT_HSTS

    res = req("/", "HTTP_HOST" => "#{UNKNOWN_HOST}:443", "HTTPS" => "on")
    res[1].wont_include(HSTS)
  end

  it "supports arrays, regexps, and procs as the hosts option" do
    app(:bare) do
      plugin :hsts, hosts: %w"www.example.com api.example.com"
      route{|_| ""}
    end

    req("/", "HTTP_HOST" => "api.example.com", "HTTPS" => "on")[1][HSTS].must_equal DEFAULT_HSTS
    req("/", "HTTP_HOST" => "other.example.com", "HTTPS" => "on")[1].wont_include(HSTS)

    app(:bare) do
      plugin :hsts, hosts: /\A[-0-9a-f]+\.example\.com\z/
      route{|_| ""}
    end

    req("/", "HTTP_HOST" => "a-b1.example.com", "HTTPS" => "on")[1][HSTS].must_equal DEFAULT_HSTS
    req("/", "HTTP_HOST" => "bad.example.org", "HTTPS" => "on")[1].wont_include(HSTS)

    app(:bare) do
      plugin :hsts, hosts: proc{|host| host.end_with?(".example.com")}
      route{|_| ""}
    end

    req("/", "HTTP_HOST" => "api.example.com", "HTTPS" => "on")[1][HSTS].must_equal DEFAULT_HSTS
    req("/", "HTTP_HOST" => "api.example.org", "HTTPS" => "on")[1].wont_include(HSTS)
  end

  it "applies the configured max_age, subdomains, and preload options in managed mode" do
    managed_app(max_age: 31536000, subdomains: false, preload: true)

    res = req("/", TLS_DIRECT)
    res[1][HSTS].must_equal "max-age=31536000; preload"

    res = req("/", PLAINTEXT)
    res[1].wont_include(HSTS)
  end

  it "does not add the header to the default headers in managed mode" do
    managed_app

    app.default_headers.wont_include(HSTS)
  end

  it "keeps managed HSTS scoped to the app that configured the hosts" do
    main_app = app(:bare) do
      plugin :multi_run
      plugin :hsts, hosts: "www.example.com"
      route do |r|
        r.multi_run
        "main"
      end
    end

    sub_app = Class.new(Roda).class_exec do
      plugin :default_headers, "x-app" => "sub"
      route{|_| "sub"}
      self
    end

    main_app.run "sub", sub_app

    res = req("/sub", TLS_DIRECT)
    res[0].must_equal 200
    res[1][HSTS].must_be_nil
    res[1]["x-app"].must_equal "sub"

    res = req("/", TLS_DIRECT)
    res[1][HSTS].must_equal DEFAULT_HSTS
  end

  it "lets a mounted sub-app manage its own HSTS policy independently" do
    main_app = app(:bare) do
      plugin :multi_run
      plugin :hsts, hosts: "www.example.com"
      route do |r|
        r.multi_run
        "main"
      end
    end

    sub_app = Class.new(Roda).class_exec do
      plugin :hsts, hosts: "api.example.com"
      route{|_| "sub"}
      self
    end

    main_app.run "sub", sub_app

    req("/sub", "HTTP_HOST" => "www.example.com", "HTTPS" => "on")[1].wont_include(HSTS)
    req("/sub", "HTTP_HOST" => "api.example.com", "HTTPS" => "on")[1][HSTS].must_equal DEFAULT_HSTS
    req("/sub", "HTTP_HOST" => "api.example.com", "rack.url_scheme" => "http")[1].wont_include(HSTS)
  end

  it "still sends the header unconditionally when loaded without hosts" do
    app(:bare) do
      plugin :hsts
      route{|_| ""}
    end

    req("/", "rack.url_scheme" => "http")[1][HSTS].must_equal DEFAULT_HSTS
    req("/", "HTTP_HOST" => UNKNOWN_HOST, "rack.url_scheme" => "http")[1][HSTS].must_equal DEFAULT_HSTS
  end

  it "does not override an HSTS header explicitly set by a route" do
    app(:bare) do
      plugin :hsts, hosts: APPROVED_HOST
      route do |r|
        response[HSTS] = "max-age=60"
        "ok"
      end
    end

    req("/", TLS_DIRECT)[1][HSTS].must_equal "max-age=60"
  end

  it "keeps the managed policy working after the app is frozen" do
    app(:bare) do
      plugin :hsts, hosts: APPROVED_HOST
      route{|_| "ok"}
    end
    app.freeze

    req("/", TLS_DIRECT)[1][HSTS].must_equal DEFAULT_HSTS
    req("/", PLAINTEXT)[1].wont_include(HSTS)
    req("/", UNCONFIRMED_TLS)[1].wont_include(HSTS)
  end
end
