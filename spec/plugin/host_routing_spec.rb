require_relative "../spec_helper"

describe "host_routing plugin" do 
  it "adds support for routing based on host name" do
    app(:bare) do
      plugin :host_routing do |hosts|
        hosts.to :t1, "t1.Example.com"
        hosts.to :t2, "t2.Example.com", "tx.Example.com"
        hosts.default :t1
      end

      route do |r|
        r.t1 do
          "t1-#{r.t1?}-#{r.t2?}"
        end

        r.t2 do
          "t2-#{r.t1?}-#{r.t2?}"
        end
      end
    end

    2.times do
      body.must_equal 't1-true-false'
      body('HTTP_HOST'=>"t1.example.com").must_equal 't1-true-false'
      body('HTTP_HOST'=>"t2.example.com").must_equal 't2-false-true'
      body('HTTP_HOST'=>"tx.example.com").must_equal 't2-false-true'
      body('HTTP_HOST'=>"T1.example.com").must_equal 't1-true-false'
      body('HTTP_HOST'=>"T2.example.com").must_equal 't2-false-true'
      body('HTTP_HOST'=>"Tx.example.com").must_equal 't2-false-true'
      @app = Class.new(@app)
    end
  end

  it "hosts.default accepts a block evaluated in route block scope" do
    app(:bare) do
      plugin :host_routing do |hosts|
        hosts.register :t2, :t3
        hosts.default :t1 do |host|
          if host.start_with?('t2.example.com')
            :t2
          elsif request.GET['b']
            :t3
          end
        end
      end

      route do |r|
        r.t1 do
          "t1-#{r.t1?}-#{r.t2?}-#{r.t3?}"
        end

        r.t2 do
          "t2-#{r.t1?}-#{r.t2?}-#{r.t3?}"
        end

        r.t3 do
          "t3-#{r.t1?}-#{r.t2?}-#{r.t3?}"
        end
      end
    end

    body.must_equal 't1-true-false-false'
    body('HTTP_HOST'=>"t2.example.com").must_equal 't2-false-true-false'
    body('QUERY_STRING'=>"b=1").must_equal 't3-false-false-true'
    body('SERVER_NAME'=>"t2.example.com").must_equal 't2-false-true-false'
    body('HTTP_X_FORWARDED_HOST'=>"t2.example.com").must_equal 't2-false-true-false'
  end

  it "supports :scope_predicates option for also defining predicates in route block scope" do
    app(:bare) do
      plugin :host_routing, :scope_predicates=>true do |hosts|
        hosts.to :t2, "t2.example.com"
        hosts.default :t1
      end

      route do |r|
        r.t1 do
          "t1-#{t1?}-#{t2?}"
        end

        r.t2 do
          "t2-#{t1?}-#{t2?}"
        end
      end
    end

    body('HTTP_HOST'=>"t2.example.com").must_equal 't2-false-true'
    body('HTTP_HOST'=>"t1.example.com").must_equal 't1-true-false'
  end

  it "uses empty string for missing host" do
    app(:bare) do
      plugin :host_routing, :scope_predicates=>true do |hosts|
        hosts.to :t2, ""
        hosts.default :t1
      end

      route do |r|
        r.t1 do
          "t1-#{r.t1?}-#{r.t2?}"
        end

        r.t2 do
          "t2-#{r.t1?}-#{r.t2?}"
        end
      end
    end

    if Rack.release >= '2.1' && !ENV["LINT"]
      # Old rack versions would return host ":" for no SERVER_NAME and no SERVER_PORT
      # Rack::Lint support in spec/helper forces SERVER_NAME=example.com
      body.must_equal 't2-false-true'
    end
    unless Rack.release =~ /\A2\.2/
      # Rack 2.2 uses ":80" host in this case
      body('SERVER_NAME'=>'', 'SERVER_PORT'=>"80").must_equal 't2-false-true'
    end
    body('HTTP_HOST'=>"t1.example.com").must_equal 't1-true-false'
  end

  it "errors if default host is not provided" do
    proc{app.plugin(:host_routing){}}.must_raise Roda::RodaError
    app.plugin(:host_routing){|x| x.default :x}
  end

  describe "fallback and authorization policy" do
    def policy_app(log=[], &block)
      app(:bare) do
        plugin :host_routing do |hosts|
          hosts.to :www, "www.example.com"
          hosts.to :admin, "admin.example.com"
          hosts.register :admin_alias
          hosts.default :www do |host|
            :admin if host == "admin-old.example.com"
          end
          hosts.fallback :www
          hosts.require_authorization(:admin) do |host|
            host != "admin-old.example.com"
          end
        end

        route do |r|
          log << [r.request_method, r.path]

          r.get "status" do
            "status"
          end

          r.post "status" do
            "posted"
          end

          r.www do
            "www-#{r.www?}-#{r.admin?}"
          end

          r.admin do
            "admin-#{r.www?}-#{r.admin?}"
          end
        end
      end
    end

    it "routes configured and fallback hosts normally" do
      policy_app

      body('HTTP_HOST'=>"www.example.com").must_equal 'www-true-false'
      body('HTTP_HOST'=>"admin.example.com").must_equal 'admin-false-true'
      body('HTTP_HOST'=>"blog.example.com").must_equal 'www-true-false'
      body('HTTP_HOST'=>"WWW.EXAMPLE.COM").must_equal 'www-true-false'
    end

    it "rejects the retired admin alias without routing side effects" do
      log = []
      policy_app(log)

      status('HTTP_HOST'=>"admin-old.example.com").must_equal 403
      body('HTTP_HOST'=>"admin-old.example.com").must_equal ''
      body('/status', 'HTTP_HOST'=>"admin-old.example.com").must_equal ''
      body('/status', 'REQUEST_METHOD'=>'POST', 'HTTP_HOST'=>"admin-old.example.com").must_equal ''
      log.must_equal []
    end

    it "keeps original request predicates for registered hosts" do
      policy_app

      body('/status', 'HTTP_HOST'=>"admin.example.com").must_equal 'status'
      body('/status', 'HTTP_HOST'=>"www.example.com").must_equal 'status'
    end

    it "handles a subclass with the same policy" do
      policy_app

      @app = Class.new(@app)
      body('HTTP_HOST'=>"admin.example.com").must_equal 'admin-false-true'
      status('HTTP_HOST'=>"admin-old.example.com").must_equal 403
      body('HTTP_HOST'=>"admin-old.example.com").must_equal ''
    end

    it "does not affect hosts not mentioned by the policy" do
      app(:bare) do
        plugin :host_routing do |hosts|
          hosts.to :t2, "t2.example.com"
          hosts.default :t1
        end

        route do |r|
          r.t1{"t1"}
          r.t2{"t2"}
        end
      end

      body('HTTP_HOST'=>"t2.example.com").must_equal 't2'
      body('HTTP_HOST'=>"other.example.com").must_equal 't1'
    end

    it "rejects fallback selection of a type that is not marked as fallback" do
      app(:bare) do
        plugin :host_routing do |hosts|
          hosts.to :www, "www.example.com"
          hosts.register :admin
          hosts.default :www do |host|
            :admin if host.end_with?("admin.example.com")
          end
          hosts.fallback :www
          hosts.require_authorization :admin
        end

        route do |r|
          r.www{"www"}
          r.admin{"admin"}
        end
      end

      body('HTTP_HOST'=>"www.example.com").must_equal 'www'
      body('HTTP_HOST'=>"evil.admin.example.com").must_equal ''
      status('HTTP_HOST'=>"evil.admin.example.com").must_equal 403
    end

    it "supports a custom unauthorized handler" do
      app(:bare) do
        plugin :host_routing do |hosts|
          hosts.to :www, "www.example.com"
          hosts.to :admin, "admin.example.com"
          hosts.register :admin
          hosts.default :www do |host|
            :admin if host.start_with?("admin")
          end
          hosts.fallback :www
          hosts.require_authorization :admin
          hosts.unauthorized do |r|
            response.status = 403
            "denied #{r.host}"
          end
        end

        route do |r|
          r.www{"www"}
          r.admin{"admin"}
        end
      end

      body('HTTP_HOST'=>"admin.example.com").must_equal 'admin'
      body('HTTP_HOST'=>"admin2.example.com").must_equal 'denied admin2.example.com'
      status('HTTP_HOST'=>"admin2.example.com").must_equal 403
    end

    it "supports a default block alias that is authorized until retired" do
      app(:bare) do
        plugin :host_routing do |hosts|
          hosts.to :www, "www.example.com"
          hosts.to :admin, "admin.example.com"
          hosts.register :admin_alias
          hosts.default :www do |host|
            :admin_alias if host.end_with?(".admin.example.com")
          end
          hosts.fallback :www
          hosts.require_authorization(:admin_alias) do |host|
            host != "retired.admin.example.com"
          end
        end

        route do |r|
          r.www{"www"}
          r.admin_alias{"admin_alias-#{r.admin_alias?}"}
        end
      end

      body('HTTP_HOST'=>"current.admin.example.com").must_equal 'admin_alias-true'
      status('HTTP_HOST'=>"retired.admin.example.com").must_equal 403
      body('HTTP_HOST'=>"retired.admin.example.com").must_equal ''
    end

    it "authorizes only explicitly configured hostnames without an authorization block" do
      app(:bare) do
        plugin :host_routing do |hosts|
          hosts.to :www, "www.example.com"
          hosts.to :admin, "admin.example.com"
          hosts.register :admin
          hosts.default :www do |host|
            :admin if host.start_with?("admin")
          end
          hosts.fallback :www
          hosts.require_authorization :admin
        end

        route do |r|
          r.www{"www"}
          r.admin{"admin"}
        end
      end

      body('HTTP_HOST'=>"admin.example.com").must_equal 'admin'
      status('HTTP_HOST'=>"admin2.example.com").must_equal 403
      status('HTTP_HOST'=>"unknown.example.com").must_equal 200
    end

    it "allows configured non-fallback types but rejects unconfigured fallback selection" do
      app(:bare) do
        plugin :host_routing do |hosts|
          hosts.to :www, "www.example.com"
          hosts.to :admin, "admin.example.com"
          hosts.register :admin
          hosts.default :www do |host|
            :admin if host.start_with?("admin")
          end
          hosts.fallback :www
          hosts.require_authorization :admin do |_|
            false
          end
        end

        route do |r|
          r.www{"www"}
          r.admin{"admin"}
        end
      end

      status('HTTP_HOST'=>"admin.example.com").must_equal 403
      status('HTTP_HOST'=>"admin.example.com", 'PATH_INFO'=>"/other").must_equal 403
      body('HTTP_HOST'=>"www.example.com").must_equal 'www'
    end

    it "passes the hostname to zero-argument authorization blocks" do
      app(:bare) do
        plugin :host_routing do |hosts|
          hosts.to :www, "www.example.com"
          hosts.to :admin, "admin.example.com"
          hosts.default :www
          hosts.fallback :www
          hosts.require_authorization(:admin){false}
        end

        route do |r|
          r.www{"www"}
          r.admin{"admin"}
        end
      end

      status('HTTP_HOST'=>"admin.example.com").must_equal 403
      body('HTTP_HOST'=>"www.example.com").must_equal 'www'
    end
  end
end
