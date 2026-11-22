require_relative "../spec_helper"
require "ipaddr"

describe "trusted_proxy plugin" do
  # Topology used by the management-application checks:
  #
  #   client -> edge proxy (10.0.8.0/24) -> app proxy (10.0.9.0/24) -> Roda
  #
  # The two proxy ranges are the trusted forwarding chain.  Management
  # actions are additionally limited to the office source network.
  EDGE_PROXY = "10.0.8.0/24"
  APP_PROXY = "10.0.9.0/24"
  OFFICE_NETWORK = IPAddr.new("192.0.2.0/24")

  def build_admin_app
    app(:bare) do
      plugin :trusted_proxy, [EDGE_PROXY, APP_PROXY]

      route do |r|
        r.on "admin" do
          source = IPAddr.new(r.ip)

          unless OFFICE_NETWORK.include?(source)
            response.status = 403
            next "forbidden"
          end

          # The duty log records the validated source and whether it was
          # attested by a fully trusted chain.  The raw header is never the
          # source of truth.
          response["X-Audit-Source"] = r.ip
          response["X-Audit-Confirmed"] = r.forwarded_ip?.to_s
          "ok"
        end
      end
    end
  end

  it "supports a direct request and ignores a spoofed forwarding header" do
    app(:bare) do
      plugin :trusted_proxy, [APP_PROXY]
      route do |r| "#{r.ip}|#{r.forwarded_ip?}" end
    end

    body("REMOTE_ADDR" => "192.0.2.10").must_equal "192.0.2.10|false"

    # Direct, untrusted peer: the attacker-controlled header is discarded.
    body(
      "REMOTE_ADDR" => "192.0.2.10",
      "HTTP_X_FORWARDED_FOR" => "192.0.2.50, 10.0.9.2"
    ).must_equal "192.0.2.10|false"
  end

  it "resolves the client across the two known proxy hops" do
    build_admin_app

    status(
      "/admin",
      "REMOTE_ADDR" => "10.0.9.2",
      "HTTP_X_FORWARDED_FOR" => "192.0.2.50, 10.0.8.1"
    ).must_equal 200

    response = req(
      "/admin",
      "REMOTE_ADDR" => "10.0.9.2",
      "HTTP_X_FORWARDED_FOR" => "192.0.2.50, 10.0.8.1"
    )[1]
    response["X-Audit-Source"].must_equal "192.0.2.50"
    response["X-Audit-Confirmed"].must_equal "true"
  end

  it "stops at the unknown upstream hop instead of trusting its claim" do
    build_admin_app

    # The app proxy attests to 198.51.100.7, but does not vouch for the
    # address before it.  198.51.100.7 is the nearest attested source and is
    # outside the office network, so the management action must not run.
    status(
      "/admin",
      "REMOTE_ADDR" => "10.0.9.2",
      "HTTP_X_FORWARDED_FOR" => "192.0.2.50, 198.51.100.7, 10.0.8.1"
    ).must_equal 403

    response = req(
      "/admin",
      "REMOTE_ADDR" => "10.0.9.2",
      "HTTP_X_FORWARDED_FOR" => "198.51.100.7, 10.0.8.1"
    )[1]
    response["X-Audit-Source"].must_be_nil
  end

  it "does not present a guess as fact when the chain cannot be confirmed" do
    build_admin_app

    # A non-parseable hop breaks the chain.  The validated source falls back
    # to the trusted peer and the request is reported as not forwarded.
    body(
      "/admin",
      "REMOTE_ADDR" => "10.0.9.2",
      "HTTP_X_FORWARDED_FOR" => "192.0.2.50, garbage, 10.0.8.1"
    ).must_equal "forbidden"

    response = req(
      "/admin",
      "REMOTE_ADDR" => "10.0.9.2",
      "HTTP_X_FORWARDED_FOR" => "192.0.2.50, garbage, 10.0.8.1"
    )[1]
    response["X-Audit-Source"].must_be_nil
  end

  it "falls back to the peer when no forwarding header is present" do
    app(:bare) do
      plugin :trusted_proxy, [APP_PROXY]
      route do |r| "#{r.ip}|#{r.forwarded_ip?}" end
    end

    body("REMOTE_ADDR" => "10.0.9.2").must_equal "10.0.9.2|false"
  end

  it "does not raise on a malformed direct peer and ignores the header" do
    app(:bare) do
      plugin :trusted_proxy, [APP_PROXY]
      route do |r| "#{r.ip}|#{r.forwarded_ip?}" end
    end

    body(
      "REMOTE_ADDR" => "not-an-ip",
      "HTTP_X_FORWARDED_FOR" => "192.0.2.50"
    ).must_equal "not-an-ip|false"
  end

  it "returns the peer when every forwarding entry is a trusted proxy" do
    app(:bare) do
      plugin :trusted_proxy, [EDGE_PROXY, APP_PROXY]
      route do |r| "#{r.ip}|#{r.forwarded_ip?}" end
    end

    body(
      "REMOTE_ADDR" => "10.0.9.2",
      "HTTP_X_FORWARDED_FOR" => "10.0.8.1, 10.0.8.2"
    ).must_equal "10.0.9.2|false"
  end

  it "normalizes whitespace, ports, and IPv6 brackets in the chain" do
    app(:bare) do
      plugin :trusted_proxy, [APP_PROXY]
      route do |r| "#{r.ip}|#{r.forwarded_ip?}" end
    end

    body(
      "REMOTE_ADDR" => "10.0.9.2",
      "HTTP_X_FORWARDED_FOR" => " 192.0.2.50:54001 , 10.0.9.3 "
    ).must_equal "192.0.2.50|true"

    body(
      "REMOTE_ADDR" => "10.0.9.2",
      "HTTP_X_FORWARDED_FOR" => "[2001:db8::abcd]:54001, 10.0.9.3"
    ).must_equal "2001:db8::abcd|true"
  end

  it "accepts a single range and a custom forwarding header" do
    app(:bare) do
      plugin :trusted_proxy, APP_PROXY, header: "X-Real-IP"
      route do |r| "#{r.ip}|#{r.forwarded_ip?}" end
    end

    body(
      "REMOTE_ADDR" => "10.0.9.2",
      "HTTP_X_REAL_IP" => "192.0.2.50"
    ).must_equal "192.0.2.50|true"

    # The default header is no longer consulted.
    body(
      "REMOTE_ADDR" => "10.0.9.2",
      "HTTP_X_FORWARDED_FOR" => "192.0.2.50"
    ).must_equal "10.0.9.2|false"
  end
end
