# frozen_string_literal: true

require "net/ftp"
require "test/unit"
require "ostruct"
require "socket"

class FTPDataConnectionScopeTest < Test::Unit::TestCase
  def pasv_reply(host, port)
    octets = host.split(".").map(&:to_i) + port.divmod(256)
    return "227 Entering Passive Mode (#{octets.join(",")})."
  end

  def fake_ftp(control_ip, family, grants = nil, use_pasv_ip: false)
    ftp = Net::FTP.new
    address = Addrinfo.new(Socket.sockaddr_in(21, control_ip), family)
    sock = OpenStruct.new(remote_address: address)
    ftp.instance_variable_set(:@bare_sock, sock)
    ftp.passive = true
    ftp.use_pasv_ip = use_pasv_ip
    ftp.data_connection_scope = grants unless grants.nil?
    return ftp
  end

  # Drives the passive branch of transfercmd with a synthetic reply.  Any
  # attempt to open a data socket is recorded instead of performed, so no port
  # is ever bound or connected.
  def drive_transfer(ftp, passive_reply, transfer_reply, command = "RETR foo")
    opened = []
    ftp.define_singleton_method(:sendcmd) do |cmd|
      case cmd
      when "PASV", "EPSV"
        passive_reply
      else
        transfer_reply
      end
    end
    ftp.define_singleton_method(:open_socket) do |host, port|
      opened.push([host, port])
      return Socket.pair(:UNIX, :STREAM).first
    end
    conn = ftp.send(:transfercmd, command)
    conn.close
    return opened
  end

  def test_scope_class_records_control_peer_and_negotiated_source
    scope = Net::FTPDataConnectionScope.new(["192.0.2.0/24"])
    decision = scope.evaluate(
      control_peer: "10.0.0.1",
      negotiated_host: "192.0.2.5",
      selected_host: "192.0.2.5",
      port: 3106,
      command: "RETR foo"
    )
    assert(decision.allowed?)
    assert_equal(:approved_grant, decision.verdict)
    assert_equal("10.0.0.1", decision.control_peer)
    assert_equal("192.0.2.5", decision.negotiated_host)
    assert_equal("192.0.2.5", decision.selected_host)
    assert_equal(3106, decision.port)
    assert_equal("RETR foo", decision.command)
    assert_not_nil(decision.grant)
    assert_same(decision, scope.decisions.last)
  end

  def test_decision_keeps_negotiated_source_when_control_peer_is_selected
    scope = Net::FTPDataConnectionScope.new(["192.0.2.0/24"])
    decision = scope.evaluate(
      control_peer: "10.0.0.1",
      negotiated_host: "203.0.113.66",
      selected_host: "10.0.0.1",
      port: 3106
    )
    assert(decision.allowed?)
    assert_equal(:co_located, decision.verdict)
    assert_equal("203.0.113.66", decision.negotiated_host)
    assert_equal("10.0.0.1", decision.selected_host)
    assert_equal("10.0.0.1", decision.control_peer)
  end

  def test_co_located_ipv4_passive_is_allowed_without_grant
    ftp = fake_ftp("10.0.0.1", Socket::AF_INET, [])
    opened = drive_transfer(ftp, pasv_reply("203.0.113.66", 3106),
                            "150 Opening data connection")
    assert_equal([["10.0.0.1", 3106]], opened)
    decision = ftp.data_connection_decisions.last
    assert(decision.allowed?)
    assert_equal(:co_located, decision.verdict)
    assert_equal("10.0.0.1", decision.control_peer)
    assert_equal("203.0.113.66", decision.negotiated_host)
    assert_equal("10.0.0.1", decision.selected_host)
  end

  def test_approved_ipv4_data_proxy_grant_allows_other_address
    grant = Net::FTPDataConnectionGrant.new(
      "192.0.2.0/24", label: "approved data proxy"
    )
    ftp = fake_ftp("10.0.0.1", Socket::AF_INET, [grant], use_pasv_ip: true)
    opened = drive_transfer(ftp, pasv_reply("192.0.2.5", 3106),
                            "150 Opening data connection")
    assert_equal([["192.0.2.5", 3106]], opened)
    decision = ftp.data_connection_decisions.last
    assert(decision.allowed?)
    assert_equal(:approved_grant, decision.verdict)
    assert_equal("10.0.0.1", decision.control_peer)
    assert_equal("192.0.2.5", decision.negotiated_host)
    assert_equal("192.0.2.5", decision.selected_host)
    assert_same(grant, decision.grant)
  end

  def test_out_of_scope_ipv4_decoy_creates_no_data_connection
    ftp = fake_ftp("10.0.0.1", Socket::AF_INET, ["192.0.2.0/24"],
                   use_pasv_ip: true)
    reply = pasv_reply("203.0.113.66", 3106)
    opened = []
    ftp.define_singleton_method(:sendcmd) { |_cmd| reply }
    ftp.define_singleton_method(:open_socket) do |host, port|
      opened.push([host, port])
      flunk "a data connection must not be opened for an out-of-scope candidate"
    end
    error = assert_raise(Net::FTPConnectionError) do
      ftp.send(:transfercmd, "RETR foo")
    end
    assert_match(/refused by data connection scope/, error.message)
    assert_empty(opened)
    decision = ftp.data_connection_decisions.last
    assert(decision.denied?)
    assert_equal(:out_of_scope, decision.verdict)
    assert_equal("10.0.0.1", decision.control_peer)
    assert_equal("203.0.113.66", decision.negotiated_host)
    assert_equal("203.0.113.66", decision.selected_host)
    assert_equal(3106, decision.port)
  end

  def test_expired_grant_only_affects_later_connections
    past = Time.now - 10
    future = Time.now + 10
    grant = Net::FTPDataConnectionGrant.new("192.0.2.0/24", expires_at: future)
    assert(grant.permit?("192.0.2.9", past))

    ftp = fake_ftp("10.0.0.1", Socket::AF_INET,
                   [Net::FTPDataConnectionGrant.new("192.0.2.0/24",
                                                    expires_at: past)],
                   use_pasv_ip: true)
    reply = pasv_reply("192.0.2.9", 3106)
    ftp.define_singleton_method(:sendcmd) { |_cmd| reply }
    ftp.define_singleton_method(:open_socket) do |_host, _port|
      flunk "an expired grant must not open a new data connection"
    end
    error = assert_raise(Net::FTPConnectionError) do
      ftp.send(:transfercmd, "RETR foo")
    end
    assert_match(/expired/, error.message)
    assert_equal(:expired, ftp.data_connection_decisions.last.verdict)
  end

  def test_ipv6_epsv_branch_uses_control_peer
    ftp = fake_ftp("2001:db8::1", Socket::AF_INET6, [])
    opened = drive_transfer(ftp, "229 Entering Extended Passive Mode (|||5210|)",
                            "150 Opening data connection")
    assert_equal([["2001:db8::1", 5210]], opened)
    decision = ftp.data_connection_decisions.last
    assert(decision.allowed?)
    assert_equal(:co_located, decision.verdict)
    assert_equal("2001:db8::1", decision.control_peer)
    assert_equal("2001:db8::1", decision.negotiated_host)
    assert_equal(5210, decision.port)
  end

  def test_ipv6_approved_proxy_grant
    ftp = fake_ftp("2001:db8::1", Socket::AF_INET6,
                   [Net::FTPDataConnectionGrant.new("2001:db8:1::/48")])
    decision = ftp.data_connection_scope.evaluate(
      control_peer: "2001:db8::1",
      negotiated_host: "2001:db8:1::7",
      port: 5210
    )
    assert(decision.allowed?)
    assert_equal(:approved_grant, decision.verdict)
    assert_equal("2001:db8:1::7", decision.negotiated_host)
  end

  def test_ipv6_out_of_scope_decoy_at_scope_level
    scope = Net::FTPDataConnectionScope.new(["2001:db8:1::/48"])
    decision = scope.evaluate(
      control_peer: "2001:db8::1",
      negotiated_host: "2001:db9::9",
      port: 5210
    )
    assert(decision.denied?)
    assert_equal(:out_of_scope, decision.verdict)
    assert_equal("2001:db9::9", decision.negotiated_host)
  end

  def test_without_scope_pasv_behavior_is_unchanged
    ftp = fake_ftp("10.0.0.1", Socket::AF_INET)
    assert_nil(ftp.data_connection_scope)
    assert_nil(ftp.data_connection_decisions)
    opened = drive_transfer(ftp, pasv_reply("203.0.113.66", 3106),
                            "150 Opening data connection")
    assert_equal([["10.0.0.1", 3106]], opened)
    assert_nil(ftp.data_connection_decisions)
  end

  def test_setter_coerces_arrays_and_nil
    ftp = Net::FTP.new
    ftp.data_connection_scope = ["10.0.0.0/8"]
    assert_kind_of(Net::FTPDataConnectionScope, ftp.data_connection_scope)
    assert_kind_of(Net::FTPDataConnectionGrant,
                   ftp.data_connection_scope.grants.first)
    ftp.data_connection_scope = nil
    assert_nil(ftp.data_connection_scope)
  end

  def test_initialize_accepts_scope_option
    scope = Net::FTPDataConnectionScope.new(["10.0.0.0/8"])
    ftp = Net::FTP.new(nil, data_connection_scope: scope)
    assert_same(scope, ftp.data_connection_scope)
  end
end
