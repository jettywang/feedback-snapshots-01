#!/usr/bin/env ruby
# frozen_string_literal: true

require "json"
require "fileutils"

ROOT = File.expand_path("..", __dir__)
$LOAD_PATH.unshift(File.join(ROOT, "lib"))
require "net/ftp"

module ConnectionAudit
  CONFIG_PATH = File.join(ROOT, "audit", "migration-config.json")
  OUTPUT_DIR = File.join(ROOT, "audit", "out")

  def self.sanitize_line(line)
    line.sub(/\APASS .*/i, "PASS ***")
  end

  class Ledger
    KINDS = %w[connect listen accept control_reply].freeze

    attr_reader :events, :output_dir

    def initialize(output_dir)
      @output_dir = output_dir
      @events = []
      @mutex = Mutex.new
      @seq = 0
      FileUtils.mkdir_p(output_dir)
    end

    def record(kind, **fields)
      event = nil
      @mutex.synchronize do
        @seq += 1
        event = {
          seq: @seq,
          kind: kind,
          scenario: Thread.current[:audit_scenario]
        }.merge(compact(fields))
        @events << event
      end
      event
    end

    def write!
      File.write(File.join(@output_dir, "records.json"), JSON.pretty_generate(@events) + "\n")
      KINDS.each do |kind|
        lines = @events.select { |event| event[:kind] == kind }
                       .map { |event| JSON.generate(event) }
        File.write(File.join(@output_dir, "#{kind}.jsonl"), lines.join("\n") + (lines.empty? ? "" : "\n"))
      end
    end

    private

    def compact(hash)
      hash.reject { |_, value| value.nil? }
    end
  end

  class AddressDouble
    attr_reader :ip_address, :ip_port, :note

    def initialize(ip_address, ip_port = nil, note = nil)
      @ip_address = ip_address
      @ip_port = ip_port
      @note = note
    end

    def ipv4?
      @ip_address.include?(".")
    end

    def ipv6?
      @ip_address.include?(":")
    end

    def to_h
      { "ip_address" => @ip_address, "ip_port" => @ip_port, "note" => @note }.compact
    end
  end

  module SourceTrace
    def self.net_ftp_frame
      location = caller_locations(1, 50).find do |candidate|
        candidate.path&.end_with?("lib/net/ftp.rb")
      end
      return nil unless location

      relative = location.path.sub("#{ROOT}/", "")
      "#{relative}:#{location.lineno}:in `#{location.label}'"
    end
  end

  class RecordingSocketDouble
    attr_reader :local_address, :remote_address, :closed

    def initialize(audit, role:, local_address:, remote_address:, replies: [])
      @audit = audit
      @ledger = audit.ledger
      @role = role
      @local_address = local_address
      @remote_address = remote_address
      @incoming = "".b
      @closed = false
      replies.each { |line| record_initial_reply(line) }
      @incoming << replies.map { |line| with_crlf(line) }.join.b
    end

    def read_nonblock(maxlen, _buffer = nil, exception: false)
      if @incoming.empty?
        return nil
      end

      chunk = @incoming.byteslice(0, maxlen)
      remainder = @incoming.byteslice(chunk.bytesize..-1)
      @incoming = remainder ? remainder.b : "".b
      chunk
    end

    def write_nonblock(buffer, exception: false)
      consume_write(buffer)
      buffer.bytesize
    end

    def write(buffer)
      consume_write(buffer)
      buffer.bytesize
    end

    def close
      return if @closed

      @closed = true
      @ledger.record("socket_close", role: @role, local: @local_address.to_h,
                                     remote: @remote_address.to_h)
    end

    def closed?
      @closed
    end

    def shutdown(_how = nil)
      @ledger.record("socket_shutdown", role: @role)
      0
    end

    def to_io
      self
    end

    def wait_readable(_timeout = nil)
      true
    end

    private

    def consume_write(buffer)
      buffer.to_s.split("\r\n").reject(&:empty?).each do |raw_line|
        line = ConnectionAudit.sanitize_line(raw_line)
        @ledger.record("control_command", role: @role, line: line)
        route(line) if @role == "control"
      end
    end

    def route(line)
      reply =
        case line
        when /\AUSER / then "331 Please specify the password."
        when /\APASS / then "230 Login successful."
        when /\ATYPE / then "200 Switching to Binary mode."
        when /\APORT / then "200 PORT command successful."
        when /\AEPRT / then "200 EPRT command successful."
        when /\APASV\b/ then @audit.current_scenario[:pasv_ipv4_reply]
        when /\AEPSV\b/ then @audit.current_scenario[:epsv_reply]
        when /\A(?:RETR|STOR|LIST|NLST|MLSD)\b/ then "150 File status okay; about to open data connection."
        when /\AQUIT\b/ then "221 Goodbye."
        else "200 Command okay."
        end

      enqueue_reply(reply)
    end

    def enqueue_reply(line)
      @incoming << with_crlf(line)
      @ledger.record("control_reply", role: @role, code: line[0, 3], line: line,
                                      source: "RecordingSocketDouble#route")
    end

    def record_initial_reply(line)
      @ledger.record("control_reply", role: @role, code: line[0, 3], line: line,
                                      source: "RecordingSocketDouble#initialize")
    end

    def with_crlf(line)
      line.end_with?("\r\n") ? line : "#{line}\r\n"
    end
  end

  class AcceptedDataDouble < RecordingSocketDouble
    def initialize(audit, local_address:, remote_address:)
      super(audit, role: "accepted_data", local_address: local_address,
                   remote_address: remote_address)
    end
  end

  class ListenerDouble
    def initialize(audit, local_address:, peer_address:)
      @audit = audit
      @ledger = audit.ledger
      @local_address = local_address
      @peer_address = peer_address
      @closed = false
    end

    def local_address
      @local_address
    end

    def accept
      @ledger.record("accept", status: "returned", local: @local_address.to_h,
                               peer: @peer_address.to_h,
                               source: SourceTrace.net_ftp_frame)
      data = AcceptedDataDouble.new(@audit, local_address: @local_address,
                                           remote_address: @peer_address)
      [data, @peer_address]
    end

    def shutdown(_how = nil)
      @ledger.record("listener_shutdown", local: @local_address.to_h)
      0
    end

    def read(_length = nil)
      @ledger.record("listener_drain", local: @local_address.to_h)
      nil
    end

    def close
      return if @closed

      @closed = true
      @ledger.record("listener_close", local: @local_address.to_h)
    end
  end

  class AddrinfoTcpDouble
    def initialize(audit, ip_address, requested_port)
      @audit = audit
      @ip_address = ip_address
      @requested_port = requested_port
    end

    def listen(_backlog = nil)
      scenario = @audit.current_scenario
      assigned_port = @requested_port.zero? ? scenario[:active_double_port] : @requested_port
      local = AddressDouble.new(@ip_address, assigned_port, "recording-listener")
      @audit.ledger.record(
        "listen",
        requested_host: @ip_address,
        requested_port: @requested_port,
        backlog_called: true,
        local_address: local.to_h,
        source: SourceTrace.net_ftp_frame
      )
      ListenerDouble.new(@audit, local_address: local,
                                 peer_address: scenario[:server_data_peer])
    end
  end

  class AuditRunner
    attr_reader :config, :ledger, :results
    attr_accessor :current_scenario

    def initialize(config_path = CONFIG_PATH, output_dir = OUTPUT_DIR)
      @config = JSON.parse(File.read(config_path))
      @ledger = Ledger.new(output_dir)
      @results = []
      @current_scenario = nil
      @original_socks_server = ENV["SOCKS_SERVER"]
    end

    def install_socket_doubles!
      audit = self

      Socket.define_singleton_method(:tcp) do |host, port, *args, **kwargs|
        audit.open_tcp_double(host, port, *args, **kwargs)
      end

      Addrinfo.define_singleton_method(:tcp) do |host, port|
        audit.addrinfo_tcp_double(host, port)
      end

      socks_class = Class.new do
        define_singleton_method(:open) do |host, port|
          audit.open_socks_double(host, port)
        end
      end
      Object.send(:remove_const, :SOCKSSocket) if Object.const_defined?(:SOCKSSocket)
      Object.const_set(:SOCKSSocket, socks_class)
    end

    def addrinfo_tcp_double(host, port)
      @ledger.record("addrinfo_tcp", requested_host: host, requested_port: port,
                                     source: SourceTrace.net_ftp_frame)
      AddrinfoTcpDouble.new(self, host, port)
    end

    def open_tcp_double(host, port, *_args, **_kwargs)
      role = call_role
      source = SourceTrace.net_ftp_frame
      local = local_address_for(role, host)
      remote = AddressDouble.new(host, port, "Socket.tcp requested peer")
      socket = RecordingSocketDouble.new(
        self,
        role: role,
        local_address: local,
        remote_address: remote,
        replies: role == "control" ? ["220 recording FTP ready."] : []
      )
      @ledger.record("connect", impl: "Socket.tcp", role: role,
                                requested_host: host, requested_port: port,
                                local_address: local.to_h,
                                remote_address: remote.to_h, source: source)
      socket
    end

    def open_socks_double(host, port)
      scenario = current_scenario
      role = call_role
      chain = scenario[:proxy_chain]
      first_hop = proxy_address(chain.first, scenario[:family])
      client_to_proxy = AddressDouble.new(scenario[:client_ip], 51_000 + @results.length,
                                         "client address toward first proxy")
      actual_peer = first_hop
      logical_target = AddressDouble.new(host, port, "application target passed to SOCKSSocket.open")
      exposed_remote =
        if scenario[:proxy_peer_mode] == "preserve_target"
          logical_target
        else
          AddressDouble.new(first_hop.ip_address, first_hop.ip_port,
                            "actual TCP peer visible to TCPSocket-style #remote_address")
        end

      @ledger.record("connect", impl: "SOCKSSocket.open", role: role,
                                requested_host: host, requested_port: port,
                                socks_server_env: ENV["SOCKS_SERVER"],
                                local_address: client_to_proxy.to_h,
                                application_target: logical_target.to_h,
                                actual_peer: actual_peer.to_h,
                                remote_address_exposed_to_net_ftp: exposed_remote.to_h,
                                source: SourceTrace.net_ftp_frame)

      chain.each_cons(2) do |upstream, downstream|
        @ledger.record("proxy_leg", hop: "#{upstream['name']}->#{downstream['name']}",
                                    source_proxy: proxy_address(upstream, scenario[:family]).to_h,
                                    destination_proxy: proxy_address(downstream, scenario[:family]).to_h)
      end
      last_proxy = chain.last
      @ledger.record("proxy_leg", hop: "#{last_proxy['name']}->application-target",
                                  destination: logical_target.to_h,
                                  note: "assumed proxy egress; not visible in Net::FTP socket")

      RecordingSocketDouble.new(
        self,
        role: role,
        local_address: client_to_proxy,
        remote_address: exposed_remote,
        replies: role == "control" ? ["220 recording FTP ready via SOCKS."] : []
      )
    end

    def run_all
      install_socket_doubles!
      scenario_definitions.each do |scenario|
        run_scenario(scenario)
      ensure
        ENV["SOCKS_SERVER"] = @original_socks_server
      end
      @ledger.write!
      write_outputs!
      self
    end

    def scenario_definitions
      e = @config["reference_endpoints"]
      chain = @config["after"]["proxy_chain"]
      v4_client = e["client_ipv4"]
      v6_client = e["client_ipv6"]
      v4_server = e["ftp_ipv4"]
      v6_server = e["ftp_ipv6"]
      declared_v4 = e["ftp_pasv_declared_ipv4"]
      pasv_port = e["pasv_port"]
      active_port = e["active_double_port"]
      data_source_port = e["ftp_data_source_port_reference"]

      [
        {
          id: "ipv4_active_complete", family: "ipv4", mode: "active", run: :complete,
          client_ip: v4_client, server_ip: v4_server, active_double_port: active_port,
          server_control: AddressDouble.new(v4_server, Net::FTP::FTP_PORT),
          server_data_peer: AddressDouble.new(v4_server, data_source_port, "reference active source port"),
          passive: false, use_pasv_ip: false, socks: false, proxy_chain: [],
          file: "archive-20261126.tar"
        },
        {
          id: "ipv6_active_complete", family: "ipv6", mode: "active", run: :complete,
          client_ip: v6_client, server_ip: v6_server, active_double_port: active_port,
          server_control: AddressDouble.new(v6_server, Net::FTP::FTP_PORT),
          server_data_peer: AddressDouble.new(v6_server, data_source_port, "reference active source port"),
          passive: false, use_pasv_ip: false, socks: false, proxy_chain: [],
          file: "archive-20261126.tar"
        },
        passive_scenario(
          id: "ipv4_passive_default_peer_complete", family: "ipv4",
          client_ip: v4_client, server_ip: v4_server, declared_ip: declared_v4,
          pasv_port: pasv_port, use_pasv_ip: false,
          reply: "227 Entering Passive Mode (#{quads(declared_v4)},#{port_bytes(pasv_port)})."
        ),
        passive_scenario(
          id: "ipv4_passive_declared_complete", family: "ipv4",
          client_ip: v4_client, server_ip: v4_server, declared_ip: declared_v4,
          pasv_port: pasv_port, use_pasv_ip: true,
          reply: "227 Entering Passive Mode (#{quads(declared_v4)},#{port_bytes(pasv_port)})."
        ),
        passive_scenario(
          id: "ipv6_passive_complete", family: "ipv6",
          client_ip: v6_client, server_ip: v6_server, declared_ip: v6_server,
          pasv_port: pasv_port, use_pasv_ip: false,
          reply: "229 Entering Extended Passive Mode (|||#{pasv_port}|)."
        ),
        {
          id: "active_ipv4_preliminary_only", family: "ipv4", mode: "active",
          run: :preliminary_only, client_ip: v4_client, server_ip: v4_server,
          active_double_port: active_port,
          server_control: AddressDouble.new(v4_server, Net::FTP::FTP_PORT),
          server_data_peer: AddressDouble.new(v4_server, data_source_port),
          passive: false, use_pasv_ip: false, socks: false, proxy_chain: [],
          file: "stop-after-150.tar"
        },
        passive_scenario(
          id: "proxy2_v4_passive_declared_chain", family: "ipv4",
          client_ip: v4_client, server_ip: v4_server, declared_ip: declared_v4,
          pasv_port: pasv_port, use_pasv_ip: true, socks: true,
          proxy_chain: chain, proxy_peer_mode: "actual_proxy",
          reply: "227 Entering Passive Mode (#{quads(declared_v4)},#{port_bytes(pasv_port)})."
        ),
        passive_scenario(
          id: "proxy2_v6_passive_preserved_peer_chain", family: "ipv6",
          client_ip: v6_client, server_ip: v6_server, declared_ip: v6_server,
          pasv_port: pasv_port, use_pasv_ip: false, socks: true,
          proxy_chain: chain, proxy_peer_mode: "preserve_target",
          reply: "229 Entering Extended Passive Mode (|||#{pasv_port}|)."
        ),
        passive_scenario(
          id: "proxy2_v6_passive_actual_peer_mismatch", family: "ipv6",
          client_ip: v6_client, server_ip: v6_server, declared_ip: v6_server,
          pasv_port: pasv_port, use_pasv_ip: false, socks: true,
          proxy_chain: chain, proxy_peer_mode: "actual_proxy",
          reply: "229 Entering Extended Passive Mode (|||#{pasv_port}|)."
        ),
        {
          id: "proxy2_active_not_committable", family: "ipv4", mode: "active", run: :complete,
          client_ip: v4_client, server_ip: v4_server, active_double_port: active_port,
          server_control: AddressDouble.new(v4_server, Net::FTP::FTP_PORT),
          server_data_peer: AddressDouble.new(v4_server, data_source_port),
          passive: false, use_pasv_ip: false, socks: true, proxy_chain: chain,
          proxy_peer_mode: "actual_proxy", force_active_after_connect: true,
          file: "proxy-active.tar"
        }
      ]
    end

    def passive_scenario(id:, family:, client_ip:, server_ip:, declared_ip:, pasv_port:,
                         use_pasv_ip:, reply:, socks: false, proxy_chain: [],
                         proxy_peer_mode: "actual_proxy")
      {
        id: id, family: family, mode: "passive", run: :complete,
        client_ip: client_ip, server_ip: server_ip,
        server_control: AddressDouble.new(server_ip, Net::FTP::FTP_PORT),
        server_data_peer: nil, passive: true, use_pasv_ip: use_pasv_ip,
        socks: socks, proxy_chain: proxy_chain, proxy_peer_mode: proxy_peer_mode,
        pasv_ipv4_reply: family == "ipv4" ? reply : "227 unused.",
        epsv_reply: family == "ipv6" ? reply : "229 unused.",
        declared_address: AddressDouble.new(declared_ip, pasv_port, "server-declared"),
        pasv_port: pasv_port, file: "passive-transfer.tar"
      }
    end

    def run_scenario(scenario)
      @current_scenario = scenario
      Thread.current[:audit_scenario] = scenario[:id]
      ENV["SOCKS_SERVER"] = scenario[:socks] ? @config["after"]["env"]["SOCKS_SERVER"] : nil

      ftp = Net::FTP.new(nil, passive: scenario[:passive],
                              use_pasv_ip: scenario[:use_pasv_ip],
                              open_timeout: 1, read_timeout: 1)
      ftp.connect(scenario[:server_ip], Net::FTP::FTP_PORT)
      passive_after_connect = ftp.passive
      if scenario[:force_active_after_connect]
        ftp.passive = false
      end
      ftp.login("archive-agent", "recording-double-password")

      execution_error = nil
      begin
        if scenario[:run] == :preliminary_only
          run_preliminary_only(ftp, scenario)
        else
          data = ftp.send(:transfercmd, "RETR #{scenario[:file]}")
          data.close
        end
      rescue StandardError => error
        execution_error = "#{error.class}: #{error.message}"
      ensure
        ftp.close unless ftp.closed?
      end

      result = analyze(scenario, ftp, passive_after_connect, execution_error)
      @results << result
      result
    ensure
      @current_scenario = nil
      Thread.current[:audit_scenario] = nil
    end

    def run_preliminary_only(ftp, scenario)
      listener = ftp.send(:makeport)
      listener_address = listener.local_address
      ftp.send(:sendport, listener_address.ip_address, listener_address.ip_port)
      reply = ftp.send(:sendcmd, "RETR #{scenario[:file]}")
      unless reply.start_with?("1")
        raise Net::FTPReplyError, "expected preliminary reply, got #{reply.inspect}"
      end

      # Deliberately do not call listener.accept. This is the stopping point
      # required by the audit: after the 1XX reply and before accept evidence.
      listener.close
    end

    def analyze(scenario, ftp, passive_after_connect, execution_error)
      events = @ledger.events.select { |event| event[:scenario] == scenario[:id] }
      bare = ftp.instance_variable_get(:@bare_sock)
      control_local = address_hash(bare.local_address)
      control_remote = address_hash(bare.remote_address)
      connect_events = events.select { |event| event[:kind] == "connect" }
      listen_events = events.select { |event| event[:kind] == "listen" }
      accept_events = events.select { |event| event[:kind] == "accept" }
      reply_events = events.select { |event| event[:kind] == "control_reply" }
      data_connect = connect_events.find { |event| event[:role] == "passive_data" }
      preliminary_reply = reply_events.find { |event| event[:code]&.start_with?("1") }
      active_command = events.map { |event| event[:line] }.compact
                             .find { |line| line.start_with?("PORT ", "EPRT ") }
      advertised = decode_active_command(active_command)
      declared = extract_server_declared(reply_events, scenario)

      checks = build_checks(
        scenario: scenario, events: events, control_local: control_local,
        control_remote: control_remote, listen_events: listen_events,
        accept_events: accept_events, data_connect: data_connect,
        preliminary_reply: preliminary_reply, advertised: advertised,
        declared: declared, passive_after_connect: passive_after_connect
      )
      paths = build_paths(
        scenario: scenario, control_remote: control_remote,
        listen_events: listen_events, accept_events: accept_events,
        data_connect: data_connect
      )
      verdict = verdict_for(scenario, checks, execution_error)

      {
        id: scenario[:id],
        family: scenario[:family],
        mode: scenario[:mode],
        run: scenario[:run].to_s,
        proxy_tier_count: scenario[:proxy_chain].length,
        configuration: {
          passive_option: scenario[:passive],
          passive_after_connect: passive_after_connect,
          use_pasv_ip: scenario[:use_pasv_ip],
          socks_server_env: scenario[:socks] ? @config["after"]["env"]["SOCKS_SERVER"] : nil,
          proxy_peer_mode: scenario[:proxy_peer_mode]
        }.compact,
        execution_error: execution_error,
        control_local_address: control_local,
        control_peer_address: control_remote,
        control_derived_address: control_remote&.slice("ip_address"),
        server_declared_address: declared,
        active_advertised_address: advertised,
        data_connection_target: data_connect && {
          host: data_connect[:requested_host], port: data_connect[:requested_port],
          impl: data_connect[:impl]
        },
        last_response: ftp.last_response,
        event_counts: events.group_by { |event| event[:kind] }.transform_values(&:length),
        checks: checks,
        required_paths: paths,
        verdict: verdict[:status],
        judgment: verdict[:judgment],
        non_committable: verdict[:non_committable]
      }
    end

    def write_outputs!
      comparison = build_config_comparison
      plan = {
        repeat_command: "ruby audit/run.rb",
        scope: "No real sockets or binds; Socket.tcp, Addrinfo.tcp, and SOCKSSocket are recording doubles.",
        source_calls: {
          control_socket: "lib/net/ftp.rb:406 open_socket(host, port)",
          socket_selection: "lib/net/ftp.rb:367-375",
          active_listen: "lib/net/ftp.rb:556 Addrinfo.tcp(@bare_sock.local_address.ip_address, 0).listen",
          active_command: "lib/net/ftp.rb:541-551 sendport/port/EPRT",
          active_order: "lib/net/ftp.rb:595-611 listen, PORT/EPRT, 1XX reply, accept",
          passive_selection: "lib/net/ftp.rb:561-568 PASV/227 or EPSV/229",
          passive_connect: "lib/net/ftp.rb:577 open_socket(host, port)"
        },
        config_comparison: comparison,
        scenarios: @results
      }
      File.write(File.join(@ledger.output_dir, "plan.json"), JSON.pretty_generate(plan) + "\n")
      File.write(File.join(ROOT, "audit", "out", "config-comparison.json"),
                 JSON.pretty_generate(comparison) + "\n")
      markdown = MarkdownReport.new(@config, plan).render
      File.write(File.join(ROOT, "audit", "out", "connection-plan.md"), markdown)
      File.write(File.join(ROOT, "audit", "CONNECTION_PLAN.md"), markdown)
    end

    private

    def build_checks(scenario:, events:, control_local:, control_remote:, listen_events:,
                     accept_events:, data_connect:, preliminary_reply:, advertised:, declared:,
                     passive_after_connect:)
      checks = []
      add_check(checks, "control_connect_recorded",
                events.any? { |event| event[:kind] == "connect" && event[:role] == "control" },
                "one connect event with role=control")
      add_check(checks, "control_peer_available_to_net_ftp",
                !control_remote.nil? && !control_remote["ip_address"].nil?,
                "@bare_sock.remote_address.ip_address=#{control_remote&.dig('ip_address')}")
      if scenario[:socks] && scenario[:passive] == false
        add_check(checks, "socks_hook_forces_passive_during_connect",
                  passive_after_connect == true,
                  "passive option=false, passive immediately after connect=#{passive_after_connect}; audit then explicitly re-enables active for that scenario")
      end

      if scenario[:mode] == "passive"
        reply_name = scenario[:family] == "ipv6" ? "229/EPSV" : "227/PASV"
        add_check(checks, "server_declared_#{reply_name.downcase}_recorded",
                  !declared.nil?, "declared=#{declared.inspect}")
        add_check(checks, "passive_data_connect_recorded",
                  !data_connect.nil?, "data connect=#{data_connect&.slice(:requested_host, :requested_port)&.inspect}")
        if data_connect && declared
          add_check(checks, "passive_port_matches_reply",
                    data_connect[:requested_port] == declared[:port],
                    "connect port #{data_connect[:requested_port]} vs reply port #{declared[:port]}")
          expected_host =
            if scenario[:family] == "ipv4" && scenario[:use_pasv_ip]
              declared[:host]
            else
              control_remote["ip_address"]
            end
          add_check(checks, "passive_host_matches_net_ftp_selection",
                    data_connect[:requested_host] == expected_host,
                    "connect host #{data_connect[:requested_host]} vs selected #{expected_host}")
          if scenario[:id] == "proxy2_v6_passive_actual_peer_mismatch"
            add_check(checks, "derived_proxy_address_is_not_the_ftp_data_endpoint",
                      false,
                      "Net::FTP selected #{data_connect[:requested_host]}; FTP-side endpoint is #{scenario[:server_ip]}",
                      expected: true)
          end
        end
      else
        listen = listen_events.first
        add_check(checks, "active_listen_recorded", !listen.nil?,
                  "listen=#{listen&.dig(:local_address)&.inspect}")
        add_check(checks, "active_advertised_command_recorded", !advertised.nil?,
                  "advertised=#{advertised.inspect}")
        if listen && advertised
          listen_addr = listen[:local_address]
          add_check(checks, "advertised_address_matches_listener",
                    advertised[:ip_address] == listen_addr["ip_address"] &&
                      advertised[:port] == listen_addr["ip_port"],
                    "PORT/EPRT #{advertised[:ip_address]}:#{advertised[:port]} vs listen #{listen_addr['ip_address']}:#{listen_addr['ip_port']}")
          add_check(checks, "listener_uses_control_local_address_family",
                    listen[:requested_host] == control_local["ip_address"],
                    "Addrinfo.tcp(#{listen[:requested_host]},0) vs bare_sock.local_address=#{control_local['ip_address']}")
        end
        if scenario[:run] == :complete
          preliminary_seq = preliminary_reply&.dig(:seq)
          accept = accept_events.first
          add_check(checks, "accept_recorded", !accept.nil?,
                    "accept=#{accept&.dig(:peer)&.inspect}")
          add_check(checks, "preliminary_reply_precedes_accept",
                    preliminary_seq && accept && preliminary_seq < accept[:seq],
                    "1XX seq=#{preliminary_seq}, accept seq=#{accept&.dig(:seq)}")
        else
          add_check(checks, "preliminary_reply_recorded", !preliminary_reply.nil?,
                    preliminary_reply&.dig(:line).to_s)
          add_check(checks, "no_accept_for_preliminary_only_stop",
                    accept_events.empty?, "accept event count=#{accept_events.length}")
          add_check(checks, "data_establishment_not_proven",
                    accept_events.empty? && data_connect.nil?,
                    "1XX alone is not evidence; no accept return or data connect return")
        end
      end

      if scenario[:mode] == "active" && scenario[:socks]
        add_check(checks, "reverse_proxy_bind_or_callback_operation_observed",
                  false,
                  "Net::FTP calls only local listen/PORT/EPRT; recording ledger has no proxy BIND API call",
                  expected: true)
      end

      checks
    end

    def build_paths(scenario:, control_remote:, listen_events:, accept_events:, data_connect:)
      paths = []
      chain = scenario[:proxy_chain]
      if scenario[:socks]
        p1 = proxy_address(chain.first, scenario[:family])
        paths << path("client-egress", "#{scenario[:client_ip]} -> #{p1.ip_address}:#{p1.ip_port}/tcp",
                      "open only this from the client host", true)
        chain.each_cons(2) do |up, down|
          a = proxy_address(up, scenario[:family])
          b = proxy_address(down, scenario[:family])
          paths << path("proxy-internal", "#{a.ip_address}:#{a.ip_port} -> #{b.ip_address}:#{b.ip_port}/tcp",
                        "proxy-to-proxy policy; not controlled by Net::FTP", nil)
        end
        if scenario[:mode] == "passive" && data_connect
          last = chain.last
          paths << path("proxy-final-egress",
                        "#{last['name']} -> #{data_connect[:requested_host]}:#{data_connect[:requested_port]}/tcp",
                        "final proxy egress must allow the host Net::FTP passed to SOCKSSocket.open", nil)
        else
          paths << path("proxy-callback", "FTP data peer -> active listener -> client/proxy chain",
                        "stock Net::FTP has no SOCKS BIND/reverse-proxy call; no committable path", false)
        end
      else
        paths << path("client-egress",
                      "#{scenario[:client_ip]} -> #{scenario[:server_ip]}:21/tcp",
                      "FTP control connection", true)
        if scenario[:mode] == "passive" && data_connect
          paths << path("client-egress",
                        "#{scenario[:client_ip]} -> #{data_connect[:requested_host]}:#{data_connect[:requested_port]}/tcp",
                        "passive data connection", true)
        elsif scenario[:mode] == "active"
          listen = listen_events.first
          target = listen&.dig(:local_address)
          peer = accept_events.first&.dig(:peer) || scenario[:server_data_peer]&.to_h
          if target
            paths << path("client-ingress",
                          "#{peer&.dig('ip_address') || scenario[:server_ip]}:#{peer&.dig('ip_port') || '*'}/tcp -> #{target['ip_address']}:#{target['ip_port']}/tcp",
                          "active server callback; fake port is deterministic, real bind uses port 0/ephemeral",
                          scenario[:run] == :complete)
          end
        end
      end
      paths
    end

    def path(owner, tuple, note, committable)
      { owner: owner, tuple: tuple, note: note, committable_in_plan: committable }
    end

    def verdict_for(scenario, checks, execution_error)
      unexpected_failed = checks.reject { |check| check[:ok] || check[:expected_non_committable] }
      if execution_error
        { status: "error", judgment: "替身执行失败：#{execution_error}", non_committable: ["修复审计脚本或替身场景"] }
      elsif unexpected_failed.any?
        { status: "check_failed", judgment: unexpected_failed.map { |check| check[:name] }.join(", "), non_committable: ["地址对账失败"] }
      elsif scenario[:run] == :preliminary_only
        {
          status: "inconclusive",
          judgment: "已收到 1XX 预备控制回复，但没有 accept 返回或被动数据 connect 返回；不能判定数据连接建成。",
          non_committable: ["真实数据通道建立"]
        }
      elsif scenario[:mode] == "active" && scenario[:socks]
        {
          status: "not_committable",
          judgment: "Net::FTP 仅完成本地 listen 与 PORT/EPRT，没有调用 SOCKS BIND 或任何反向代理接口；真实回连通路无法承诺。",
          non_committable: ["两级正向代理后的主动回连", "外部通告地址转换"]
        }
      elsif scenario[:id] == "proxy2_v6_passive_actual_peer_mismatch"
        {
          status: "not_committable",
          judgment: "TCPSocket 式 SOCKS 套接字的 remote_address 是第一级代理；EPSV 又不带主机，导致 Net::FTP 把数据目标选成代理地址而非 FTP 主机。",
          non_committable: ["actual-peer 语义下的 IPv6/EPSV 目标", "必须在预发核对代理套接字的 remote_address"]
        }
      elsif scenario[:socks]
        {
          status: "conditional",
          judgment: "记录型替身中的调用顺序和地址选择一致；生产仍取决于两级代理策略、代理协议和 remote_address 语义。",
          non_committable: ["P1→P2 与 P2→目标的防火墙状态", "真实代理 CONNECT/SOCKS 协商"]
        }
      else
        {
          status: "verified_in_recording_double",
          judgment: "记录型替身中的连接、地址选择、命令/回复和数据套接字返回均一致；真实防火墙可达性仍需预发证据。",
          non_committable: ["真实防火墙可达性", "除非固定端口范围或 ALG，否则无法承诺生产主动端口"]
        }
      end
    end

    def build_config_comparison
      before = @config["before"]
      after = @config["after"]
      identity_same = @config["same_client_must_not_change"].to_h do |key|
        [key, @config[key]]
      end
      {
        same_client_identity: identity_same,
        offline: true,
        rows: [
          row("Net::FTP passive", before.dig("net_ftp_options", "passive"),
              after.dig("net_ftp_options", "passive"),
              "迁移后使用出站 PASV/EPSV，避免在客户端开放主动回连监听。"),
          row("use_pasv_ip", before.dig("net_ftp_options", "use_pasv_ip"),
              after.dig("net_ftp_options", "use_pasv_ip"),
              "true 时采用 227 明示主机；false 时用 @bare_sock.remote_address 推导。"),
          row("SOCKS_SERVER", before.dig("env", "SOCKS_SERVER"),
              after.dig("env", "SOCKS_SERVER"),
              "这是本版 Net::FTP 唯一识别的代理钩子；两级链本身在代码之外。"),
          row("proxy_chain_length", before["proxy_chain"].length, after["proxy_chain"].length,
              "Net::FTP 没有两级代理客户端配置项。"),
          row("client_ingress_rules", before["client_ingress"].length, after["client_ingress"].length,
              "改为被动后，客户端侧 FTP 回连入站规则降为 0。"),
          row("client_egress_rules", before["client_egress"], after["client_egress"],
              "分段后，客户端主机只需放行到第一级代理的出站。")
        ]
      }
    end

    def row(key, before, after, impact)
      { key: key, before: before, after: after, impact: impact, changed: before != after }
    end

    def add_check(checks, name, ok, evidence, expected: false)
      checks << { name: name, ok: !!ok, expected_non_committable: expected, evidence: evidence }
    end

    def address_hash(address)
      case address
      when AddressDouble then address.to_h
      when nil then nil
      else
        { "ip_address" => address.ip_address, "ip_port" => safe_port(address),
          "note" => address.class.name }
      end
    rescue StandardError
      { "class" => address.class.name }
    end

    def safe_port(address)
      address.ip_port
    rescue StandardError
      nil
    end

    def decode_active_command(line)
      return nil unless line

      if (match = line.match(/\APORT ((?:\d+,){5}\d+)\z/))
        numbers = match[1].split(",").map(&:to_i)
        ip = numbers.first(4).join(".")
        port = numbers[4] * 256 + numbers[5]
        { protocol: "PORT", eprt_family: nil, ip_address: ip, port: port }
      elsif (match = line.match(/\AEPRT \|(\d+)\|([^|]+)\|(\d+)\|\z/))
        { protocol: "EPRT", eprt_family: match[1].to_i, ip_address: match[2], port: match[3].to_i }
      end
    end

    def extract_server_declared(reply_events, scenario)
      raw = reply_events.map { |event| event[:line] }.find { |line| line.start_with?("227 ", "229 ") }
      return nil unless raw

      if raw.start_with?("227")
        match = raw.match(/(?<host>\d+(?:,\d+){3}),(?<port>\d+,\d+)/)
        return nil unless match

        numbers = match["host"].split(",").map(&:to_i)
        port_numbers = match["port"].split(",").map(&:to_i)
        {
          protocol: "PASV/227",
          host: numbers.join("."),
          port: port_numbers[0] * 256 + port_numbers[1],
          raw: raw
        }
      else
        match = raw.match(/\((?<d>[!-~])\k<d>\k<d>(?<port>\d+)\k<d>\)/)
        { protocol: "EPSV/229", host: nil, port: match && match["port"].to_i, raw: raw }
      end
    end

    def call_role
      labels = caller_locations(3, 30).map(&:label).join(" ")
      if labels.include?("transfercmd")
        "passive_data"
      elsif labels.include?("connect")
        "control"
      else
        "unknown"
      end
    end

    def local_address_for(role, host)
      ip = current_scenario[:client_ip]
      port = role == "control" ? 51_000 : 52_000 + @results.length
      AddressDouble.new(ip, port, "recording local address toward #{host}")
    end

    def proxy_address(proxy, family)
      key = family == "ipv6" ? "ipv6" : "ipv4"
      AddressDouble.new(proxy[key], proxy["port"], proxy["name"])
    end

    def quads(ipv4)
      ipv4.split(".").join(",")
    end

    def port_bytes(port)
      [port.divmod(256)].flatten.join(",")
    end
  end

  class MarkdownReport
    def initialize(config, plan)
      @config = config
      @plan = plan
    end

    def render
      <<~MD
        # Net::FTP 迁移连接计划（全记录型替身）

        复跑命令：

        ```sh
        ruby audit/run.rb
        ```

        本命令离线运行，不做 DNS、不发起真实连接、不绑定真实端口；`Socket.tcp`、`Addrinfo.tcp` 和 `SOCKSSocket.open` 均由记录型替身接管。原始事件见 `audit/out/records.json` 与 `audit/out/{connect,listen,accept,control_reply}.jsonl`。

        ## 代码调用依据

        - 控制连接：`lib/net/ftp.rb:406` 调 `open_socket(host, port)`；分支在 `lib/net/ftp.rb:367`：有 `SOCKSSocket` 且 `SOCKS_SERVER` 非空时走 SOCKS，否则 `Socket.tcp`。
        - 地址族和 PASV/EPSV 选择：`lib/net/ftp.rb:542` 与 `lib/net/ftp.rb:562` 都读取 `@bare_sock.remote_address`。
        - 主动模式：`lib/net/ftp.rb:556` 用 `@bare_sock.local_address.ip_address` 和端口 `0` 监听；`lib/net/ftp.rb:598` 把该监听地址/端口写入 `PORT` 或 `EPRT`。
        - 主动模式顺序：`lib/net/ftp.rb:595` 监听，`lib/net/ftp.rb:598` 发 PORT/EPRT，`lib/net/ftp.rb:605` 起等待 `1XX`，之后才在 `lib/net/ftp.rb:611` 调 `accept`。因此只有 `150/125` 不能证明数据连接建成。
        - 被动模式：IPv4 控制对端发 `PASV` 并解析 227；IPv6 控制对端发 `EPSV` 并解析 229。默认 `use_pasv_ip: false` 时，227 里的主机地址被忽略，改用控制套接字的 `remote_address.ip_address`；229 本来只有端口，主机也永远取控制对端。
        - 两级代理不是本版本 `Net::FTP` 的内建配置；它只识别一个旧式 `SOCKS_SERVER/SOCKSSocket` 钩子。两级链路必须由外部 SOCKS/CONNECT 链式服务、透明代理或定制套接字提供。

        ## 迁移前后离线对照

        | 项目 | 迁移前 | 迁移后 | 影响 |
        |---|---:|---:|---|
        #{config_rows}

        同一客户端身份保持不变：#{@plan[:config_comparison][:same_client_identity].map { |key, value| "`#{key}=#{value}`" }.join("，")}。

        ## 场景核对

        | 场景 | 模式/族 | 结论 | 必须开放的通路（记录中的具体元组） |
        |---|---|---|---|
        #{scenario_rows}

        ## 地址逐项对账

        | 场景 | 服务器明示 | 控制连接推导 | 主动通告 | 实际数据目标 | 对账 |
        |---|---|---|---|---|---|
        #{address_summary_rows}

        #{address_details}

        ## 预备回复后停止的主动模式

        `active_ipv4_preliminary_only` 场景真实调用了 `makeport`、`sendport` 和发送 `RETR` 的 `sendcmd`，在收到 `150` 后、调用 `listener.accept` 前停止。

        - 有 `connect`、`listen`、PORT 命令、200 和 150 回复记录。
        - `audit/out/accept.jsonl` 中没有该场景的 `accept` 记录。
        - 判定只能是“预备回复已收到，数据连接未证明建成”；不能把 150 当作防火墙回连已通的证据。
        - 完整主动场景必须额外出现 `accept` 返回和对端地址；被动场景必须额外出现数据 `connect` 成功返回，随后最好有一次 EOF/字节传输证据。
        - 记录中的服务端源端口 `#{@config['reference_endpoints']['ftp_data_source_port_reference']}` 只是传统 FTP-DATA 参考值；`Net::FTP` 不绑定或校验服务端源端口，真实规则应以 `accept` 对端记录和服务端部署为准。

        ## 仍不能承诺的通路

        - 替身只证明 `Net::FTP` 的调用顺序和地址选择自洽，不证明真实防火墙、代理协商或路由可达。
        - 主动模式真实代码绑定端口 `0`，生产端口是临时端口；报告中的 `#{@config['reference_endpoints']['active_double_port']}` 只是确定性替身端口。没有固定端口范围、FTP ALG 或端口映射时，无法提前承诺单条入站规则。
        - `Net::FTP` 总是把 `@bare_sock.local_address.ip_address` 写进 PORT/EPRT，没有“对外通告地址”选项。NAT/代理后的私网地址或代理内网地址不能靠客户端配置自动改成外部回连地址。
        - 两级代理的 P1→P2、P2→FTP/数据端口两段不在 `Net::FTP` 记录内，必须由代理配置和代理侧防火墙负责。
        - 普通正向 SOCKS/HTTP CONNECT 链不提供主动模式所需的反向 BIND/回连；`proxy2_active_not_committable` 中即使替身 `accept` 能返回，也不代表真实代理会把 FTP 服务端回连送达客户端监听器。
        - 代理套接字的 `remote_address` 语义必须在预发用真实运行时核对：是第一级代理地址（TCPSocket 式实际对端），还是保留/转换后的 FTP 目标地址。两种替身分别给出了 `proxy2_v4_passive_declared_chain`、`proxy2_v6_passive_preserved_peer_chain` 与 `proxy2_v6_passive_actual_peer_mismatch` 的差异。
        - FTPS 会保留同样的 TCP 源/目的端口需求，但加密控制连接使传统 FTP ALG 无法读取或改写 PASV/PORT；TLS 证书、主机名校验和 `PROT P` 需另行验证。
      MD
    end

    private

    def config_rows
      @plan[:config_comparison][:rows].map do |row|
        "| `#{row[:key]}` | `#{format_value(row[:before])}` | `#{format_value(row[:after])}` | #{row[:impact]} |"
      end.join("\n")
    end

    def scenario_rows
      @plan[:scenarios].map do |scenario|
        paths = scenario[:required_paths].map { |path| "`#{path[:tuple]}`（#{path[:owner]}）" }.join("<br>")
        "| `#{scenario[:id]}` | #{scenario[:mode]}/#{scenario[:family]} | **#{verdict_label(scenario[:verdict])}** (`#{scenario[:verdict]}`) — #{scenario[:judgment]} | #{paths} |"
      end.join("\n")
    end

    def address_summary_rows
      @plan[:scenarios].map do |scenario|
        unexpected = scenario[:checks].reject { |check| check[:ok] || check[:expected_non_committable] }.length
        expected_gaps = scenario[:checks].count { |check| !check[:ok] && check[:expected_non_committable] }
        reconciliation =
          if unexpected.positive?
            "#{unexpected} 项不一致"
          elsif expected_gaps.positive?
            "调用自洽；#{expected_gaps} 项通路不能承诺"
          else
            "全部对得上"
          end
        [
          "| `#{scenario[:id]}`",
          format_endpoint(scenario[:server_declared_address], declared: true),
          format_endpoint(scenario[:control_peer_address]),
          format_endpoint(scenario[:active_advertised_address], advertised: true),
          format_endpoint(scenario[:data_connection_target], target: true),
          "#{reconciliation} |"
        ].join(" | ")
      end.join("\n")
    end

    def verdict_label(status)
      {
        "verified_in_recording_double" => "替身验证通过",
        "inconclusive" => "证据不足",
        "conditional" => "有条件可承诺",
        "not_committable" => "不能承诺",
        "check_failed" => "对账失败",
        "error" => "执行错误"
      }.fetch(status, status)
    end

    def address_details
      @plan[:scenarios].map do |scenario|
        [
          "### `#{scenario[:id]}`",
          "",
          "- 控制连接本地地址：`#{scenario[:control_local_address]&.dig('ip_address')}:#{scenario[:control_local_address]&.dig('ip_port')}`",
          "- 实际控制对端/控制推导地址：`#{scenario[:control_peer_address]&.dig('ip_address')}:#{scenario[:control_peer_address]&.dig('ip_port')}`",
          "- 服务器明示地址：`#{format_hash(scenario[:server_declared_address])}`",
          "- 主动通告地址：`#{format_hash(scenario[:active_advertised_address])}`",
          "- 检查项：",
          scenario[:checks].map do |check|
            marker = check[:ok] ? "x" : (check[:expected_non_committable] ? "!" : " ")
            "  - [#{marker}] `#{check[:name]}` — #{check[:evidence]}"
          end.join("\n"),
          ""
        ].join("\n")
      end.join("\n")
    end

    def format_value(value)
      case value
      when Array
        value.empty? ? "（空）" : value.map { |item| item.is_a?(Hash) ? item["name"] : item }.join(", ")
      when nil
        "（未设置）"
      when true
        "true"
      when false
        "false"
      else
        value.to_s
      end
    end

    def format_endpoint(hash, declared: false, advertised: false, target: false)
      return "—" if hash.nil? || hash.empty?

      host = hash[:ip_address] || hash["ip_address"] ||
             hash[:host] || hash["host"]
      port = hash[:ip_port] || hash["ip_port"] ||
             hash[:port] || hash["port"]
      if declared && host.nil?
        return port ? "仅端口 `#{port}`（EPSV）" : "—"
      end
      return "—" if host.nil?

      if advertised || target || port
        "`#{host}:#{port}`"
      else
        "`#{host}`"
      end
    end

    def format_hash(hash)
      return "（无）" unless hash

      host = hash[:ip_address] || hash["ip_address"] || hash[:host] || hash["host"]
      port = hash[:ip_port] || hash["ip_port"] || hash[:port] || hash["port"]
      if host && port
        "#{host}:#{port}"
      elsif host
        host
      else
        hash.inspect
      end
    end
  end
end

if __FILE__ == $PROGRAM_NAME
  runner = ConnectionAudit::AuditRunner.new.run_all
  failed = runner.results.flat_map { |result| result[:checks] }
                 .reject { |check| check[:ok] || check[:expected_non_committable] }
  if failed.any?
    warn "Address reconciliation failed:"
    failed.each { |check| warn "- #{check[:name]}: #{check[:evidence]}" }
    exit 1
  end
  puts "Wrote #{ConnectionAudit::OUTPUT_DIR}/connection-plan.md"
  puts "Wrote #{ConnectionAudit::OUTPUT_DIR}/records.json"
end
