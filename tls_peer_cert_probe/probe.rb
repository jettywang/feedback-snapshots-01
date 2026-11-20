# frozen_string_literal: true

# TLS peer_cert 证据探针
#
# 用本机自签 CA + 服务器证书，通过 UNIXSocket.pair 的 IO 替身替代 TCPSocket，
# 在不绑定任何端口的情况下驱动本仓库的 Net::HTTP 走完真实 TLS 握手，
# 并记录:
#   * 什么时候发生了证书验证 (verify_callback)
#   * 看到的对端标识 (peer_cert subject / SAN / SHA256 指纹)
#   * 是否尝试 / 成功恢复了 TLS 会话 (session_reused?)
#
# 运行: ruby -Ilib tls_peer_cert_probe/probe.rb

require "openssl"
require "socket"
require "json"
require "delegate"
require "net/http"

LOG_PATH = File.expand_path("evidence.log", __dir__)
File.truncate(LOG_PATH, 0)

module ProbeLog
  def self.log(event, **data)
    line = { t: Time.now.strftime("%H:%M:%S.%L"), event: event }.merge(data)
    File.open(LOG_PATH, "a") { |f| f.puts(JSON.generate(line)) }
    puts JSON.generate(line)
  end
end

# ---------------------------------------------------------------- 证书材料

def make_key = OpenSSL::PKey::RSA.new(2048)

def make_ca(cn, serial)
  key = make_key
  cert = OpenSSL::X509::Certificate.new
  cert.version = 2
  cert.serial = serial
  cert.subject = OpenSSL::X509::Name.parse("/CN=#{cn}")
  cert.issuer = cert.subject
  cert.public_key = key.public_key
  cert.not_before = Time.now - 3600
  cert.not_after = Time.now + 86_400
  ef = OpenSSL::X509::ExtensionFactory.new
  ef.subject_certificate = cert
  ef.issuer_certificate = cert
  cert.add_extension ef.create_extension("basicConstraints", "CA:TRUE", true)
  cert.add_extension ef.create_extension("keyUsage", "keyCertSign,cRLSign", true)
  cert.add_extension ef.create_extension("subjectKeyIdentifier", "hash")
  cert.sign(key, OpenSSL::Digest::SHA256.new)
  [cert, key]
end

def make_server_cert(ca_cert, ca_key, cn, san, serial)
  key = make_key
  cert = OpenSSL::X509::Certificate.new
  cert.version = 2
  cert.serial = serial
  cert.subject = OpenSSL::X509::Name.parse("/CN=#{cn}")
  cert.issuer = ca_cert.subject
  cert.public_key = key.public_key
  cert.not_before = Time.now - 3600
  cert.not_after = Time.now + 86_400
  ef = OpenSSL::X509::ExtensionFactory.new
  ef.subject_certificate = cert
  ef.issuer_certificate = ca_cert
  cert.add_extension ef.create_extension("basicConstraints", "CA:FALSE", true)
  cert.add_extension ef.create_extension("keyUsage", "digitalSignature,keyEncipherment", true)
  cert.add_extension ef.create_extension("extendedKeyUsage", "serverAuth", true)
  cert.add_extension ef.create_extension("subjectAltName", "DNS:#{san}", false)
  cert.sign(ca_key, OpenSSL::Digest::SHA256.new)
  [cert, key]
end

def fp(cert) = cert && OpenSSL::Digest::SHA256.hexdigest(cert.to_der)[0, 16]

CA1_CERT, CA1_KEY = make_ca("Probe-CA-1", 1001)
CA2_CERT, = make_ca("Probe-CA-2", 1002) # 不信任服务器的那家 CA
SRV_CERT, SRV_KEY = make_server_cert(CA1_CERT, CA1_KEY, "peer.test", "peer.test", 2001)

STORE1 = OpenSSL::X509::Store.new.tap { |s| s.add_cert(CA1_CERT) }
STORE2 = OpenSSL::X509::Store.new.tap { |s| s.add_cert(CA2_CERT) }

# ---------------------------------------------------------------- 服务器(IO 替身的对端)

class PairServer
  Conn = Struct.new(:id, :ssl_version, :session_reused, :peer_cert_seen)

  attr_reader :conns

  def initialize(ctx)
    @ctx = ctx
    @queue = Queue.new
    @conns = []
    @mutex = Mutex.new
    @next_id = 0
    @thread = Thread.new { serve }
  end

  def enqueue(io) = @queue << io

  def shutdown
    @queue << :stop
    @thread.join(2)
  end

  private

  def serve
    loop do
      raw = @queue.pop
      break if raw == :stop

      Thread.new(raw) { |io| handle(io) }
    end
  end

  def handle(raw)
    id = nil
    ssl = OpenSSL::SSL::SSLSocket.new(raw, @ctx)
    ssl.sync_close = true
    ssl.accept
    id = @mutex.synchronize { @next_id += 1 }
    @mutex.synchronize do
      @conns << Conn.new(id, ssl.ssl_version, ssl.session_reused?, !ssl.peer_cert.nil?)
    end
    ProbeLog.log("server_accept", conn: id, ssl_version: ssl.ssl_version, session_reused: ssl.session_reused?)
    # 最小 HTTP/1.1 keep-alive 服务
    loop do
      buf = +""
      buf << ssl.readpartial(1024) until buf.include?("\r\n\r\n")
      ssl.write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
    end
  rescue OpenSSL::SSL::SSLError => e
    ProbeLog.log("server_ssl_error", conn: id, error: e.message)
  rescue EOFError, IOError, SystemCallError
    # 客户端 finish 关闭连接
  ensure
    ssl&.close rescue nil
  end
end

def make_server_ctx(max_version: nil)
  OpenSSL::SSL::SSLContext.new.tap do |ctx|
    ctx.add_certificate(SRV_CERT, SRV_KEY, [CA1_CERT])
    ctx.session_id_context = "tls-peer-cert-probe"
    ctx.max_version = max_version if max_version
  end
end

# ---------------------------------------------------------------- 客户端 IO 替身

# Net::HTTP#connect 会对 connect 返回的 IO 调用 setsockopt(TCP_NODELAY),
# UNIXSocket 不支持; SSLSocket 又要求真正的 IO 对象, 因此在 socketpair 的
# 客户端端点上定义单例方法拦截该调用并记录, 其余行为与真实 TCPSocket 一致.
def make_io_standin(client_io)
  client_io.define_singleton_method(:setsockopt) do |level, optname, value|
    if level == Socket::IPPROTO_TCP && optname == Socket::TCP_NODELAY
      ProbeLog.log("io_standin_setsockopt", level: level, optname: optname, value: value, action: "no-op")
      0
    else
      super(level, optname, value)
    end
  end
  client_io
end

class ProbeHTTP < Net::HTTP
  attr_reader :connect_count
  attr_accessor :pair_server

  def initialize(*args)
    @connect_count = 0
    super
  end

  private

  def timeouted_connect(_addr, _port)
    @connect_count += 1
    server_io, client_io = UNIXSocket.pair
    @pair_server.enqueue(server_io)
    make_io_standin(client_io)
  end
end

# ---------------------------------------------------------------- 场景记录辅助

def make_verify_callback(label)
  lambda do |ok, store_ctx|
    cert = store_ctx.current_cert
    ProbeLog.log("verify_callback", phase: label, preverify_ok: ok, depth: store_ctx.error_depth,
        error: store_ctx.error_string, subject: cert&.subject&.to_s,
        issuer: cert&.issuer&.to_s, serial: cert&.serial&.to_s, cert_fp: fp(cert))
    ok
  end
end

def snapshot(http, label)
  sock = http.instance_variable_get(:@socket)&.io
  sess = http.instance_variable_get(:@ssl_session)
  ProbeLog.log("snapshot", phase: label,
      connect_count: http.connect_count,
      ssl_version: sock&.ssl_version,
      cipher: sock&.cipher&.[](0),
      session_reused: sock&.session_reused?,
      verify_result: sock&.verify_result,
      peer_cert_subject: http.peer_cert&.subject&.to_s,
      peer_cert_fp: fp(http.peer_cert),
      cached_session: !sess.nil?,
      cached_session_timeout: sess&.timeout)
end

# ---------------------------------------------------------------- 场景

server13 = PairServer.new(make_server_ctx)
server12 = PairServer.new(make_server_ctx(max_version: :TLS1_2))

ProbeLog.log("probe_start", ruby: RUBY_VERSION, openssl: OpenSSL::OPENSSL_VERSION,
    server_cert_subject: SRV_CERT.subject.to_s, server_cert_fp: fp(SRV_CERT),
    ca1: CA1_CERT.subject.to_s, ca2: CA2_CERT.subject.to_s)

# --- A: 首次握手 (TLS1.3, 全握手) ------------------------------------
http = ProbeHTTP.new("peer.test", 443, nil).tap { |h| h.pair_server = server13 }
http.use_ssl = true
http.verify_mode = OpenSSL::SSL::VERIFY_PEER
http.cert_store = STORE1
http.verify_callback = make_verify_callback("A-first-handshake")
http.start
snapshot(http, "A-after-start")
2.times { |i| ProbeLog.log("http_get", phase: "A", seq: i, body: http.get("/").body) }
snapshot(http, "A-after-keepalive-gets")
http.finish

# --- B: 同一实例重连 -> 尝试会话恢复 (TLS1.3 PSK) ---------------------
http.verify_callback = make_verify_callback("B-resumed")
http.start
snapshot(http, "B-after-reconnect")
ProbeLog.log("http_get", phase: "B", body: http.get("/").body)
http.finish

# --- C: 重新指定验证配置 (换成不信任服务器证书的 STORE2) 后再重连 ------
http.verify_callback = make_verify_callback("C-new-store")
http.cert_store = STORE2
begin
  http.start
  snapshot(http, "C-after-reconnect-with-new-store")
  ProbeLog.log("http_get", phase: "C", body: http.get("/").body,
      note: "新信任库本不应通过, 但恢复会话绕过了验证")
  http.finish
rescue OpenSSL::SSL::SSLError => e
  ProbeLog.log("handshake_failed", phase: "C", error: e.message)
end

# --- D: 强制完整握手 (清掉缓存会话) -> 新验证配置真正生效 --------------
http.instance_variable_set(:@ssl_session, nil)
http.verify_callback = make_verify_callback("D-forced-full-handshake")
begin
  http.start
  snapshot(http, "D-unexpected-success")
  http.finish
rescue OpenSSL::SSL::SSLError => e
  ProbeLog.log("handshake_failed", phase: "D", error: e.message,
      note: "全握手下 STORE2 正确拒绝服务器证书, 证明 C 的成功来自会话恢复绕过")
end

# --- E: TLS1.2 对照组 -------------------------------------------------
http12 = ProbeHTTP.new("peer.test", 443, nil).tap { |h| h.pair_server = server12 }
http12.use_ssl = true
http12.verify_mode = OpenSSL::SSL::VERIFY_PEER
http12.cert_store = STORE1
http12.min_version = :TLS1_2
http12.max_version = :TLS1_2
http12.verify_callback = make_verify_callback("E1-tls12-first")
http12.start
snapshot(http12, "E1-tls12-after-start")
ProbeLog.log("http_get", phase: "E1", body: http12.get("/").body)
http12.finish

http12.verify_callback = make_verify_callback("E2-tls12-resumed")
http12.start
snapshot(http12, "E2-tls12-after-reconnect")
ProbeLog.log("http_get", phase: "E2", body: http12.get("/").body)
http12.finish

ProbeLog.log("probe_done", server13_conns: server13.conns.map(&:to_h), server12_conns: server12.conns.map(&:to_h))
server13.shutdown
server12.shutdown
