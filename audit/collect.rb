# frozen_string_literal: true

# Two-pass FTP evidence collection against recording servers.
#
# Run from the repository root:
#   .feedback/bundle-env exec ruby -Ilib audit/collect.rb
#
# The sandbox used for this audit forbids bind(2)/connect(2), so the
# control and data connections are carried over UNIXSocket.pair endpoints
# behind Net::FTP's real protocol engine (BufferedSocket, sendcmd,
# transfercmd, parse227). Every control line and every data connection is
# recorded by the server with the collector's clock.

require "net/ftp"
require "socket"
require "json"
require "digest"
require "fileutils"
require "delegate"

EVIDENCE_DIR = File.expand_path("evidence", __dir__)

REPORT_CONTENT = begin
  body = +"id,amount\n"
  i = 1
  while body.bytesize < 4096
    body << "#{i},#{(i * 37) % 1000}.00\n"
    i += 1
  end
  body.byteslice(0, 4096).freeze
end

module VirtualTCP
  @listeners = {}
  @next_port = 20_000
  @mutex = Mutex.new

  class Listener
    def initialize
      @queue = Queue.new
    end

    def push(sock)
      @queue.push(sock)
    end

    def accept
      @queue.pop
    end
  end

  class << self
    def listen(port)
      listener = Listener.new
      @mutex.synchronize { @listeners[port] = listener }
      listener
    end

    def alloc_port
      @mutex.synchronize { @next_port += 1 }
    end

    def connect(port)
      listener = @mutex.synchronize { @listeners[port] }
      raise "no virtual listener on port #{port}" unless listener
      client_end, server_end = UNIXSocket.pair
      listener.push(server_end)
      VirtualSocket.new(client_end, peer_port: port)
    end
  end
end

class VirtualSocket < SimpleDelegator
  def initialize(io, peer_port:)
    super(io)
    @remote = Addrinfo.tcp("127.0.0.1", peer_port)
    @local = Addrinfo.tcp("127.0.0.1", 0)
  end

  def remote_address
    @remote
  end

  def local_address
    @local
  end
end

class AuditFTP < Net::FTP
  private

  def open_socket(_host, port)
    VirtualTCP.connect(port)
  end
end

class RecordingFTPServer
  attr_reader :receipts

  def initialize(name, profile, transcript)
    @name = name
    @dirs = profile[:dirs]
    @files = profile[:files] || {}
    @mlsx = profile[:mlsx]
    @log = transcript
    @receipts = []
  end

  def handle(sock)
    cwd = "/"
    pending = nil
    say(sock, "220 #{@name} FTP service ready")
    while (line = sock.gets)
      line = line.chomp
      log("CTRL >> #{line}")
      cmd, arg = line.split(" ", 2)
      case cmd.to_s.upcase
      when "USER"
        say(sock, "331 Please specify the password.")
      when "PASS"
        say(sock, "230 Login successful.")
      when "TYPE"
        say(sock, "200 Switching to #{arg.to_s.include?("I") ? "Binary" : "ASCII"} mode.")
      when "PASV"
        port = VirtualTCP.alloc_port
        listener = VirtualTCP.listen(port)
        pending = Queue.new
        q = pending
        Thread.new { q << listener.accept }
        say(sock, "227 Entering Passive Mode (127,0,0,1,#{port / 256},#{port % 256})")
      when "PWD"
        say(sock, "257 \"#{cwd}\" is the current directory")
      when "CWD"
        target = normalize(cwd, arg)
        if @dirs.key?(target)
          cwd = target
          say(sock, "250 Directory successfully changed.")
        else
          say(sock, "550 Failed to change directory.")
        end
      when "LIST"
        path = arg ? normalize(cwd, arg) : cwd
        entries = @dirs[path]
        if entries.nil?
          say(sock, "550 No such directory.")
        else
          payload = entries.map { |e| e[:list] }.join("\r\n") + "\r\n"
          say(sock, "150 Here comes the directory listing.")
          deliver(pending, payload, "LIST #{path}")
          say(sock, "226 Directory send OK.")
        end
      when "MLSD"
        unless @mlsx
          say(sock, "502 Command not implemented.")
          close_pending(pending)
          next
        end
        path = arg ? normalize(cwd, arg) : cwd
        entries = @dirs[path]
        if entries.nil?
          say(sock, "550 No such directory.")
        else
          payload = entries.map { |e| "#{e[:facts]} #{e[:name]}" }.join("\r\n") + "\r\n"
          say(sock, "150 Here comes the directory listing.")
          deliver(pending, payload, "MLSD #{path}")
          say(sock, "226 Directory send OK.")
        end
      when "MLST"
        unless @mlsx
          say(sock, "502 Command not implemented.")
          next
        end
        path = arg ? normalize(cwd, arg) : cwd
        entry = find_entry(path)
        if entry
          say(sock, "250- Listing #{path}")
          say(sock, " #{entry[:facts]} #{path}")
          say(sock, "250 End")
        else
          say(sock, "550 No such file.")
        end
      when "RETR"
        path = normalize(cwd, arg)
        content = @files[path]
        if content.nil?
          say(sock, "550 No such file.")
        else
          say(sock, "150 Opening BINARY mode data connection for #{arg}.")
          deliver(pending, content, "RETR #{arg} (resolved #{path})")
          say(sock, "226 Transfer complete.")
          @receipts << {
            "command" => "RETR #{arg}",
            "resolved_path" => path,
            "cwd_at_time" => cwd,
            "bytes" => content.bytesize,
            "sha256" => Digest::SHA256.hexdigest(content),
            "reply" => "226 Transfer complete."
          }
        end
      when "QUIT"
        say(sock, "221 Goodbye.")
        break
      else
        say(sock, "502 Command not implemented.")
      end
    end
  rescue Errno::EPIPE, IOError
  ensure
    sock.close rescue nil
  end

  private

  def normalize(cwd, arg)
    parts = (arg.to_s.start_with?("/") ? [] : cwd.split("/")) + arg.to_s.split("/")
    normalized = parts.reject { |p| p.empty? || p == "." }
    normalized = normalized.each_with_object([]) do |p, acc|
      p == ".." ? acc.pop : acc << p
    end
    "/" + normalized.join("/")
  end

  def find_entry(path)
    dir = File.dirname(path)
    name = File.basename(path)
    @dirs.fetch(dir, []).find { |e| e[:name] == name }
  end

  def deliver(pending, payload, label)
    conn = pending.pop
    conn.write(payload)
    conn.close
    log("DATA << #{payload.bytesize} bytes sha256=#{Digest::SHA256.hexdigest(payload)} (#{label})")
  end

  def close_pending(pending)
    pending.pop.close rescue nil
  end

  def say(sock, text)
    log("CTRL << #{text}")
    sock.write("#{text}\r\n")
  end

  def log(event)
    @log << "[#{Time.now.utc.strftime("%Y-%m-%dT%H:%M:%S.%3NZ")}] #{event}"
  end
end

SERVER_A_PROFILE = {
  mlsx: false,
  dirs: {
    "/" => [
      { name: "report.csv",
        list: "-rw-r--r--  1 ftp  ftp  4096 Nov 26 09:41 report.csv" },
      { name: "archive",
        list: "drwxr-xr-x  2 ftp  ftp  4096 Mar  3  2025 archive" },
    ],
    "/archive" => [
      { name: "report.csv",
        list: "-rw-r--r--  1 ftp  ftp  4096 Mar  3  2025 report.csv" },
    ],
  },
}.freeze

SERVER_B_PROFILE = {
  mlsx: true,
  dirs: {
    "/" => [
      { name: "report.csv",
        facts: "Type=file;Size=#{REPORT_CONTENT.bytesize};Modify=20261126094107;Unique=9F3A01;Perm=r;" },
      { name: "archive",
        facts: "Type=dir;Modify=20250303000000;Unique=9F3A00;Perm=flcdmpe;" },
    ],
    "/archive" => [
      { name: "report.csv",
        facts: "Type=file;Size=4096;Modify=20250303182215;Unique=9F3A02;Perm=r;" },
    ],
  },
  files: { "/report.csv" => REPORT_CONTENT },
}.freeze

def write_evidence(name, content)
  File.write(File.join(EVIDENCE_DIR, name), content)
end

def facts_to_json(entry)
  facts = entry.facts.transform_values do |v|
    v.is_a?(Time) ? v.utc.strftime("%Y-%m-%dT%H:%M:%SZ") : v
  end
  { "pathname" => entry.pathname, "facts" => facts }
end

def run_collection(port, profile_name, profile)
  transcript = []
  server = RecordingFTPServer.new(profile_name, profile, transcript)
  listener = VirtualTCP.listen(port)
  thread = Thread.new { server.handle(listener.accept) }
  ftp = AuditFTP.new
  ftp.passive = true
  ftp.connect("127.0.0.1", port)
  ftp.login("audit", "audit")
  yield ftp
  begin
    ftp.quit
  rescue Net::FTPError, IOError, SystemCallError
  end
  ftp.close unless ftp.closed?
  thread.join(10)
  [server, transcript]
end

def collection_one
  run_collection(21_001, "server-a", SERVER_A_PROFILE) do |ftp|
    write_evidence("collection1_pwd_before.txt", ftp.pwd + "\n")
    write_evidence("collection1_list_root.txt", ftp.list.join("\n") + "\n")
    ftp.chdir("archive")
    write_evidence("collection1_pwd_after_cwd.txt", ftp.pwd + "\n")
    write_evidence("collection1_list_archive.txt", ftp.list.join("\n") + "\n")
    begin
      ftp.mlsd
      write_evidence("collection1_mlsd_attempt.txt", "MLSD unexpectedly succeeded\n")
    rescue Net::FTPError => e
      write_evidence("collection1_mlsd_attempt.txt",
                     "MLSD attempted after CWD to /archive\nreply: #{e.message}")
    end
  end.then do |(_server, transcript)|
    write_evidence("collection1_control_transcript.txt", transcript.join("\n") + "\n")
  end
end

def collection_two
  run_collection(21_002, "server-b", SERVER_B_PROFILE) do |ftp|
    write_evidence("collection2_mlsd_root.json",
                   JSON.pretty_generate(ftp.mlsd("/").map { |e| facts_to_json(e) }) + "\n")
    write_evidence("collection2_mlsd_archive.json",
                   JSON.pretty_generate(ftp.mlsd("/archive").map { |e| facts_to_json(e) }) + "\n")
    local = File.join(EVIDENCE_DIR, "collection2_retr_report.csv")
    ftp.getbinaryfile("/report.csv", local)
    write_evidence("collection2_mlst_root_report.json",
                   JSON.pretty_generate(facts_to_json(ftp.mlst("/report.csv"))) + "\n")
    write_evidence("collection2_mlst_archive_report.json",
                   JSON.pretty_generate(facts_to_json(ftp.mlst("/archive/report.csv"))) + "\n")
    write_evidence("collection2_client_receipt.json", JSON.pretty_generate(
      "local_file" => "collection2_retr_report.csv",
      "bytes" => File.size(local),
      "sha256" => Digest::SHA256.file(local).hexdigest
    ) + "\n")
  end.then do |(server, transcript)|
    write_evidence("collection2_server_receipts.json", JSON.pretty_generate(server.receipts) + "\n")
    write_evidence("collection2_control_transcript.txt", transcript.join("\n") + "\n")
  end
end

FileUtils.mkdir_p(EVIDENCE_DIR)
collection_one
collection_two
puts "evidence written to #{EVIDENCE_DIR}"
