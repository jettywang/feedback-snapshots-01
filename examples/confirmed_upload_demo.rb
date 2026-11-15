#!/usr/bin/env ruby
# Demonstrates the confirmation contract without a network or SSH server.
#
#   ruby -Ilib examples/confirmed_upload_demo.rb
#
# The fake session below answers SFTP requests in memory. It is intentionally
# not a mock of Net::SFTP::Session's whole surface: it implements only the
# calls ConfirmedUpload makes, so the printed evidence is the evidence a real
# server would have to supply.

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "net/sftp/operations/confirmed_upload"
require "stringio"

# A tiny in-memory SFTP server. It keeps one file and answers the extension
# requests the confirmation flow uses.
class MemorySession
  attr_reader :extensions, :files, :calls

  def initialize(extensions: ["posix-rename@openssh.com", "fsync@openssh.com"],
                 fail_write_at: nil, fail_close: false, fail_fsync: false,
                 fail_rename: false, lose_rename_reply: false)
    @extensions = extensions.to_h { |name| [name, "1"] }
    @files = {}
    @calls = []
    @fail_write_at = fail_write_at
    @fail_close = fail_close
    @fail_fsync = fail_fsync
    @fail_rename = fail_rename
    @lose_rename_reply = lose_rename_reply
    @writes = 0
  end

  def extension?(name)
    @extensions.key?(name)
  end

  def open!(path, flags, attributes = {})
    @calls << [:open, path, flags]
    create = flags.is_a?(Integer) && (flags & IO::CREAT) != 0
    if create
      raise status(4, "Failure") if @files.key?(path)

      @files[path] = +""
    elsif !@files.key?(path)
      raise status(2, "No such file")
    end

    handle = Object.new
    handle.define_singleton_method(:path) { path }
    handle
  end

  def write!(handle, offset, data)
    @writes += 1
    @calls << [:write, offset, data.bytesize]
    raise status(4, "No space left on device") if @writes == @fail_write_at

    @files[handle.path] << data
    true
  end

  def fsync!(handle)
    @calls << [:fsync]
    raise status(4, "fsync failed") if @fail_fsync

    true
  end

  def stat!(path)
    @calls << [:stat, path]
    raise status(2, "No such file") unless @files.key?(path)

    Struct.new(:size).new(@files.fetch(path).bytesize)
  end

  def read!(handle, offset, length)
    @calls << [:read, offset]
    data = @files.fetch(handle.path)
    return nil if offset >= data.bytesize

    data.byteslice(offset, length)
  end

  def close!(handle)
    @calls << [:close, handle.path]
    raise status(4, "close failed") if @fail_close && handle.path == "/incoming/.report.csv.part"

    true
  end

  def posix_rename!(old_path, new_path)
    @calls << [:posix_rename, old_path, new_path]
    raise status(4, "rename failed") if @fail_rename

    # The rename takes effect, but the reply is lost with the channel. The
    # client cannot tell this apart from a rename that never happened.
    @files[new_path] = @files.delete(old_path)
    raise Net::SFTP::SessionClosedError if @lose_rename_reply

    true
  end

  def remove!(path)
    @calls << [:remove, path]
    @files.delete(path)
    true
  end

  private

  def status(code, message)
    Net::SFTP::StatusException.new(
      Net::SFTP::Response.new(nil, :code => code, :message => message),
      "server"
    )
  end
end

def run(title, session, data: "the full payload", **options)
  upload = Net::SFTP::Operations::ConfirmedUpload.new(
    session, StringIO.new(data), "/incoming/report.csv",
    { :staging_path => "/incoming/.report.csv.part", :read_size => 4,
      :verify => :readback }.merge(options)
  )
  result = upload.wait.result

  puts "== #{title}"
  # Business notification belongs here: after #wait, and only with the
  # facts in the result. Never from upload's :close or :finish events.
  puts "notification: #{result.notification}"
  puts "state=#{result.state} published=#{result.published?} " \
       "content_confirmed=#{result.content_confirmed?}"
  puts "bytes=#{result.bytes_confirmed}/#{result.bytes_from_source} " \
       "writes=#{result.writes_confirmed}/#{result.writes_sent} " \
       "close=#{result.close} fsync=#{result.fsync} " \
       "verify=#{result.verification} rename=#{result.rename}"
  puts "final_path=#{result.published? ? result.remote : '(unchanged)'} " \
       "staging=#{session.files.key?(result.staging_path) ? result.staging_path : '(gone)'}"
  puts
  result
end

puts "SSH authentication: this demo has no SSH transport, so the result " \
     "reports :not_observed. A real Net::SFTP session exposes the transport's " \
     ":authenticated hint, which is recorded as :confirmed."
puts

run("write fails", MemorySession.new(:fail_write_at => 2))
run("CLOSE fails", MemorySession.new(:fail_close => true))
run("fsync fails", MemorySession.new(:fail_fsync => true))
run("rename fails", MemorySession.new(:fail_rename => true))
run("rename reply lost", MemorySession.new(:lose_rename_reply => true))
run("all confirmations", MemorySession.new)
