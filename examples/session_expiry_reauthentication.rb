# Frozen-string-literal: true

# Drives a RubySMB::Client through STATUS_NETWORK_SESSION_EXPIRED using an in-memory,
# scripted SMB3 server (no real socket). Two authentication generations use distinct
# NTLM challenge material, so the script can prove that:
#
#   * the expired session's derived keys, signing sequence and (for 3.1.1) preauth
#     integrity context cannot validate traffic of the new session;
#   * exactly one re-authentication and one replay happen, even when the server keeps
#     returning the expiry error;
#   * a non-idempotent request is never blindly re-sent and its result is reported as
#     unknown instead of a fabricated success.
#
# Run with:
#   ruby examples/session_expiry_reauthentication.rb
$LOAD_PATH.unshift File.expand_path('../lib', __dir__)
require 'ruby_smb'
require File.expand_path('../spec/support/scripted_smb2_server_dispatcher', __dir__)

def assert(condition, message)
  raise "assertion failed: #{message}" unless condition
  puts "  ok: #{message}"
end

def frames_for(dispatcher, command)
  dispatcher.wire.select { |frame| frame[:command] == command }
end

def signature_valid?(dispatcher, frame, generation)
  preauth_hash = dispatcher.preauth_hashes&.[](generation[:generation])
  dispatcher.valid_signature?(frame, generation, preauth_hash)
end

def run_scenario(dialect:, always_encrypt:)
  puts "\n=== SMB dialect 0x#{dialect.to_s(16).upcase} ==="
  dispatcher = ScriptedSmb2ServerDispatcher.new(
    password: 'generation-password',
    challenges: ["\x11" * 8, "\x22" * 8, "\x33" * 8, "\x44" * 8],
    dialect: dialect
  )
  client = RubySMB::Client.new(
    dispatcher,
    smb1: false,
    smb2: false,
    smb3: true,
    username: 'alice',
    password: 'generation-password',
    always_encrypt: always_encrypt
  )
  client.login
  assert(client.dialect == format('0x%04x', dialect), "negotiated expected dialect")
  assert(client.session_key == dispatcher.generations[0][:session_key], "generation 0 session key matches the server")

  # First expiry: an idempotent READ is replayed once after re-authentication.
  dispatcher.expire_next(RubySMB::SMB2::Commands::READ)
  response = client.send_recv(RubySMB::SMB2::Packet::ReadRequest.new)
  header = RubySMB::SMB2::SMB2Header.read(response)
  assert(header.nt_status == WindowsError::NTStatus::STATUS_SUCCESS, "retried READ reports real server success")
  assert(dispatcher.generations.size == 2, "exactly one re-authentication ran")
  assert(client.session_key == dispatcher.generations[1][:session_key], "generation 1 session key matches the server")
  assert(dispatcher.generations[0][:session_key] != dispatcher.generations[1][:session_key], "generation keys differ")

  read_frames = frames_for(dispatcher, RubySMB::SMB2::Commands::READ)
  assert(read_frames.size == 2, "two READ frames on the wire (one expired, one retried)")
  assert(read_frames.map { |frame| frame[:message_id] }.uniq.size == 2, "retry uses a fresh message id")
  read_frames.each do |frame|
    generation_index = dispatcher.generations.index { |generation| generation[:session_id] == frame[:session_id] }
    own_generation = dispatcher.generations[generation_index]
    other_generation = dispatcher.generations[generation_index.zero? ? 1 : 0]
    assert(signature_valid?(dispatcher, frame, own_generation), "READ verifies with its own generation key")
    assert(!signature_valid?(dispatcher, frame, other_generation), "READ cannot be verified with the other generation key")
  end

  if dialect == 0x0311
    assert(dispatcher.preauth_hashes[0] != dispatcher.preauth_hashes[1], "3.1.1 preauth hashes restart per generation")
    assert(client.preauth_integrity_hash_value == dispatcher.preauth_hashes[1], "client uses the new generation preauth hash")
  end

  # Non-idempotent WRITE: re-authenticate, but never replay the write.
  dispatcher.expire_next(RubySMB::SMB2::Commands::WRITE)
  begin
    client.send_recv(RubySMB::SMB2::Packet::WriteRequest.new)
    raise 'expected RequestOutcomeUnknown'
  rescue RubySMB::Error::RequestOutcomeUnknown => error
    assert(error.command == RubySMB::SMB2::Commands::WRITE, "unknown outcome carries the WRITE command")
    assert(error.status_code == WindowsError::NTStatus::STATUS_NETWORK_SESSION_EXPIRED, "unknown outcome carries the expiry status")
  end
  assert(frames_for(dispatcher, RubySMB::SMB2::Commands::WRITE).size == 1, "non-idempotent WRITE is sent exactly once")
  assert(dispatcher.generations.size == 3, "session was still rebuilt for the failed WRITE")

  # Persistent expiry: the chain must stop after the second expiry instead of looping.
  generations_before = dispatcher.generations.size
  reads_before = read_frames.size
  dispatcher.always_expire(RubySMB::SMB2::Commands::READ)
  begin
    client.send_recv(RubySMB::SMB2::Packet::ReadRequest.new)
    raise 'expected RequestOutcomeUnknown'
  rescue RubySMB::Error::RequestOutcomeUnknown
    assert(true, "persistent expiry raises instead of recursing")
  end
  assert(dispatcher.generations.size == generations_before + 1, "only one more re-authentication attempted")
  assert(frames_for(dispatcher, RubySMB::SMB2::Commands::READ).size == reads_before + 2, "bounded to one retried READ")
end

run_scenario(dialect: 0x0302, always_encrypt: true)
run_scenario(dialect: 0x0311, always_encrypt: false)

puts "\nAll session-expiry re-authentication checks passed."
