# Optional development aid: re-derive every published vector with an
# implementation that shares no code with RubySMB. Not loaded by the specs.
#
#   ruby spec/tools/netlogon_vectors_check.rb
#
# The expected output is written in spec/support/netlogon_vectors.rb; this
# script only prints what OpenSSL computes for the same inputs.
require 'openssl'

SHARED_SECRET = ['0123456789abcdef0123456789abcdef'].pack('H*')

def derive(cc_hex, sc_hex)
  cc = [cc_hex].pack('H*')
  sc = [sc_hex].pack('H*')
  key = OpenSSL::HMAC.digest(OpenSSL::Digest.new('SHA256'), SHARED_SECRET, cc + sc)[0, 16]
  cipher = OpenSSL::Cipher.new('AES-128-CFB8').encrypt
  cipher.iv = "\x00" * 16
  cipher.key = key
  client = cipher.update(cc) + cipher.final
  cipher = OpenSSL::Cipher.new('AES-128-CFB8').encrypt
  cipher.iv = "\x00" * 16
  cipher.key = key
  server = cipher.update(sc) + cipher.final
  [key, client, server].map { |v| v.unpack1('H*') }
end

{
  'session A' => %w[0011223344556677 8899aabbccddeeff],
  'session B' => %w[1021324354657687 98a9bacbdcedfe0f],
  'swapped order' => %w[8899aabbccddeeff 0011223344556677],
  'reversed client' => %w[7766554433221100 8899aabbccddeeff]
}.each do |label, (cc, sc)|
  key, client, server = derive(cc, sc)
  puts format('%-16s key=%s client=%s server=%s', label, key, client, server)
end
