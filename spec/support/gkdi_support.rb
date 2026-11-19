module GkdiSupport
  module_function

  # Encode a GUID string into its little-endian on-the-wire 16 bytes.
  def guid_bytes(hex)
    parts = hex.split('-')
    bytes =
      [parts[0]].pack('H8').bytes.reverse +
      [parts[1]].pack('H4').bytes.reverse +
      [parts[2]].pack('H4').bytes.reverse +
      parts[3].scan(/../).map { |x| x.hex } +
      parts[4].scan(/../).map { |x| x.hex }
    bytes.pack('C*')
  end

  def wide_stringz(str)
    str.encode('utf-16le').b + "\x00\x00".b
  end

  # Build a raw Group Key Envelope blob matching [MS-GKDI] 2.2.4 wire layout.
  # Key material bytes are fixed filler values so the fixture carries no real
  # secret and is safe to commit.
  def build_envelope(
    root_key_identifier:,
    l0_index: 100,
    l1_index: 101,
    l2_index: 102,
    dw_flags: 0,
    kdf_algorithm: 'SP800_108_CTR_HMAC',
    hash_algorithm: 'SHA256',
    secret_agreement_algorithm: 'DH',
    secret_agreement_parameters: [1, 2, 3, 4],
    private_key_length: 256,
    public_key_length: 256,
    l1_key: Array.new(64, 0xAA),
    l2_key: [],
    domain_name: 'corp.example.com',
    forest_name: 'example.com'
  )
    kdf_name = wide_stringz(kdf_algorithm)
    hash_name = wide_stringz(hash_algorithm)
    kdf_parameters =
      ([0, 0, 0, 0, 1, 0, 0, 0].pack('C*') +
       [hash_name.bytesize].pack('V') +
       [0, 0, 0, 0].pack('C*') +
       hash_name).b
    sa_name = wide_stringz(secret_agreement_algorithm)
    sa_parameters = secret_agreement_parameters.pack('C*')
    domain = wide_stringz(domain_name)
    forest = wide_stringz(forest_name)

    header =
      [1].pack('V') +
      [0x4b, 0x44, 0x53, 0x5b].pack('C*') +
      [dw_flags].pack('V') +
      [l0_index, l1_index, l2_index].pack('V3') +
      guid_bytes(root_key_identifier)

    counts = [
      kdf_name.bytesize,
      kdf_parameters.bytesize,
      sa_name.bytesize,
      sa_parameters.bytesize,
      private_key_length,
      public_key_length,
      l1_key.length,
      l2_key.length,
      domain.bytesize,
      forest.bytesize
    ]
    header += counts.pack('V10')

    body =
      kdf_name + kdf_parameters +
      sa_name + sa_parameters +
      l1_key.pack('C*') + l2_key.pack('C*') +
      domain + forest

    (header + body).b
  end

  # Wrap an envelope blob in a complete GkdiGetKeyResponse NDR message.
  def build_get_key_response(envelope_blob, error_status: 0)
    response = RubySMB::Dcerpc::Gkdi::GkdiGetKeyResponse.new
    response.pcb_out = envelope_blob.bytesize
    response.pbb_out = envelope_blob.bytes
    response.error_status = error_status
    response.to_binary_s
  end
end
