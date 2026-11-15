require 'common'

class Protocol::LimitsTest < Net::SFTP::TestCase
  Limits = Net::SFTP::Protocol::Limits

  def test_defaults_mean_no_limit
    limits = Limits.new

    assert_equal 0, limits.max_packet_length
    assert_equal 0, limits.max_read_length
    assert_equal 0, limits.max_write_length
    assert_equal 0, limits.max_open_handles
    assert_nil limits.write_payload_limit
    assert_nil limits.read_payload_limit
  end

  def test_zero_and_missing_values_mean_no_limit_per_contract
    assert_equal Limits.new, Limits.new(0, 0, 0, 0)
    assert_nil Limits.new(0).write_payload_limit(8)
    assert_nil Limits.new(0, 0).read_payload_limit(8)
  end

  def test_non_numeric_negative_and_oversized_values_are_treated_as_absent
    limits = Limits.new("big", -5, Limits::MAX_VALUE + 1, 1.5)

    assert_equal 0, limits.max_packet_length
    assert_equal 0, limits.max_read_length
    assert_equal 0, limits.max_write_length
    assert_equal 0, limits.max_open_handles
  end

  def test_huge_advertised_value_cannot_exceed_uint32
    limits = Limits.new(1 << 40)

    assert_equal 0, limits.max_packet_length
    assert_nil limits.write_payload_limit
  end

  def test_write_payload_deducts_actual_packet_overhead
    limits = Limits.new(1000)

    # packet length includes framing, handle (4 length prefix + handle),
    # offset (8) and the data string length prefix (4).
    assert_equal 1000 - Limits::WRITE_OVERHEAD - 6, limits.write_payload_limit(6)
  end

  def test_read_payload_honors_request_and_reply_budgets
    tight_packet = Limits.new(500)

    # The FXP_DATA reply has less overhead than the request, so the request
    # budget is the binding one for a short handle.
    assert_equal 500 - Limits::READ_REQUEST_OVERHEAD - 2, tight_packet.read_payload_limit(2)

    # With a short handle the FXP_DATA reply (more total overhead) is the
    # binding constraint rather than the FXP_READ request.
    reply_bound = Limits.new(Limits::READ_RESPONSE_OVERHEAD + 100)
    assert_equal 88, reply_bound.read_payload_limit(0)
  end

  def test_read_and_write_length_fields_apply
    limits = Limits.new(0, 256, 128, 0)

    assert_equal 128, limits.write_payload_limit(4)
    assert_equal 256, limits.read_payload_limit(4)
  end

  def test_packet_budget_tightens_an_otherwise_generous_write_length
    limits = Limits.new(Limits::WRITE_OVERHEAD + 40, 0, 10_000, 0)

    assert_equal 40, limits.write_payload_limit(0)
  end

  def test_handle_bytes_are_part_of_the_deducted_overhead
    limits = Limits.new(Limits::WRITE_OVERHEAD + 10 + 5)

    assert_equal 10, limits.write_payload_limit(5)
  end

  def test_contradictory_tiny_packet_budget_floors_chunk_at_one_byte
    limits = Limits.new(Limits::WRITE_OVERHEAD - 5)

    assert_equal 1, limits.write_chunk_size(32_000)
    assert_equal 1, limits.read_chunk_size(32_000)
  end

  def test_chunk_size_never_exceeds_the_client_default
    generous = Limits.new(1 << 20, 1 << 20, 1 << 20, 1 << 20)

    assert_equal 32_000, generous.write_chunk_size(32_000)
    assert_equal 32_000, generous.read_chunk_size(32_000)
  end

  def test_chunk_size_uses_smaller_negotiated_value
    limits = Limits.new(Limits::READ_REQUEST_OVERHEAD + 1000)

    assert_equal 1000, limits.write_chunk_size(32_000)
    assert_equal 1000, limits.read_chunk_size(32_000)
  end

  def test_open_handle_limit_can_only_shrink_the_local_budget
    assert_equal 16, Limits.new(0, 0, 0, 64).open_handle_limit(16)
    assert_equal 8, Limits.new(0, 0, 0, 8).open_handle_limit(16)
    assert_equal 16, Limits.new(0, 0, 0, 0).open_handle_limit(16)
  end

  def test_from_extended_reply_reads_the_four_values
    packet = Net::SFTP::Packet.new(Net::SSH::Buffer.from(
      :byte, FXP_EXTENDED_REPLY,
      :long, 1000, :long, 500, :long, 250, :long, 8
    ).to_s)

    assert_equal Limits.new(1000, 500, 250, 8), Limits.from_extended_reply(packet)
  end

  def test_from_extended_reply_treats_truncated_fields_as_absent
    packet = Net::SFTP::Packet.new(Net::SSH::Buffer.from(
      :byte, FXP_EXTENDED_REPLY, :long, 1000
    ).to_s)

    assert_equal Limits.new(1000, 0, 0, 0), Limits.from_extended_reply(packet)
  end

  def test_equality_and_hash
    assert_equal Limits.new(1, 2, 3, 4), Limits.new(1, 2, 3, 4)
    refute_equal Limits.new(1, 2, 3, 4), Limits.new(1, 2, 3, 0)
    assert_equal Limits.new(1, 2, 3, 4).hash, Limits.new(1, 2, 3, 4).hash
  end
end
