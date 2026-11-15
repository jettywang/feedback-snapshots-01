require 'net/sftp/errors'

module Net; module SFTP; module Protocol

  # Several SFTP structures are a 32-bit item count followed by that many
  # items. Net::SSH::Buffer returns nil instead of raising when a read runs
  # past the end of the data, so a loop over an unchecked count from the
  # server keeps allocating long after the packet is exhausted.
  #
  # A structure may also be length-delimited by an enclosing field, such as the
  # string that carries an ACL. In that case the count must be checked against
  # that structure's own bytes, not against everything left in the packet, or
  # the items can silently borrow bytes from whatever follows the structure
  # (for instance the next directory entry in a FXP_NAME response).
  module BoundedRead
    # The number of bytes each fixed-width field occupies on the wire.
    FIELD_WIDTHS = { :byte => 1, :long => 4, :int64 => 8 }.freeze

    # Reads an item count from +buffer+ and raises Net::SFTP::Exception if it
    # is missing, or larger than the remaining bytes could hold given that
    # each item takes at least +min_item_size+ bytes.
    def read_bounded_count!(buffer, min_item_size, what)
      read_bounded_count_within!(buffer, min_item_size, buffer.length, what)
    end

    # Same as #read_bounded_count!, but the count is checked against the bytes
    # between the current position and +limit+, rather than the whole buffer.
    # This is how a count nested in a length-delimited structure is kept from
    # reaching into data that belongs to whatever follows it.
    def read_bounded_count_within!(buffer, min_item_size, limit, what)
      count = read_within!(buffer, :long, limit, "#{what} count")
      remaining = limit - buffer.position
      remaining = 0 if remaining < 0

      if count > remaining / min_item_size
        raise TruncatedPacketError, "server sent #{count} #{what} entries in only #{remaining} bytes"
      end

      count
    end

    # Reads a field of the given +type+ that must end at or before +limit+,
    # raising TruncatedPacketError rather than returning nil. A nil would
    # otherwise be indistinguishable from an attribute the server did not
    # intend to send.
    def read_within!(buffer, type, limit, what)
      return read_string_within!(buffer, limit, what) if type == :string

      width = FIELD_WIDTHS.fetch(type)
      remaining = limit - buffer.position
      if remaining < width
        raise TruncatedPacketError, "truncated packet: #{what} needs #{width} bytes but only #{[remaining, 0].max} remain"
      end

      value = buffer.send("read_#{type}")
      raise TruncatedPacketError, "truncated packet: missing #{what}" if value.nil?
      value
    end

    # Reads an SSH string that must end at or before +limit+. Net::SSH::Buffer
    # silently clamps an over-long string to the bytes it has, so the declared
    # length is checked before reading.
    def read_string_within!(buffer, limit, what)
      length = read_within!(buffer, :long, limit, "#{what} length")
      remaining = limit - buffer.position
      if length > remaining
        raise TruncatedPacketError, "truncated packet: #{what} claims #{length} bytes but only #{remaining} remain"
      end

      value = buffer.read(length)
      if value.nil? || value.bytesize != length
        raise TruncatedPacketError, "truncated packet: missing #{what}"
      end
      value
    end

    # Returns the last byte offset a repeated entry may read, reserving
    # +min_item_size+ bytes for every entry after it. Used by FXP_NAME parsing
    # so one entry's attributes cannot consume the bytes that introduce the
    # next entry.
    def entry_limit(buffer, index, count, min_item_size)
      buffer.position + buffer.available - (count - index - 1) * min_item_size
    end

    # Raises MalformedPacketError if exactly the expected number of bytes was
    # not consumed between +start+ and +limit+.
    def assert_consumed!(buffer, start, limit, what)
      consumed = buffer.position - start
      expected = limit - start
      unless consumed == expected
        raise MalformedPacketError, "#{what} consumed #{consumed} of #{expected} bytes"
      end
    end
  end

end; end; end
