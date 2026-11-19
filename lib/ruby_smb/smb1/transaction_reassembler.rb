module RubySMB
  module SMB1
    # Reassembles fragmented SMB1 transaction responses (SMB_COM_TRANSACTION,
    # SMB_COM_TRANSACTION2 and SMB_COM_NT_TRANSACT) into a single parameter
    # buffer and a single data buffer.
    #
    # Every fragment is validated before it is merged so that bytes from the
    # parameter region, the data region or a different transaction can never be
    # spliced together:
    #
    # * The transaction identity (command, PID, TID, UID and MID) is locked by
    #   the first fragment and every subsequent fragment must match it.
    # * The declared total parameter/data counts must be identical in every
    #   fragment.
    # * The in-packet offset and count of each region must lie inside the
    #   received packet, and the displaced range must fit inside the declared
    #   total.
    # * Overlapping fragments are only accepted when the overlapping bytes are
    #   identical (consistent retransmission). Conflicting overlaps are
    #   rejected and never overwrite previously accepted bytes.
    #
    # Parameter and data coverage are tracked independently: a fragment that
    # completes one region says nothing about the other, and the transaction
    # is only complete when both regions are fully covered. Any validation
    # failure resets the reassembler so stale fragments can never leak into a
    # subsequent transaction.
    class TransactionReassembler
      # The reassembled parameter and data bytes of a complete transaction
      Result = Struct.new(:parameters, :data)

      # Size of the SMB1 header in bytes
      HEADER_SIZE = 32

      # Offset of the WordCount field, right after the SMB1 header
      WORD_COUNT_OFFSET = HEADER_SIZE

      # "\xFFSMB" as it appears on the wire
      PROTOCOL_ID = [RubySMB::SMB1::SMB_PROTOCOL_ID].pack('N').freeze

      # SMB1 header flag indicating the packet is a server reply
      FLAGS_REPLY = 0x80

      # Upper bound for a declared parameter or data total. A server declares
      # these totals before any fragment is received, so they cannot be
      # trusted blindly; capping them prevents memory exhaustion.
      DEFAULT_MAX_TOTAL_SIZE = 16 * 1024 * 1024

      # Per-command location of the fragment fields in the parameter block.
      # Offsets are relative to the start of the packet (the SMB header).
      LAYOUTS = {
        RubySMB::SMB1::Commands::SMB_COM_TRANSACTION  => { word_count: 10, wide: false },
        RubySMB::SMB1::Commands::SMB_COM_TRANSACTION2 => { word_count: 10, wide: false },
        RubySMB::SMB1::Commands::SMB_COM_NT_TRANSACT  => { word_count: 18, wide: true }
      }.freeze

      # Tracks the coverage of a single region (parameters or data) of the
      # transaction. Fragments are merged into a buffer of the declared total
      # size while a list of covered intervals records which bytes have
      # actually been received.
      class Region
        # @return [Integer, nil] the declared total size of the region
        attr_reader :total

        def initialize(name:, max_total_size:)
          @name = name
          @max_total_size = max_total_size
          @total = nil
          @buffer = nil
          @intervals = []
        end

        # Records the declared total size of the region. Every fragment must
        # declare the same total.
        #
        # @param total [Integer] the TotalParameterCount or TotalDataCount from a fragment
        # @raise [RubySMB::Error::InvalidPacket] if the total is implausible or
        #   conflicts with a previously declared total
        def declare_total(total)
          if @total.nil?
            if total > @max_total_size
              raise RubySMB::Error::InvalidPacket,
                    "Declared #{@name} total size #{total} exceeds the maximum allowed #{@max_total_size}"
            end
            @total = total
            @buffer = ("\x00".b * total)
          elsif total != @total
            raise RubySMB::Error::InvalidPacket,
                  "Conflicting #{@name} total size: expected #{@total}, got #{total}"
          end
        end

        # Merges a fragment chunk into the region at the given displacement.
        # Overlapping previously received bytes is only allowed when the
        # overlapping bytes are identical; a conflicting overlap is rejected
        # and the previously accepted bytes are kept.
        #
        # @param displacement [Integer] the displacement of the chunk within the region
        # @param chunk [String] the fragment bytes for this region
        # @raise [RubySMB::Error::InvalidPacket] if the chunk lies outside the
        #   declared total or conflicts with previously received bytes
        def write(displacement, chunk)
          range_end = displacement + chunk.bytesize
          if @total.nil? || range_end > @total
            raise RubySMB::Error::InvalidPacket,
                  "#{@name.capitalize} fragment (displacement #{displacement}, #{chunk.bytesize} bytes) "\
                  "exceeds the declared total of #{@total || 'unknown'} bytes"
          end

          @intervals.each do |interval|
            overlap_start = [interval.begin, displacement].max
            overlap_end = [interval.end, range_end].min
            next if overlap_start >= overlap_end

            existing = @buffer[overlap_start...overlap_end]
            incoming = chunk[(overlap_start - displacement)...(overlap_end - displacement)]
            unless existing == incoming
              raise RubySMB::Error::InvalidPacket,
                    "Conflicting #{@name} fragment overlap at displacement #{overlap_start}"
            end
          end

          @buffer[displacement, chunk.bytesize] = chunk
          merge_interval(displacement...range_end)
        end

        # @return [Boolean] true only when every byte of the declared total
        #   has been received
        def complete?
          return false if @total.nil?
          @total.zero? || @intervals == [0...@total]
        end

        # @return [String] the reassembled bytes (only meaningful when complete)
        def bytes
          @buffer || ''.b
        end

        private

        def merge_interval(range)
          @intervals << range
          @intervals.sort_by!(&:begin)
          merged = [@intervals.first]
          @intervals.each do |interval|
            last = merged.last
            if interval.begin <= last.end
              merged[-1] = last.begin...[last.end, interval.end].max
            else
              merged << interval
            end
          end
          @intervals = merged
        end
      end

      def initialize(max_total_size: DEFAULT_MAX_TOTAL_SIZE)
        @max_total_size = max_total_size
        reset!
      end

      # Drops all buffered fragments, returning the reassembler to its initial
      # state. Called automatically whenever a fragment is rejected so that
      # stale fragments can never leak into a subsequent transaction.
      #
      # @return [self]
      def reset!
        @identity = nil
        @parameter_region = Region.new(name: 'parameter', max_total_size: @max_total_size)
        @data_region = Region.new(name: 'data', max_total_size: @max_total_size)
        self
      end

      # Feeds one raw transaction response fragment into the reassembler.
      #
      # @param raw_response [String, #to_binary_s] the raw SMB1 transaction
      #   response packet
      # @return [Boolean] true when this fragment completes the transaction
      # @raise [RubySMB::Error::InvalidPacket] if the fragment is malformed,
      #   belongs to a different transaction or conflicts with previously
      #   received fragments; the reassembler is reset in this case
      def add_fragment(raw_response)
        raw_response = raw_response.to_binary_s if raw_response.respond_to?(:to_binary_s)
        apply_fragment(parse_fragment(raw_response.to_s.b))
        complete?
      rescue RubySMB::Error::InvalidPacket
        reset!
        raise
      end

      # @return [Boolean] true only when both the parameter and the data
      #   region have been fully received
      def complete?
        @parameter_region.complete? && @data_region.complete?
      end

      # Returns the reassembled transaction. Every returned byte originates
      # from fragments of one single, fully received transaction.
      #
      # @return [Result] the reassembled parameters and data
      # @raise [RubySMB::Error::RubySMBError] if the transaction is incomplete
      def assemble
        unless complete?
          raise RubySMB::Error::RubySMBError,
                'Cannot assemble the transaction: the parameter and data regions are not both complete'
        end
        Result.new(@parameter_region.bytes, @data_region.bytes)
      end

      private

      # A single parsed and bounds-checked transaction response fragment
      Fragment = Struct.new(
        :identity, :total_parameter_count, :total_data_count,
        :parameter_displacement, :parameters, :data_displacement, :data
      )

      # Parses and validates the envelope of a raw fragment: protocol,
      # command, reply flag, word count, packet length and the in-packet
      # offset/count of both regions.
      #
      # @param raw [String] the raw packet (binary encoding)
      # @return [Fragment]
      # @raise [RubySMB::Error::InvalidPacket] if the packet is malformed
      def parse_fragment(raw)
        unless raw.bytesize >= HEADER_SIZE && raw[0, 4] == PROTOCOL_ID
          raise RubySMB::Error::InvalidPacket, 'Not an SMB1 packet'
        end

        command = raw.getbyte(4)
        layout = LAYOUTS[command]
        unless layout
          raise RubySMB::Error::InvalidPacket,
                format('Not an SMB1 transaction response (command=0x%02x)', command)
        end

        unless (raw.getbyte(9) & FLAGS_REPLY) == FLAGS_REPLY
          raise RubySMB::Error::InvalidPacket, 'Not a server reply packet'
        end

        word_count = raw.getbyte(WORD_COUNT_OFFSET)
        if word_count.nil? || word_count < layout[:word_count]
          raise RubySMB::Error::InvalidPacket,
                "Truncated parameter block (WordCount=#{word_count || 'none'})"
        end
        if raw.bytesize < WORD_COUNT_OFFSET + 1 + (word_count * 2)
          raise RubySMB::Error::InvalidPacket, 'Truncated packet: smaller than the declared parameter block'
        end

        if layout[:wide]
          # 3 reserved bytes precede the 32-bit fragment fields
          fields = raw.unpack("x#{WORD_COUNT_OFFSET + 4}V8")
        else
          # 16-bit totals, 2 reserved bytes, then the 16-bit fragment fields
          fields = raw.unpack("x#{WORD_COUNT_OFFSET + 1}v2x2v6")
        end
        total_parameter_count, total_data_count,
          parameter_count, parameter_offset, parameter_displacement,
          data_count, data_offset, data_displacement = fields

        Fragment.new(
          [command, raw[12, 2], raw[24, 8]],
          total_parameter_count,
          total_data_count,
          parameter_displacement,
          extract_region(raw, 'parameter', parameter_offset, parameter_count),
          data_displacement,
          extract_region(raw, 'data', data_offset, data_count)
        )
      end

      # Extracts a region's bytes from the packet, verifying that the
      # in-packet offset and count lie within the received packet. A packet
      # that is shorter than its declared counts is rejected.
      #
      # @param raw [String] the raw packet
      # @param name [String] the region name, for error messages
      # @param offset [Integer] the in-packet offset of the region
      # @param count [Integer] the number of bytes the region occupies
      # @return [String] the region bytes
      # @raise [RubySMB::Error::InvalidPacket] if offset/count are out of bounds
      def extract_region(raw, name, offset, count)
        return ''.b if count.zero?

        if offset < HEADER_SIZE || offset > raw.bytesize || count > raw.bytesize - offset
          raise RubySMB::Error::InvalidPacket,
                "#{name.capitalize} region (offset #{offset}, #{count} bytes) lies outside "\
                "the received packet of #{raw.bytesize} bytes"
        end
        raw[offset, count]
      end

      # Validates a parsed fragment against the current transaction state and
      # merges it into the parameter and data regions.
      #
      # @param fragment [Fragment]
      # @raise [RubySMB::Error::InvalidPacket] if the fragment belongs to a
      #   different transaction or declares conflicting totals
      def apply_fragment(fragment)
        if @identity.nil?
          @identity = fragment.identity
        elsif @identity != fragment.identity
          raise RubySMB::Error::InvalidPacket,
                'Fragment belongs to a different transaction (command/PID/TID/UID/MID mismatch)'
        end

        @parameter_region.declare_total(fragment.total_parameter_count)
        @data_region.declare_total(fragment.total_data_count)
        @parameter_region.write(fragment.parameter_displacement, fragment.parameters) unless fragment.parameters.empty?
        @data_region.write(fragment.data_displacement, fragment.data) unless fragment.data.empty?
      end
    end
  end
end
