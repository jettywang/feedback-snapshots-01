
# Directed mutations for NDR conformant varying array size information.
#
# Each fixture is an independent byte layout. The expectations come from that
# layout (32-bit little-endian size words, NDR element alignment, element
# widths), not from the parser under test. The matching finite array model is
# simple: the transmitted element count cannot exceed the number of element
# slots the remaining bytes can hold.
RSpec.describe RubySMB::Dcerpc::Ndr::NdrConfVarArray do
  let(:ndr) { RubySMB::Dcerpc::Ndr }
  let(:deferred_element_name) { 'directed_mutation_deferred_element' }
  let(:deferred_element_class) do
    Class.new(ndr::NdrStruct) do
      default_parameters byte_align: 4
      endian :little

      ndr_uint32     :id
      ndr_string_ptr :name
    end
  end
  let(:array_class) do
    element_name = deferred_element_name
    Class.new(ndr::NdrConfVarArray) { default_parameters type: element_name.to_sym }
  end

  before :example do
    BinData::RegisteredClasses.register(deferred_element_name, deferred_element_class)
  end

  after :example do
    BinData::RegisteredClasses.unregister(deferred_element_name)
  end

  def u32(*values)
    values.pack('L<*')
  end

  # The three size words, followed by the caller's element bytes.
  def size_information(max_count, offset, actual_count)
    u32(max_count, offset, actual_count)
  end

  describe 'a legal non-zero offset slice' do
    # max_count=6 offset=2 actual_count=2 -> window [2, 4) inside [0, 6).
    # Elements are [id, ref_id] pairs; each deferred string is
    # [max_count, offset, actual_count, bytes] and starts 4-byte aligned:
    #   0..12   size information
    #  12..20   element 0 (id=0x11111111, ref_id=1)
    #  20..28   element 1 (id=0x22222222, ref_id=2)
    #  28..42   deferred element 0 string: 2 bytes "hi"
    #  42..44   alignment pad
    #  44..57   deferred element 1 string: 1 byte "Z"
    #  57..59   bytes belonging to the enclosing structure, not the array
    let(:tail) { "\xDE\xAD".b }
    let(:binary) do
      layout = +''.b
      layout << size_information(6, 2, 2)
      layout << u32(0x11111111, 1)
      layout << u32(0x22222222, 2)
      layout << size_information(2, 0, 2) << 'hi'.b
      layout << "\x00\x00".b
      layout << size_information(1, 0, 1) << 'Z'.b
      layout
    end

    it 'parses exactly the two in-window elements' do
      array = array_class.read(binary)
      expect(array.map(&:id)).to eq([0x11111111, 0x22222222])
      expect(array.map { |e| e.name.to_s }).to eq(['hi', 'Z'])
    end

    it 'keeps the transmitted offset and counts' do
      array = array_class.read(binary)
      expect(array.max_count).to eq(6)
      expect(array.offset).to eq(2)
      expect(array.actual_count).to eq(2)
    end

    it 'consumes only the bytes that belong to the array' do
      io = StringIO.new(binary + tail)
      array_class.read(io)
      expect(io.pos).to eq(binary.bytesize)
      expect(io.read).to eq(tail)
    end

    it 're-encodes exactly the parsed range' do
      array = array_class.read(binary + tail)
      expect(array.to_binary_s).to eq(binary)
      expect(array.num_bytes).to eq(binary.bytesize)
    end

    it 'accepts the boundary case offset + actual_count == max_count' do
      # Same layout as above, with max_count reduced to the window end.
      boundary = binary.dup
      boundary[0, 4] = u32(4)
      expect { array_class.read(boundary) }.to_not raise_error
      expect(array_class.read(boundary).map(&:id)).to eq([0x11111111, 0x22222222])
      expect(array_class.read(boundary).to_binary_s).to eq(boundary)
    end

    it 'keeps a tail that itself looks like size information out of the array' do
      # The tail would be a valid size-information header for another array.
      fake_tail = size_information(1, 0, 1) + 'Q'.b
      io = StringIO.new(binary + fake_tail)
      array = array_class.read(io)
      expect(array.map { |e| e.name.to_s }).to eq(['hi', 'Z'])
      expect(io.pos).to eq(binary.bytesize)
      expect(io.read).to eq(fake_tail)
    end

    it 'consumes deferred referents in stream order, not by element value' do
      # Deferred string "B" belongs to element 0x11 and "AA" to 0x22. Swapping
      # the deferred payloads must swap the names, proving the reader follows
      # pointer order rather than sorting or inferring by element content.
      swapped = +''.b
      swapped << size_information(6, 2, 2)
      swapped << u32(0x11, 1) << u32(0x22, 2)
      swapped << size_information(1, 0, 1) << 'B'.b
      swapped << "\x00\x00\x00".b
      swapped << size_information(2, 0, 2) << 'AA'.b
      array = array_class.read(swapped)
      expect(array.map { |e| [e.id, e.name.to_s] }).to eq([[0x11, 'B'], [0x22, 'AA']])
      expect(array.to_binary_s).to eq(swapped)
    end

    it 'does not confuse an element whose bytes look like a string header' do
      # id = 3 is exactly the max_count of "one" below.
      layout = +''.b
      layout << size_information(3, 0, 1)
      layout << u32(3, 1)
      layout << size_information(3, 0, 3) << 'one'.b
      array = array_class.read(layout)
      expect(array.map(&:id)).to eq([3])
      expect(array[0].name.to_s).to eq('one')
      expect(array.to_binary_s).to eq(layout)
    end
  end

  describe 'element content that mimics the following field' do
    # A pointer-to-array field followed by a uint32 tail. The tag, every element
    # id, every deferred payload, and the tail all carry 0xCAFE. Only the size
    # information decides where each range ends.
    let(:tail_struct_class) do
      pointer_plugin = ndr::PointerClassPlugin
      pointer_class = Class.new(ndr::NdrConfVarArray) do
        default_parameters type: 'directed_mutation_deferred_element'
        extend pointer_plugin
      end
      BinData::RegisteredClasses.register('directed_mutation_items_ptr', pointer_class)

      Class.new(ndr::NdrStruct) do
        default_parameters byte_align: 4
        endian :little

        ndr_uint32                     :tag
        directed_mutation_items_ptr    :items
        ndr_uint32                     :tail
      end
    end

    after :example do
      BinData::RegisteredClasses.unregister('directed_mutation_items_ptr')
    end

    it 'stops at the array bound and leaves the tail untouched' do
      value = 0xCAFE
      struct = tail_struct_class.new(
        tag: value,
        items: [{ id: value, name: [value].pack('L<') }, { id: value, name: [value].pack('L<') }],
        tail: value
      )
      binary = struct.to_binary_s
      io = StringIO.new(binary)
      parsed = tail_struct_class.read(io)
      expect(parsed.tag).to eq(value)
      expect(parsed.items.map(&:id)).to eq([value, value])
      expect(parsed.items.map { |e| e.name.to_s.bytes }).to eq([[0xFE, 0xCA, 0, 0]] * 2)
      expect(parsed.tail).to eq(value)
      expect(io.pos).to eq(binary.bytesize)
      expect(parsed.to_binary_s).to eq(binary)
    end
  end

  describe 'element alignment' do
    # The 12-byte size information is already 8- and 4-byte aligned, so the
    # first transmitted element starts at 12. A non-zero offset does not move
    # the first element; it indexes the conformant array.
    it 'honours a two-byte element width' do
      klass = Class.new(ndr::NdrConfVarArray) { default_parameters type: :ndr_uint16 }
      layout = size_information(4, 1, 3) + [0xAA, 0xBB, 0xCC].pack('S<*')
      array = klass.read(layout)
      expect(array.to_a).to eq([0xAA, 0xBB, 0xCC])
      expect(array.to_binary_s).to eq(layout)
    end

    it 'keeps one-byte elements unpadded' do
      klass = Class.new(ndr::NdrConfVarArray) { default_parameters type: :ndr_uint8 }
      layout = size_information(8, 3, 2) + [0x09, 0x08].pack('C*')
      array = klass.read(layout)
      expect(array.to_a).to eq([0x09, 0x08])
      expect(array.to_binary_s).to eq(layout)
    end

    it 'aligns an eight-byte element after the size information' do
      klass = Class.new(ndr::NdrConfVarArray) { default_parameters type: :ndr_uint64 }
      layout = size_information(3, 1, 2) + ("\x00" * 4) + [0xAA, 0xBB].pack('Q<*')
      array = klass.read(layout)
      expect(array.to_a).to eq([0xAA, 0xBB])
      expect(array.to_binary_s).to eq(layout)
    end

    # A varying string element carries its own offset/actual_count pair, so
    # the smallest element is 8 bytes, not the string body length.
    it 'accounts for varying-string element headers' do
      klass = Class.new(ndr::NdrConfVarArray) { default_parameters type: :ndr_var_string }
      layout = +''.b
      layout << size_information(3, 1, 2)
      layout << u32(0, 2) << 'hi'.b
      layout << u32(0, 1) << 'Z'.b
      array = klass.read(layout)
      expect(array.to_a).to eq(['hi', 'Z'])
      expect(array.to_binary_s).to eq(layout)
    end

    it 'rejects a huge varying-string count using the header width' do
      klass = Class.new(ndr::NdrConfVarArray) { default_parameters type: :ndr_var_string }
      layout = size_information(0xFFFFFFFF, 0, 0xFFFFFFFF) + u32(0, 4) + 'abcd'.b
      expect { klass.read(layout) }.to raise_error(IOError, /cannot fit in the 12 remaining byte/)
    end
  end

  describe 'conflicting size information' do
    it 'rejects offset + actual_count beyond max_count before reading elements' do
      # max_count=2, offset=2, actual_count=2 -> window [2, 4) exceeds [0, 2).
      layout = size_information(2, 2, 2) + u32(0xAA, 0xBB)
      io = StringIO.new(layout)
      expect { array_class.read(io) }.to raise_error(IOError, /exceeds max_count/)
      expect(io.pos).to eq(12)
      expect(io.read).to eq(u32(0xAA, 0xBB))
    end

    it 'rejects an upper bound smaller than the actual window' do
      # max_count=3, offset=0, actual_count=4: the declared bound is too small.
      layout = size_information(3, 0, 4) + u32(0xAA, 0xBB, 0xCC, 0xDD)
      io = StringIO.new(layout)
      expect { array_class.read(io) }.to raise_error(IOError, /exceeds max_count/)
      expect(io.pos).to eq(12)
      expect(io.read).to eq(u32(0xAA, 0xBB, 0xCC, 0xDD))
    end

    it 'rejects a huge offset without letting the sum wrap' do
      # 0xFFFFFFFE + 2 would wrap to 0 in 32-bit arithmetic.
      layout = size_information(4, 0xFFFFFFFE, 2) + u32(0xAA)
      expect { array_class.read(layout) }.to raise_error(IOError, /exceeds max_count/)
    end

    it 'rejects a huge actual_count with a small input' do
      layout = size_information(0xFFFFFFFF, 0, 0xFFFFFFFF) + u32(0xAA)
      expect { array_class.read(layout) }.to raise_error(IOError, /cannot fit/)
    end

    it 'rejects a huge conformant max_count with a small input' do
      klass = Class.new(ndr::NdrConfArray) { default_parameters type: :ndr_uint32 }
      layout = u32(0xFFFFFFFF) + ("\x00" * 16)
      expect { klass.read(layout) }.to raise_error(IOError, /cannot fit/)
    end
  end

  describe 'allocation guard' do
    # Counting instantiations proves the parser does not build the declared
    # number of elements before validating it against the stream.
    let(:counting_element_class) do
      Class.new(BinData::Uint32le) do
        default_parameters byte_align: 4
        class << self; attr_accessor :instances; end
        self.instances = 0

        def initialize_instance
          self.class.instances += 1
          super
        end
      end
    end
    let(:counting_array_class) do
      BinData::RegisteredClasses.register('directed_mutation_counting_u32', counting_element_class)
      Class.new(ndr::NdrConfVarArray) do
        default_parameters type: :directed_mutation_counting_u32
      end
    end

    after :example do
      BinData::RegisteredClasses.unregister('directed_mutation_counting_u32')
    end

    it 'rejects a 2^32-1 count after only the prototype was instantiated' do
      array = counting_array_class.new
      counting_element_class.instances = 0
      expect {
        array.read(size_information(0xFFFFFFFF, 0, 0xFFFFFFFF) + u32(0xAA))
      }.to raise_error(IOError, /cannot fit/)
      expect(array).to be_empty
      expect(counting_element_class.instances).to be <= 4
    end

    it 'still reads a legal count' do
      array = counting_array_class.new
      array.read(size_information(2, 0, 2) + u32(7, 8))
      expect(array.to_a).to eq([7, 8])
    end
  end

  describe 'truncated input' do
    it 'rejects a stream cut inside the last deferred referent' do
      layout = +''.b
      layout << size_information(4, 0, 1)
      layout << u32(0xAA, 1)
      layout << size_information(3, 0, 3) << 'on'.b
      expect { array_class.read(layout) }.to raise_error(IOError)
    end

    it 'rejects a stream that ends inside the resident elements' do
      layout = size_information(4, 0, 4) + u32(0xAA, 0xBB)
      expect { array_class.read(layout) }.to raise_error(IOError)
    end
  end

  describe 're-encoding bounds' do
    it 'refuses to encode a varying count that disagrees with the elements' do
      array = array_class.new([{ id: 1, name: 'a' }])
      array.max_count = 4
      array.offset = 2
      array.actual_count = 3
      expect { array.to_binary_s }.to raise_error(IOError, /actual_count/)
    end

    it 'refuses to encode a window beyond the conformant bound' do
      array = array_class.new([{ id: 1, name: 'a' }, { id: 2, name: 'b' }])
      array.max_count = 3
      array.offset = 2
      expect { array.to_binary_s }.to raise_error(IOError, /exceeds max_count/)
    end

    it 'accepts a legal non-zero offset window and round-trips it' do
      array = array_class.new([{ id: 1, name: 'a' }, { id: 2, name: 'b' }])
      array.max_count = 6
      array.offset = 2
      binary = array.to_binary_s
      parsed = array_class.read(binary)
      expect(parsed.offset).to eq(2)
      expect(parsed.actual_count).to eq(2)
      expect(parsed.max_count).to eq(6)
      expect(parsed.to_binary_s).to eq(binary)
    end
  end

  describe 'when nested in a structure' do
    # A conformant varying array in a structure has its max_count hoisted to
    # the start of the structure; offset/actual_count stay in place.
    let(:struct_class) do
      Class.new(ndr::NdrStruct) do
        default_parameters byte_align: 4
        endian :little

        ndr_uint32         :tag
        ndr_conf_var_array :items, type: 'directed_mutation_deferred_element'
      end
    end

    # max_count=6 tag=0xAAAA offset=2 actual_count=2, two elements, then the
    # two deferred strings. No field follows, so this is the whole body.
    let(:binary) do
      layout = +''.b
      layout << u32(6, 0xAAAA, 2, 2)
      layout << u32(0x11, 1) << u32(0x22, 2)
      layout << size_information(2, 0, 2) << 'hi'.b
      layout << "\x00\x00".b
      layout << size_information(1, 0, 1) << 'Z'.b
      layout
    end

    it 'reads the nested array and consumes the whole body' do
      tail = "\xBE\xEF".b
      io = StringIO.new(binary + tail)
      struct = struct_class.read(io)
      expect(struct.tag).to eq(0xAAAA)
      expect(struct.items.map(&:id)).to eq([0x11, 0x22])
      expect(struct.items.max_count).to eq(6)
      expect(io.pos).to eq(binary.bytesize)
      expect(io.read).to eq(tail)
    end

    it 're-encodes the hoisted max_count verbatim, not as the element count' do
      struct = struct_class.read(binary)
      expect(struct.to_binary_s).to eq(binary)
    end

    it 'rejects a conflict before consuming the deferred block' do
      conflict = binary.dup
      conflict[0, 4] = u32(3) # max_count=3 < offset(2) + actual(2)
      io = StringIO.new(conflict)
      expect { struct_class.read(io) }.to raise_error(IOError, /exceeds max_count/)
      # max_count (4), tag (4), offset (4) and actual_count (4) were read; no
      # element or deferred byte was touched.
      expect(io.pos).to eq(16)
      expect(io.read).to eq(binary.byteslice(16..-1))
    end
  end
end
