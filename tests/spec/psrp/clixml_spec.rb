require 'winrm/psrp/clixml'

describe WinRM::PSRP::Clixml do
  describe '.decode' do
    # Each fixed line is asserted by Unicode code point rather than terminal
    # rendering so surrogate, replacement and underscore cases are unambiguous.
    shared_examples 'a CLIXML decode line' do |wire, expected_codepoints|
      it "decodes #{wire.inspect} to #{expected_codepoints.inspect}" do
        decoded = described_class.decode(wire)
        expect(decoded.valid_encoding?).to be(true)
        expect(decoded.codepoints.map { |cp| format('U+%04X', cp) })
          .to eq(expected_codepoints)
      end
    end

    context 'plain text without escapes' do
      include_examples 'a CLIXML decode line', 'hello',
                       %w[U+0068 U+0065 U+006C U+006C U+006F]
    end

    context 'a single escape token' do
      include_examples 'a CLIXML decode line', '_x0041_', %w[U+0041]
      include_examples 'a CLIXML decode line', '_x0061_', %w[U+0061]
    end

    context 'adjacent escape tokens are one UTF-16 run' do
      include_examples 'a CLIXML decode line', '_x0041__x0042_',
                       %w[U+0041 U+0042]
      include_examples 'a CLIXML decode line', '_x000D__x000A_',
                       %w[U+000D U+000A]
    end

    context 'a valid surrogate pair is reassembled into one code point' do
      include_examples 'a CLIXML decode line', '_xD83D__xDE00_',
                       %w[U+1F600]
      include_examples 'a CLIXML decode line', 'a_xD83D__xDE00_b',
                       %w[U+0061 U+1F600 U+0062]
      include_examples 'a CLIXML decode line', '_xD834__xDF06_',
                       %w[U+1D306]
    end

    context 'bad surrogate sequences are replaced, never raised' do
      include_examples 'a CLIXML decode line', '_xD83D_', %w[U+FFFD]
      include_examples 'a CLIXML decode line', '_xDE00_', %w[U+FFFD]
      include_examples 'a CLIXML decode line', '_xD83D__x0041_',
                       %w[U+FFFD U+0041]
      include_examples 'a CLIXML decode line', '_x0041__xDE00_',
                       %w[U+0041 U+FFFD]
      include_examples 'a CLIXML decode line', '_xD83D__xD83D_',
                       %w[U+FFFD U+FFFD]
      include_examples 'a CLIXML decode line', '_xDE00__xD83D__xDE00_',
                       %w[U+FFFD U+1F600]
    end

    context 'literal underscore patterns survive a single pass' do
      # A literal `_x0041_` is carried on the wire with its underscores escaped.
      include_examples 'a CLIXML decode line', '_x005F_x0041_x005F_',
                       %w[U+005F U+0078 U+0030 U+0030 U+0034 U+0031 U+005F]
      # An escaped underscore immediately followed by a real escape resolves
      # both, without re-scanning the emitted underscore.
      include_examples 'a CLIXML decode line', '_x005F__x0041_',
                       %w[U+005F U+0041]
      # Two escaped underscores then a literal token shape: the underscores
      # emitted inside the same call must not be treated as new escapes.
      include_examples 'a CLIXML decode line', '_x005F__x005F_x0041__',
                       %w[U+005F U+005F U+0078 U+0030 U+0030 U+0034 U+0031 U+005F U+005F]
    end

    context 'malformed tokens are treated as literal text' do
      include_examples 'a CLIXML decode line', '_x0041',
                       %w[U+005F U+0078 U+0030 U+0030 U+0034 U+0031]
      include_examples 'a CLIXML decode line', '_xGGGG_',
                       %w[U+005F U+0078 U+0047 U+0047 U+0047 U+0047 U+005F]
    end

    context 'multibyte literal text surrounding escapes' do
      include_examples 'a CLIXML decode line', "€_x0041_",
                       %w[U+20AC U+0041]
      include_examples 'a CLIXML decode line', "_x0041_€_x0042_",
                       %w[U+0041 U+20AC U+0042]
      include_examples 'a CLIXML decode line', "é_xD83D__xDE00_è",
                       %w[U+00E9 U+1F600 U+00E8]
    end

    it 'interprets each token once instead of replacing until exhausted' do
      # A single left-to-right pass keeps the escaped underscore and only the
      # token that genuinely follows it. A naive replace-to-fixpoint loop would
      # keep re-interpreting the emitted underscore and collapse the result
      # further, down to "A". Assert the stable single-pass contract instead.
      decoded = described_class.decode('_x005F__x0041_')
      expect(decoded).to eq("_A")
      expect(decoded.codepoints.map { |cp| format('U+%04X', cp) })
        .to eq(%w[U+005F U+0041])

      literal = described_class.decode('_x005F_x0041_x005F_')
      expect(literal).to eq('_x0041_')
    end

    it 'passes nil through as nil' do
      expect(described_class.decode(nil)).to be_nil
    end
  end
end
