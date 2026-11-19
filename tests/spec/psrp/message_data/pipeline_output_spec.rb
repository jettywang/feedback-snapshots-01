require 'winrm/psrp/message_data/base'
require 'winrm/psrp/message_data/pipeline_output'

describe WinRM::PSRP::MessageData::PipelineOutput do
  subject { described_class.new(raw_data) }

  context 'receiving output with BOM and no new line' do
    let(:raw_data) { "\xEF\xBB\xBF<obj><S>some data</S></obj>" }

    it 'output removes BOM and adds newline' do
      expect(subject.output).to eq("some data\r\n")
    end
  end

  context 'receiving output with encoded new line' do
    let(:raw_data) { '<obj><S>some data_x000D__x000A_</S></obj>' }

    it 'decodes without double newline' do
      expect(subject.output).to eq("some data\r\n")
    end
  end

  context 'receiving output with new line in middle' do
    let(:raw_data) { '<obj><S>some_x000D__x000A_data</S></obj>' }

    it 'decodes and replaces newline' do
      expect(subject.output).to eq("some\r\ndata\r\n")
    end
  end

  context 'CLIXML character escapes' do
    def codepoints(text)
      text.codepoints.map { |cp| format('U+%04X', cp) }
    end

    it 'reassembles a surrogate pair into one supplementary code point' do
      output = described_class.new('<obj><S>_xD83D__xDE00_</S></obj>').output
      expect(output.valid_encoding?).to be(true)
      expect(codepoints(output)).to eq(%w[U+1F600 U+000D U+000A])
    end

    it 'keeps adjacent escapes in a single UTF-16 run' do
      output = described_class.new('<obj><S>_x0041__x0042_</S></obj>').output
      expect(codepoints(output)).to eq(%w[U+0041 U+0042 U+000D U+000A])
    end

    it 'restores a literal _x0041_ carried via escaped underscores' do
      raw = '<obj><S>_x005F_x0041_x005F_</S></obj>'
      output = described_class.new(raw).output
      expect(output).to eq("_x0041_\r\n")
      expect(codepoints(output))
        .to eq(%w[U+005F U+0078 U+0030 U+0030 U+0034 U+0031 U+005F U+000D U+000A])
    end

    it 'replaces an unpaired surrogate instead of raising' do
      output = described_class.new('<obj><S>_xD83D_</S></obj>').output
      expect(output.valid_encoding?).to be(true)
      expect(codepoints(output)).to eq(%w[U+FFFD U+000D U+000A])
    end

    it 'leaves XML entity decoding to the parser and only handles CLIXML' do
      output = described_class.new('<obj><S>&lt;_x0041_&gt;</S></obj>').output
      expect(codepoints(output)).to eq(%w[U+003C U+0041 U+003E U+000D U+000A])
    end
  end
end
