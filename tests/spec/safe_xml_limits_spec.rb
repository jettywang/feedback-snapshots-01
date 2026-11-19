require 'benchmark'
require 'winrm/safe_xml'

describe 'WinRM::SafeXML structural budgets', unit: true do
  describe 'bounded nesting depth' do
    # Root counts toward depth, so 255 nested <a> under <r> sits exactly on
    # the limit while 256 crosses it.
    let(:at_limit) { "<r>#{'<a>' * 255}x#{'</a>' * 255}</r>" }
    let(:over_limit) { "<r>#{'<a>' * 256}x#{'</a>' * 256}</r>" }

    it 'accepts nesting at the depth limit' do
      expect { WinRM::SafeXML.parse(at_limit) }.not_to raise_error
    end

    it 'rejects nesting past the depth limit on the document path' do
      expect { WinRM::SafeXML.parse(over_limit, 'T') }
        .to raise_error(WinRM::WinRMXMLParseError, /depth exceeded/)
    end

    it 'rejects nesting past the depth limit on the validated (Nori) path' do
      expect { WinRM::SafeXML.validate!(over_limit, 'T') }
        .to raise_error(WinRM::WinRMXMLParseError, /depth exceeded/)
    end

    it 'rejects before XPath traversal could overflow the stack' do
      expect { WinRM::SafeXML.parse(over_limit, 'T') }.to raise_error do |error|
        expect(error).to be_a(WinRM::WinRMXMLParseError)
        expect(error).not_to be_a(SystemStackError)
      end
    end
  end

  describe 'bounded document size' do
    it 'rejects a document over the byte budget' do
      oversized = "<r>#{'a' * (WinRM::SafeXML::MAX_DOCUMENT_BYTES + 1)}</r>"
      expect { WinRM::SafeXML.parse(oversized, 'T') }
        .to raise_error(WinRM::WinRMXMLParseError, /exceeds limit/)
    end

    it 'rejects oversize input on the validated (Nori) path' do
      oversized = "<r>#{'a' * (WinRM::SafeXML::MAX_DOCUMENT_BYTES + 1)}</r>"
      expect { WinRM::SafeXML.validate!(oversized, 'T') }
        .to raise_error(WinRM::WinRMXMLParseError, /exceeds limit/)
    end

    it 'accepts a long but in-budget text node without excessive work' do
      payload = "<r>#{'a' * 100_000}</r>"
      expect(WinRM::SafeXML.parse(payload).root.text.length).to eq(100_000)
    end
  end

  describe 'malformed namespace and markup variants' do
    [
      %q{<r xmlns:1="bad"/>},
      %q{<r: xmlns="urn:x"/>},
      %q{<r xmlns="urn:a" xmlns="urn:b"/>},
      %q{<a:r xmlns:a="urn:a"><b:x/></a:r>}
    ].each_with_index do |payload, i|
      it "rejects malformed namespace variant #{i}" do
        expect { WinRM::SafeXML.parse(payload, 'T') }
          .to raise_error(WinRM::WinRMXMLParseError, /malformed XML/)
      end
    end

    it 'rejects truncated and unclosed markup' do
      expect { WinRM::SafeXML.parse('<Envelope><Body>', 'T') }
        .to raise_error(WinRM::WinRMXMLParseError, /malformed XML/)
      expect { WinRM::SafeXML.parse('<r><a>text', 'T') }
        .to raise_error(WinRM::WinRMXMLParseError, /malformed XML/)
    end

    it 'rejects multiple root elements and trailing garbage' do
      expect { WinRM::SafeXML.parse('<a/><b/>', 'T') }
        .to raise_error(WinRM::WinRMXMLParseError, /malformed XML/)
      expect { WinRM::SafeXML.parse('<r/>trailing', 'T') }
        .to raise_error(WinRM::WinRMXMLParseError, /malformed XML/)
    end
  end

  describe 'work budget', :performance do
    it 'keeps a rejected deep payload cheap (no machine exhaustion)' do
      deep = "<r>#{'<a>' * 50_000}x#{'</a>' * 50_000}</r>"
      elapsed = Benchmark.realtime do
        expect { WinRM::SafeXML.validate!(deep, 'T') }
          .to raise_error(WinRM::WinRMXMLParseError)
      end
      expect(elapsed).to be < 1.0
    end

    it 'keeps a rejected oversize payload cheap' do
      oversized = "<r>#{'a' * 5_000_000}</r>"
      elapsed = Benchmark.realtime do
        expect { WinRM::SafeXML.parse(oversized, 'T') }
          .to raise_error(WinRM::WinRMXMLParseError)
      end
      expect(elapsed).to be < 1.0
    end
  end
end
