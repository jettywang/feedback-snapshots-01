require 'winrm/psrp/message_data/base'
require 'winrm/psrp/message_data/pipeline_host_call'
require 'winrm/psrp/message_data/pipeline_output'
require 'winrm/psrp/message_data/error_record'

# Regression coverage for bounded parsing of untrusted CLIXML. These payloads
# are deliberately small (a few KB at most): each one triggers its parse path
# on structure rather than by exhausting the machine.
describe 'CLIXML bounded parsing', unit: true do
  let(:billion_laughs) do
    defs = %Q{<!DOCTYPE Obj [\n<!ENTITY e0 "ab">\n}
    1.upto(8) do |i|
      defs += %Q{<!ENTITY e#{i} "#{Array.new(5) { "&e#{i - 1};" }.join}">\n}
    end
    "#{defs}]><Obj><MS><S>&e8;</S></MS></Obj>"
  end

  let(:deeply_nested) do
    '<Obj><MS>' + ('<Obj><MS>' * 200) + '<S>x</S>' +
      ('</MS></Obj>' * 200) + '</MS></Obj>'
  end

  let(:oversized) { "<Obj><MS><S>#{'a' * 600_000}</S></MS></Obj>" }
  let(:malformed_namespace) { %q{<Obj xmlns:1="bad"><MS><S>x</S></MS></Obj>} }
  let(:truncated) { '<Obj><MS><S>x</S>' }

  shared_examples 'a bounded CLIXML entry point' do
    it 'rejects entity expansion before any output is produced' do
      expect { invoke(described_class.new(billion_laughs)) }
        .to raise_error(WinRM::WinRMXMLParseError, /entity expansion|malformed XML/)
    end

    it 'rejects excessive nesting rather than overflowing the XPath stack' do
      expect { invoke(described_class.new(deeply_nested)) }
        .to raise_error(WinRM::WinRMXMLParseError, /depth exceeded|malformed XML/)
    end

    it 'rejects an oversized document' do
      expect { invoke(described_class.new(oversized)) }
        .to raise_error(WinRM::WinRMXMLParseError, /exceeds limit/)
    end

    it 'rejects a malformed namespace declaration' do
      expect { invoke(described_class.new(malformed_namespace)) }
        .to raise_error(WinRM::WinRMXMLParseError, /malformed XML/)
    end

    it 'rejects truncated markup' do
      expect { invoke(described_class.new(truncated)) }
        .to raise_error(WinRM::WinRMXMLParseError)
    end

    it 'raises the WinRM parse error, never a raw REXML or stack error' do
      [billion_laughs, deeply_nested, oversized, malformed_namespace, truncated].each do |payload|
        begin
          invoke(described_class.new(payload))
          raise 'expected a bounded-parse rejection'
        rescue WinRM::WinRMXMLParseError
          # expected
        end
      end
    end
  end

  describe WinRM::PSRP::MessageData::PipelineHostCall do
    # The Nori/REXML pull-parser path, reached through Base#clixml.
    let(:benign) do
      '<Obj><MS><Obj N="mi"><ToString>WriteLine1</ToString></Obj>' \
        '<Obj N="mp"><LST><S>hello</S></LST></Obj></MS></Obj>'
    end

    def invoke(object)
      object.method_identifier
    end

    it_behaves_like 'a bounded CLIXML entry point'

    it 'still decodes a small well-formed host call' do
      expect(described_class.new(benign).method_identifier).to eq('WriteLine1')
    end

    it 'validates through SafeXML before Nori touches the bytes' do
      expect(WinRM::SafeXML).to receive(:validate!)
        .with(benign, 'WinRM CLIXML message data').and_call_original
      described_class.new(benign).method_identifier
    end
  end

  describe WinRM::PSRP::MessageData::PipelineOutput do
    let(:benign) { '<Obj><S>some data</S></Obj>' }

    def invoke(object)
      object.output
    end

    it_behaves_like 'a bounded CLIXML entry point'

    it 'still decodes a small well-formed output fragment' do
      expect(described_class.new(benign).output).to eq("some data\r\n")
    end

    it 'parses through the SafeXML document entry point' do
      expect(WinRM::SafeXML).to receive(:parse)
        .with(benign, 'WinRM CLIXML pipeline output').and_call_original
      described_class.new(benign).output
    end
  end

  describe WinRM::PSRP::MessageData::ErrorRecord do
    let(:benign) do
      '<Obj><MS><S N="FullyQualifiedErrorId">NativeCommandError</S>' \
        '<Obj N="InvocationInfo"><Props><S N="Line">go</S></Props></Obj>' \
        '<S N="ErrorCategory_Message">cat</S></MS></Obj>'
    end

    def invoke(object)
      object.fully_qualified_error_id
    end

    it_behaves_like 'a bounded CLIXML entry point'

    it 'still reads a property from a small well-formed error record' do
      expect(described_class.new(benign).fully_qualified_error_id)
        .to eq('NativeCommandError')
    end

    it 'parses through the SafeXML document entry point' do
      expect(WinRM::SafeXML).to receive(:parse)
        .with(benign, 'WinRM CLIXML error record').and_call_original
      described_class.new(benign).fully_qualified_error_id
    end

    it 'caches the bounded document and does not re-parse on repeat access' do
      record = described_class.new(benign)
      expect(WinRM::SafeXML).to receive(:parse).once.and_call_original
      record.fully_qualified_error_id
      record.error_category_message
    end
  end
end
