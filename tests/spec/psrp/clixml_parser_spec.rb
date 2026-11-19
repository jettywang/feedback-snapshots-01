require 'winrm/psrp/clixml_parser'

describe WinRM::PSRP::ClixmlParser do
  subject(:parser) { described_class.new }

  describe '#parse' do
    context 'primitive values' do
      it 'keeps strings as strings' do
        view = parser.parse('<obj><S>some data</S></obj>')
        node = view[:members]['S']
        expect(node[:kind]).to eq('primitive')
        expect(node[:value]).to eq('some data')
        expect(node[:value]).to be_a(String)
      end

      it 'coerces integers rather than stringifying them' do
        view = parser.parse('<Obj><I32 N="n">42</I32><I64 N="big">-9000000000</I64></Obj>')
        expect(view[:members]['n'][:value]).to eq(42)
        expect(view[:members]['n'][:value]).to be_a(Integer)
        expect(view[:members]['big'][:value]).to eq(-9_000_000_000)
      end

      it 'coerces booleans and doubles while retaining the raw text' do
        view = parser.parse('<Obj><B N="flag">true</B><D N="ratio">3.5</D></Obj>')
        expect(view[:members]['flag'][:value]).to eq(true)
        expect(view[:members]['flag'][:value]).to be_a(TrueClass)
        expect(view[:members]['ratio'][:value]).to eq(3.5)
        expect(view[:members]['ratio'][:value]).to be_a(Float)
        expect(view[:members]['ratio'][:raw]).to eq('3.5')
      end

      it 'represents Nil as an explicit null node' do
        view = parser.parse('<Obj><Nil N="missing"/></Obj>')
        node = view[:members]['missing']
        expect(node[:kind]).to eq('null')
        expect(node[:value]).to be_nil
      end

      it 'treats element names case-insensitively' do
        view = parser.parse('<obj><i32 N="n">7</i32><b N="b">false</b></obj>')
        expect(view[:members]['n'][:value]).to eq(7)
        expect(view[:members]['b'][:value]).to eq(false)
      end

      it 'records an unsupported element as unknown evidence without instantiating a class' do
        view = parser.parse('<Obj><MyCustomTag N="custom">raw-value</MyCustomTag></Obj>')
        node = view[:members]['custom']
        expect(node[:kind]).to eq('unknown')
        expect(node[:value_type]).to eq('MYCUSTOMTAG')
        expect(node[:raw]).to eq('raw-value')
      end
    end

    context 'type information' do
      it 'captures the .NET type name hierarchy' do
        xml = '<Obj RefId="0"><TN RefId="0"><T>System.IO.FileInfo</T><T>System.Object</T></TN>' \
              '<MS><S N="Name">a.txt</S></MS></Obj>'
        view = parser.parse(xml)
        expect(view[:ref_id]).to eq(0)
        expect(view[:type_names]).to eq(['System.IO.FileInfo', 'System.Object'])
      end

      it 'resolves a shared type-name reference within the message' do
        xml = '<Obj RefId="0"><MS>' \
              '<Obj N="first" RefId="1"><TN RefId="0"><T>Thing</T></TN><MS><S N="k">a</S></MS></Obj>' \
              '<Obj N="second" RefId="2"><TN RefId="0"/><MS><S N="k">b</S></MS></Obj>' \
              '</MS></Obj>'
        view = parser.parse(xml)
        expect(view[:members]['second'][:type_names]).to eq(['Thing'])
      end
    end

    context 'collections' do
      it 'maps lists and arrays onto ordered elements' do
        view = parser.parse('<Obj><LST><I32>1</I32><S>two</S></LST></Obj>')
        values = view[:elements].map { |node| node[:value] }
        expect(values).to eq([1, 'two'])
      end

      it 'maps dictionaries into key/value entries' do
        xml = '<Obj><DCT><En><S N="K">a</S><I32 N="V">1</I32></En></DCT></Obj>'
        view = parser.parse(xml)
        entry = view[:entries].first
        expect(entry[:key][:value]).to eq('a')
        expect(entry[:value][:value]).to eq(1)
      end
    end

    context 'object references and identity' do
      let(:shared_xml) do
        '<Obj RefId="0"><MS>' \
          '<Obj N="shared_a" RefId="1"><MS><S N="k">v</S></MS></Obj>' \
          '<Obj N="shared_b"><Obj RefId="1"/></Obj>' \
          '<Obj N="distinct_a" RefId="3"><MS><S N="k">v</S></MS></Obj>' \
          '<Obj N="distinct_b" RefId="4"><MS><S N="k">v</S></MS></Obj>' \
        '</MS></Obj>'
      end

      it 'renders a shared object as a reference to the defining ref id' do
        view = parser.parse(shared_xml)
        expect(view[:members]['shared_b'][:members]['Obj']).to eq(kind: 'reference', ref_id: 1)
      end

      it 'keeps content-equal objects as distinct identities' do
        view = parser.parse(shared_xml)
        distinct_a = view[:members]['distinct_a']
        distinct_b = view[:members]['distinct_b']
        expect(distinct_a[:members]).to eq(distinct_b[:members])
        expect(distinct_a[:ref_id]).not_to eq(distinct_b[:ref_id])
      end

      it 'resolves a forward reference whose definition appears later' do
        xml = '<Obj RefId="0"><MS><Obj N="early"><Obj RefId="1"/></Obj>' \
              '<Obj N="late" RefId="1"><MS><S N="k">v</S></MS></Obj></MS></Obj>'
        view = parser.parse(xml)
        expect(view[:members]['early'][:members]['Obj']).to eq(kind: 'reference', ref_id: 1)
      end

      it 'renders a cycle distinctly from a normal reference' do
        xml = '<Obj RefId="5"><MS><Obj N="back"><Obj RefId="5"/></Obj></MS></Obj>'
        view = parser.parse(xml)
        expect(view[:members]['back'][:members]['Obj']).to eq(kind: 'cycle', ref_id: 5)
      end

      it 'renders an unresolved reference distinctly from a cycle' do
        xml = '<Obj RefId="0"><MS><Obj N="dangling"><Obj RefId="99"/></Obj></MS></Obj>'
        view = parser.parse(xml)
        expect(view[:members]['dangling'][:members]['Obj']).to eq(
          kind: 'unresolved_reference', ref_id: 99
        )
      end

      it 'does not carry reference scope across messages' do
        parser.parse('<Obj RefId="0"><MS><S N="k">first</S></MS></Obj>')
        second = parser.parse('<Obj RefId="5"><MS><Obj N="dangling"><Obj RefId="0"/></Obj></MS></Obj>')
        expect(second[:members]['dangling'][:members]['Obj']).to eq(
          kind: 'unresolved_reference', ref_id: 0
        )
      end
    end

    context 'bounds' do
      it 'stops expanding once the depth limit is reached' do
        xml = '<Obj>' + (1..8).map { '<MS><Obj N="n">' }.join +
              '<S>x</S>' + ('</Obj></MS>' * 8) + '</Obj>'
        view = described_class.new(max_depth: 3).parse(xml)
        deep = view[:members]['n'][:members]['n'][:members]['n']
        expect(deep).to eq(kind: 'truncated', reason: 'depth_limit', depth: 3, max_depth: 3)
      end

      it 'stops expanding once the node budget is reached' do
        xml = '<Obj><LST>' + (1..40).map { '<I32>1</I32>' }.join + '</LST></Obj>'
        view = described_class.new(max_nodes: 5).parse(xml)
        expect(view[:elements]).to include(kind: 'truncated', reason: 'node_limit', max_nodes: 5)
      end
    end

    context 'malformed input' do
      it 'raises a parse error when the payload is not valid XML' do
        expect { parser.parse('<Obj><MS>') }.to raise_error(WinRM::PSRP::ClixmlParseError)
      end

      it 'tolerates a leading byte order mark' do
        view = parser.parse("\xEF\xBB\xBF<obj><S>data</S></obj>")
        expect(view[:members]['S'][:value]).to eq('data')
      end
    end
  end
end
