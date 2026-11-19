require 'stringio'
require 'winrm'

describe WinRM::LogRedactor do
  let(:secret) { 'FAKE-SECRET-4f1d2c-do-not-log' }
  let(:password) { 'FAKE-PASSWORD-9b7e-do-not-log' }
  let(:token) { 'FAKE-TOKEN-77aa-do-not-log' }

  def soap(body, extra_namespaces = '')
    <<~XML
      <?xml version="1.0" encoding="UTF-8"?>
      <env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope"
                    xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"
                    xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
                    #{extra_namespaces}>
        <env:Header>
          <a:MessageID>uuid:11111111-2222-3333-4444-555555555555</a:MessageID>
          <a:Action>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command</a:Action>
          <a:To>http://user:#{password}@localhost:5985/wsman?token=#{token}</a:To>
        </env:Header>
        <env:Body>
          #{body}
        </env:Body>
      </env:Envelope>
    XML
  end

  let(:command_document) do
    soap(
      '<rsp:CommandLine CommandId="AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE">' \
      "<rsp:Command>\"echo #{secret}\"</rsp:Command>" \
      "<rsp:Arguments>--password=#{password}</rsp:Arguments>" \
      '</rsp:CommandLine>'
    )
  end

  let(:creation_document) do
    soap(
      '<creationXml xmlns="http://schemas.microsoft.com/powershell">' \
      "#{secret}</creationXml>"
    )
  end

  describe '.describe' do
    it 'keeps correlation ids, operation, and lengths in the summary' do
      summary = described_class.describe(command_document, operation: 'request')[:summary]

      expect(summary).to include('request')
      expect(summary).to include('op="CommandLine"')
      expect(summary).to include('message_id="uuid:11111111-2222-3333-4444-555555555555"')
      expect(summary).to include('command_id="AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"')
      expect(summary).to include("bytes=#{command_document.bytesize}")
      expect(summary).to match(/redactions=[1-9]/)
    end

    it 'replaces shell command and argument payloads with stable digests' do
      first = described_class.describe(command_document)[:redacted]
      second = described_class.describe(command_document)[:redacted]

      expect(first).to include('REDACTED Command')
      expect(first).to include('REDACTED Arguments')
      expect(first).not_to include(secret)
      expect(first).not_to include(password)
      expect(first).to eq(second)
    end

    it 'redacts credentials embedded in endpoint URLs' do
      redacted = described_class.describe(command_document)[:redacted]

      expect(redacted).to include('http://[REDACTED]@localhost:5985/wsman?[REDACTED]')
      expect(redacted).not_to include(token)
    end

    it 'redacts encoded PSRP creation payloads' do
      redacted = described_class.describe(creation_document)[:redacted]

      expect(redacted).to include('REDACTED creationXml')
      expect(redacted).not_to include(secret)
    end

    it 'does not modify the original message' do
      original = command_document.dup
      described_class.describe(command_document)

      expect(command_document).to eq(original)
    end

    it 'summarizes malformed XML by location without echoing its content' do
      malformed = "<env:Envelope xmlns:env='u'><a>#{secret}</a"
      description = described_class.describe(malformed, operation: 'response')

      expect(description[:redacted]).to be_nil
      expect(description[:summary]).to include('xml=unparseable')
      expect(description[:summary]).to include('line=1')
      expect(description[:summary]).to match(/position=\d+/)
      expect(description[:summary]).not_to include(secret)
      expect(description[:summary]).not_to include(malformed)
    end

    it 'does not echo multi-line secret content from malformed XML' do
      malformed = "<a>\n#{secret}\n#{password}\n</b>"
      summary = described_class.describe(malformed)[:summary]

      expect(summary).not_to include(secret)
      expect(summary).not_to include(password)
      expect(summary).not_to match(/\n/)
    end

    it 'treats binary payloads as opaque content' do
      binary = "\x00\xFF\x10#{secret}\x00".b
      summary = described_class.describe(binary)[:summary]

      expect(summary).to include("bytes=#{binary.bytesize}")
      expect(summary).to include('xml=unparseable')
      expect(summary).not_to include(secret)
    end

    it 'redacts sensitive environment variables and leaves benign ones readable' do
      shell = soap(
        '<rsp:Shell><rsp:Environment>' \
        "<rsp:Variable Name=\"DB_PASSWORD\">#{password}</rsp:Variable>" \
        '<rsp:Variable Name="PUBLIC">visible</rsp:Variable>' \
        '</rsp:Environment></rsp:Shell>'
      )
      redacted = described_class.describe(shell)[:redacted]

      expect(redacted).to include('REDACTED Variable')
      expect(redacted).to include('visible')
      expect(redacted).not_to include(password)
    end

    it 'omits comments that could carry copied secrets' do
      comment = soap("<rsp:CommandLine CommandId=\"C\"><!--#{secret}--></rsp:CommandLine>")
      redacted = described_class.describe(comment)[:redacted]

      expect(redacted).to include('OMITTED comment')
      expect(redacted).not_to include(secret)
    end
  end


  describe 'hardening against alternate shapes' do
    it 'redacts shell payload names even under rewritten namespaces' do
      legacy = <<~XML
        <Envelope xmlns="urn:legacy" xmlns:sh="urn:shell">
          <Body>
            <sh:CommandLine CommandId="00000000-0000-0000-0000-000000000009">
              <sh:Command>echo #{secret}</sh:Command>
              <sh:Arguments>--password=#{password}</sh:Arguments>
            </sh:CommandLine>
          </Body>
        </Envelope>
      XML
      redacted = described_class.describe(legacy)[:redacted]

      expect(redacted).to include('REDACTED Command')
      expect(redacted).to include('REDACTED Arguments')
      expect(redacted).not_to include(secret)
      expect(redacted).not_to include(password)
    end

    it 'treats mixed-case and unprefixed names as sensitive by semantic name' do
      odd = "<Envelope><COMMAND>#{secret}</COMMAND><arguments>#{password}</arguments></Envelope>"
      redacted = described_class.describe(odd)[:redacted]

      expect(redacted).to include('REDACTED COMMAND')
      expect(redacted).to include('REDACTED arguments')
      expect(redacted).not_to include(secret)
      expect(redacted).not_to include(password)
    end

    it 'redacts namespaced sensitive attributes and drops all query parameters' do
      doc = <<~XML
        <env:Envelope xmlns:env="u" xmlns:x="urn:x">
          <env:Body>
            <x:Thing x:password="#{password}" note="http://user:#{password}@h:1/p?unknown=#{token}"/>
          </env:Body>
        </env:Envelope>
      XML
      redacted = described_class.describe(doc)[:redacted]

      expect(redacted).to include('REDACTED password attribute')
      expect(redacted).to include('http://[REDACTED]@h:1/[REDACTED path]?[REDACTED]')
      expect(redacted).not_to include(password)
      expect(redacted).not_to include(token)
    end

    it 'omits free text that visibly embeds credential pairs' do
      doc = "<a><description>password=#{password} token=#{token}</description></a>"
      redacted = described_class.describe(doc)[:redacted]

      expect(redacted).to include('OMITTED text')
      expect(redacted).not_to include(password)
      expect(redacted).not_to include(token)
    end

    it 'does not trust content smuggled into correlation fields' do
      doc = <<~XML
        <env:Envelope xmlns:env="u" xmlns:a="urn:a">
          <env:Header>
            <a:MessageID>#{secret}</a:MessageID>
            <a:Action>http://example.com/#{secret}</a:Action>
          </env:Header>
          <env:Body><a:Thing CommandId="#{secret}"/></env:Body>
        </env:Envelope>
      XML
      summary = described_class.describe(doc)[:summary]

      expect(summary).to include('REDACTED identifier')
      expect(summary).to include('REDACTED')
      expect(summary).not_to include(secret)
    end
  end

  describe '.error_summary' do
    it 'retains REXML line and position for failures without the unparsed tail' do
      error = begin
        REXML::Document.new('<a><b>')
      rescue REXML::ParseException => e
        e
      end
      summary = described_class.error_summary(error)

      expect(summary).to include('class=REXML::ParseException')
      expect(summary).to include('line=1')
      expect(summary).to match(/position=\d+/)
      expect(summary).not_to include('<a><b>')
    end

    it 'summarizes arbitrary exceptions without echoing message text' do
      error = StandardError.new("boom #{secret}\n#{password}")
      summary = described_class.error_summary(error)

      expect(summary).to include('class=StandardError')
      expect(summary).to match(/message_bytes=\d+/)
      expect(summary).to match(/message_sha256=sha256:\h+/)
      expect(summary).not_to include(secret)
      expect(summary).not_to include(password)
    end
  end

  describe '.endpoint' do
    it 'removes userinfo and query parameters' do
      endpoint = described_class.endpoint("https://user:#{password}@host:5986/wsman?token=#{token}")

      expect(endpoint).to eq('https://[REDACTED]@host:5986/wsman')
    end

    it 'does not leak unparseable endpoint text' do
      expect(described_class.endpoint("not a url #{secret}")).to eq('[endpoint redacted]')
    end
  end
end
