# frozen_string_literal: true

describe Grape::Report do
  let(:source) { StringIO.new('the rendered report bytes') }
  let(:summary) { { title: 'Quarterly report', totals: { revenue: 42 } } }

  let(:report) do
    described_class.new(
      'quarterly-report',
      source: -> { source },
      summary: ->(format) { summary.merge(format: format) },
      media_types: { json: 'application/json', txt: 'text/plain', binary: 'application/octet-stream' }
    )
  end

  describe '#attachment' do
    subject(:triplet) { report.attachment(:json, status: 200) }

    it 'streams the source without reading it up front' do
      expect(source).not_to be_closed
      status, headers, body = triplet

      expect(status).to eq(200)
      expect(body).to be_a(Grape::ServeStream::SourceBody)
      expect(source).not_to be_closed

      chunks = []
      body.each { |chunk| chunks << chunk }
      expect(chunks.join).to eq('the rendered report bytes')
      expect(source).to be_closed
    end

    it 'labels the response with the negotiated type and an attachment filename' do
      _status, headers, _body = triplet

      expect(headers[Rack::CONTENT_TYPE]).to eq('application/json')
      expect(headers['content-disposition']).to eq(
        "attachment; filename=\"quarterly-report.json\"; filename*=UTF-8''quarterly-report.json"
      )
    end

    it 'escapes a non-ASCII filename for the extended parameter' do
      unicode_report = described_class.new(
        '季度报告',
        source:,
        summary:,
        media_types: { json: 'application/json' }
      )
      _status, headers, _body = unicode_report.attachment(:json)

      disposition = headers['content-disposition']
      expect(disposition).to include("filename*=UTF-8''#{CGI.escape('季度报告.json')}")
      expect(disposition).to include('filename="____.json"')
    end

    it 'neutralizes quotes and control characters in the fallback filename' do
      malicious_report = described_class.new(
        "evil\".txt; name",
        source:,
        summary:,
        media_types: { json: 'application/json' }
      )
      _status, headers, _body = malicious_report.attachment(:json)

      expect(headers['content-disposition']).to include('filename="evil_.txt__name.json"')
    end

    it 'falls back to a given extension when none is known for the format' do
      custom_report = described_class.new(
        'quarterly-report',
        source:,
        summary:,
        media_types: { json: 'application/vnd.api+json' },
        extensions: { json: 'api.json' }
      )
      _status, headers, _body = custom_report.attachment(:json)

      expect(headers['content-disposition']).to include('filename="quarterly-report.api.json"')
    end
  end

  describe '#summary_response' do
    subject(:triplet) { report.summary_response(:json) }

    it 'renders the summary for the negotiated format' do
      status, headers, body = triplet

      expect(status).to eq(200)
      expect(headers[Rack::CONTENT_TYPE]).to eq('application/json')
      expect(body).to eq([summary.merge(format: :json)])
      expect(headers['content-disposition']).to include('inline')
    end

    it 'keeps the attachment branch downloadable when download is not allowed' do
      status, headers, body = report.summary_response(:txt)

      expect(status).to eq(200)
      expect(headers[Rack::CONTENT_TYPE]).to eq('text/plain')
      expect(body).to eq([summary.merge(format: :txt)])
      expect(headers['content-disposition']).to include('filename="quarterly-report.txt"')
    end
  end

  describe '#answer' do
    it 'answers the attachment for an allowed download' do
      status, _headers, body = report.answer(:json, download: true)

      expect(status).to eq(200)
      expect(body).to be_a(Grape::ServeStream::SourceBody)
    end

    it 'answers the inline summary for a request without a download' do
      _status, _headers, body = report.answer(:json, download: false)

      expect(body).to eq([summary.merge(format: :json)])
    end
  end
end
