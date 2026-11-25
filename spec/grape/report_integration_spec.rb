# frozen_string_literal: true

describe 'Grape::Report over Rack' do
  # A synthetic report whose attachment source is only produced when Rack reads
  # the body, so the specs can observe it being opened and closed.
  let(:opened_sources) { [] }
  let(:attachment_bytes) { "REPORT-#{'x' * 40_000}-END" }

  let(:report) do
    bytes = attachment_bytes
    sources = opened_sources
    Grape::Report.new(
      'synthetic-report',
      source: -> { StringIO.new(bytes).tap { |source| sources << source } },
      summary: ->(format) { { format: format, headline: 'A synthetic report', lines: 3 } },
      media_types: { json: 'application/json', txt: 'text/plain' }
    )
  end

  let(:app) do
    served = report
    Class.new(Grape::API) do
      content_type :json, 'application/json'
      content_type :txt, 'text/plain'
      default_format :json

      params do
        optional :download, type: Grape::API::Boolean
      end
      get :report do
        serve_report served, download: params[:download] == true
      end
    end
  end

  before { app }

  describe 'the approved attachment, read fully' do
    before { get '/report', download: true }

    it 'streams every byte as an attachment' do
      expect(last_response.status).to eq(200)
      expect(last_response.body).to eq(attachment_bytes)
    end

    it 'publishes the negotiated type and a usable filename' do
      expect(last_response.headers['Content-Type']).to eq('application/json')
      expect(last_response.headers['Content-Disposition']).to eq(
        "attachment; filename=\"synthetic-report.json\"; filename*=UTF-8''synthetic-report.json"
      )
    end

    it 'closes the source once the body is sent' do
      expect(opened_sources.size).to eq(1)
      expect(opened_sources.first).to be_closed
    end
  end

  describe 'the inline summary' do
    before { get '/report' }

    it 'renders the summary the request is allowed' do
      expect(last_response.status).to eq(200)
      expect(last_response.headers['Content-Type']).to eq('application/json')
      expect(JSON.parse(last_response.body)).to eq(
        'format' => 'json', 'headline' => 'A synthetic report', 'lines' => 3
      )
    end

    it 'keeps the same filename convention inline and never opens the source' do
      expect(last_response.headers['Content-Disposition']).to start_with('inline')
      expect(last_response.headers['Content-Disposition']).to include('filename="synthetic-report.json"')
      expect(opened_sources).to be_empty
    end
  end

  describe 'a format the request cannot negotiate' do
    it 'answers 406 without offering a download' do
      get '/report', format: 'atom'

      expect(last_response.status).to eq(406)
      expect(last_response.headers['Content-Disposition']).to be_nil
      expect(opened_sources).to be_empty
    end
  end

  describe 'an attachment abandoned after the first chunk' do
    it 'closes the source and reports only the bytes sent' do
      status, headers, body = app.call(Rack::MockRequest.env_for('/report?download=true'))
      expect(status).to eq(200)
      expect(headers['Content-Type']).to eq('application/json')
      expect(headers['Content-Disposition']).to start_with('attachment')

      sent = +''
      body.each do |chunk|
        sent << chunk
        break
      end

      expect(sent.bytesize).to eq(Grape::ServeStream::CHUNK_SIZE)
      expect(sent).to eq(attachment_bytes.byteslice(0, Grape::ServeStream::CHUNK_SIZE))
      expect(opened_sources.size).to eq(1)
      expect(opened_sources.first).to be_closed

      body.close
      expect(opened_sources.size).to eq(1)
      expect(opened_sources.first).to be_closed
    end
  end
end
