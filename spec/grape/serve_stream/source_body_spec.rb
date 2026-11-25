# frozen_string_literal: true

describe Grape::ServeStream::SourceBody do
  describe '#each' do
    it 'streams the source in chunks' do
      source = StringIO.new('a' * 40_000)
      chunks = []
      described_class.new(source).each { |chunk| chunks << chunk }

      expect(chunks.join).to eq('a' * 40_000)
      expect(chunks).to all(have_attributes(length: be <= 16_384))
    end

    it 'does not open the source until the body is read' do
      opened = Class.new do
        def initialize(marker)
          @marker = marker
        end

        def read(*)
          @marker << :read
          nil
        end

        def close
          @marker << :closed
        end
      end

      marker = []
      factory = -> { opened.new(marker) }
      body = described_class.new(factory)

      expect(marker).to be_empty
      body.each { |_| }
      expect(marker).to eq(%i[read closed])
    end

    it 'closes the source once the body has been read fully' do
      source = StringIO.new('the whole report')
      body = described_class.new(source)
      body.each { |_| }

      expect(source).to be_closed
      expect(body).to be_closed
    end

    it 'closes the source when reading stops after the first chunk' do
      source = StringIO.new('a' * 40_000)
      body = described_class.new(source)
      sent = 0
      body.each do |chunk|
        sent += chunk.bytesize
        break
      end

      expect(sent).to eq(16_384)
      expect(source).to be_closed
      expect(body).to be_closed
    end

    it 'closes the source when the reader raises' do
      source = StringIO.new('a' * 40_000)
      body = described_class.new(source)

      expect do
        body.each { raise 'client gone' }
      end.to raise_error('client gone')

      expect(source).to be_closed
      expect(body).to be_closed
    end

    it 'closes a source that was never read' do
      source = StringIO.new('unread')
      body = described_class.new(source)
      body.close

      expect(source).to be_closed
      expect(body).to be_closed
    end

    it 'never opens a lazy factory when closed before being read' do
      opened = false
      body = described_class.new(-> { StringIO.new('unread').tap { opened = true } })
      body.close

      expect(opened).to be(false)
      expect(body).to be_closed
    end

    it 'is idempotent when closed more than once' do
      source = StringIO.new('once')
      closes = 0
      source.define_singleton_method(:close) do
        closes += 1
        super()
      end

      body = described_class.new(source)
      body.close
      body.close

      expect(closes).to eq(1)
      expect(body).to be_closed
    end

    it 'rejects a source that cannot be read' do
      expect { described_class.new(:not_a_source) }.to raise_error(ArgumentError, /#read and #close/)
    end
  end
end
