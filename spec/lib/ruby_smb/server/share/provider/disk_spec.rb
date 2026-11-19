RSpec.describe RubySMB::Server::Share::Provider::Disk do
  let(:name) { 'share' }
  let(:path) { Dir.getwd }
  subject(:share_provider) { described_class.new(name, path) }

  it { is_expected.to respond_to :name }
  it { is_expected.to respond_to :path }
  it { is_expected.to respond_to :type }

  describe '#TYPE' do
    it 'is TYPE_DISK' do
      expect(described_class::TYPE).to eq RubySMB::Server::Share::TYPE_DISK
    end
  end

  describe '#initialize' do
    it 'sets the name' do
      expect(share_provider.name).to eq name
    end

    it 'sets the path' do
      expect(share_provider.path).to be_a Pathname
      expect(share_provider.path).to eq Pathname.new(path)
    end

    it 'sets the type correctly' do
      expect(share_provider.type).to eq RubySMB::Server::Share::TYPE_DISK
    end

    it 'raises an ArgumentError for an invalid path' do
      # __FILE__ is not a directory so it's invalid
      expect { described_class.new(name, __FILE__) }.to raise_error(ArgumentError)
    end
  end
end

RSpec.describe RubySMB::Server::Share::Provider::Disk::Processor do
  let(:session) { RubySMB::Server::Session.new(rand(0xffffffff)) }
  let(:server_client) { double('ServerClient') }
  let(:share_provider) { RubySMB::Server::Share::Provider::Disk.new('share', Dir.getwd) }
  subject(:share_processor) { described_class.new(share_provider, server_client, session) }

  it { is_expected.to respond_to :provider }

  describe '#owned_by?' do
    it 'is true for the connection and session that created it' do
      expect(share_processor.owned_by?(server_client, session)).to be true
    end

    it 'is false for another connection' do
      expect(share_processor.owned_by?(double('OtherServerClient'), session)).to be false
    end

    it 'is false for another session' do
      expect(share_processor.owned_by?(server_client, RubySMB::Server::Session.new(rand(0xffffffff)))).to be false
    end
  end

  describe '#disconnect!' do
    it 'closes every open handle and clears the table' do
      handle = RubySMB::Server::Share::Provider::Disk::Processor::Handle.new('a', Pathname.new(Dir.getwd), false, StringIO.new('a'))
      handles = share_processor.instance_variable_get(:@handles)
      handles[1] = handle

      share_processor.disconnect!

      expect(handle.file).to be_closed
      expect(handles).to be_empty
    end

    it 'keeps clearing handles when one close raises' do
      good = StringIO.new('good')
      bad = StringIO.new('bad')
      allow(bad).to receive(:close).and_raise(IOError)
      handles = share_processor.instance_variable_get(:@handles)
      handles[1] = RubySMB::Server::Share::Provider::Disk::Processor::Handle.new('bad', Pathname.new(Dir.getwd), false, bad)
      handles[2] = RubySMB::Server::Share::Provider::Disk::Processor::Handle.new('good', Pathname.new(Dir.getwd), false, good)

      share_processor.disconnect!

      expect(good).to be_closed
      expect(handles).to be_empty
    end
  end

  describe '#maximal_access' do
    # no path specified should be the root of the share
    context 'with no path specified' do
      let(:maximal_access) { share_processor.maximal_access }
      it 'is a FileAccessMask' do
        expect(maximal_access).to be_a RubySMB::SMB2::BitField::FileAccessMask
      end

      it 'marks the data as readable' do
        expect(maximal_access.read_data).to eq 1
      end

      it 'marks the data attributes as readable' do
        expect(maximal_access.read_attr).to eq 1
      end
    end
  end
end
