# frozen_string_literal: true

class InMemoryCache
  attr_accessor :store
  attr_reader :reads, :writes

  def initialize
    self.store = {}
    @reads = []
    @writes = []
  end

  def read(key)
    reads << key
    deserialize(store[key]) if store.key?(key)
  end

  def write(key, val, _options)
    writes << key
    store[key] = serialize(val)
  end

  def serialize(val)
    Marshal.dump(val)
  end

  def deserialize(val)
    Marshal.load(val)
  end
end
