# frozen_string_literal: true

# A data source for the JSON Lines disclosure specs: it saves the checkpoint of
# its own read as it goes and can be closed, so a spec can tell what the
# controlled side still knows after a response was truncated.
class JsonlDisclosureSource
  attr_reader :checkpoint, :closures

  def initialize(rows)
    @rows = rows
    @checkpoint = 0
    @closures = 0
  end

  def each
    @rows.each_with_index do |row, index|
      yield row
      @checkpoint = index + 1
    end
  end

  def close
    @closures += 1
  end
end
