# The selected advisory, report and configuration specs use versioned fixtures.
# The shared test helper normally clones a second project even for these specs.
require_relative "../spec/spec_helper"

module Fixtures::Database
  def self.clone
    FileUtils.mkdir_p(PATH)
  end

  def self.reset!(*)
    # Database history is irrelevant to this focused set of specs.
  end
end
