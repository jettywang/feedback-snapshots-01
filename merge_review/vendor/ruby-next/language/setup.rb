# frozen_string_literal: true

module RubyNext
  module Language
    def self.setup_gem_load_path(**)
      # no-op: running on Ruby 4, no transpilation needed
    end
  end
end
