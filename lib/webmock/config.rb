# frozen_string_literal: true

module WebMock
  class Config
    include Singleton

    def initialize
      @show_stubbing_instructions = true
      @show_body_diff = true
      @show_redacted_structures = true
      @show_redacted_field_names = true
      @show_redacted_values = true
    end

    attr_accessor :allow_net_connect
    attr_accessor :allow_localhost
    attr_accessor :allow
    attr_accessor :net_http_connect_on_start
    attr_accessor :show_stubbing_instructions
    attr_accessor :query_values_notation
    attr_accessor :show_body_diff
    attr_accessor :show_redacted_structures
    attr_accessor :show_redacted_field_names
    attr_accessor :show_redacted_values
  end
end
