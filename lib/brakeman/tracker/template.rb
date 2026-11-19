require 'set'
require 'brakeman/tracker/collection'
require 'brakeman/template_context'

module Brakeman
  class Template < Brakeman::Collection
    attr_accessor :type
    attr_reader :output_contexts, :output_flags
    attr_reader :render_path
    attr_writer :src

    def initialize name, called_from, file_name, tracker
      super name, nil, file_name, nil, tracker
      @render_path = called_from
      @outputs = []
      @output_contexts = {}
      @output_flags = {}
    end

    # Records the contexts seen for a line of this template.
    def add_output_context line, context
      (@output_contexts[line] ||= Set.new) << context
    end

    def add_output_flags line, flags
      (@output_flags[line] ||= Set.new).merge flags
    end

    def output_flags_for line
      @output_flags[line] || Set.new
    end

    def output_context_for line
      contexts = @output_contexts[line]
      return TemplateContext::UNKNOWN if contexts.nil? or contexts.empty?
      return contexts.first if contexts.length == 1

      TemplateContext::UNKNOWN
    end

    # Record contexts and conversion flags found by the template context
    # tracker, then attach the per-line result to each output expression.
    def annotate_output_contexts contexts, flags = {}
      contexts.each do |line, line_contexts|
        line_contexts.each { |context| add_output_context line, context }
      end

      flags.each do |line, line_flags|
        add_output_flags line, line_flags
      end

      each_output do |output|
        output.output_context = output_context_for(output.line)
        output.output_flags = output_flags_for(output.line)
      end
    end

    def add_output exp
      @outputs << exp
    end

    def each_output
      @outputs.each do |o|
        yield o
      end
    end

    def rendered_from_controller?
      if @render_path
        @render_path.rendered_from_controller?
      else
        false
      end
    end
  end
end
