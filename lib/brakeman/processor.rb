#Load all files in processors/
Dir.glob("#{File.expand_path(File.dirname(__FILE__))}/processors/*.rb").each { |f| require f.match(/brakeman\/processors.*/)[0] }
require 'brakeman/tracker'
require 'set'
require 'pathname'

module Brakeman
  #Makes calls to the appropriate processor.
  #
  #The ControllerProcessor, TemplateProcessor, and ModelProcessor will
  #update the Tracker with information about what is parsed.
  class Processor
    include Util

    def initialize(app_tree, options)
      @tracker = Tracker.new(app_tree, self, options)
    end

    def tracked_events
      @tracker
    end

    #Process configuration file source
    def process_config src, file_name
      ConfigProcessor.new(@tracker).process_config src, file_name
    end

    #Process Gemfile
    def process_gems gem_files
      GemProcessor.new(@tracker).process_gems gem_files
    end

    #Process route file source
    def process_routes src
      RoutesProcessor.new(@tracker).process_routes src
    end

    #Process controller source. +file_name+ is used for reporting
    def process_controller src, file_name
      if contains_class? src
        ControllerProcessor.new(@tracker).process_controller src, file_name
      else
        LibraryProcessor.new(@tracker).process_library src, file_name
      end
    end

    #Process variable aliasing in controller source and save it in the
    #tracker.
    def process_controller_alias name, src, only_method = nil, file = nil
      ControllerAliasProcessor.new(@tracker, only_method).process_controller name, src, file
    end

    #Process a model source
    def process_model src, file_name
      result = ModelProcessor.new(@tracker).process_model src, file_name
      AliasProcessor.new(@tracker, file_name).process result if result
    end

    #Process either an ERB or HAML template
    def process_template name, src, type, called_from = nil, file_name = nil
      processor = case type
                  when :erb
                    ErbTemplateProcessor.new(@tracker, name, called_from, file_name)
                  when :haml
                    HamlTemplateProcessor.new(@tracker, name, called_from, file_name)
                  when :haml6
                    Haml6TemplateProcessor.new(@tracker, name, called_from, file_name)
                  when :erubi
                    ErubiTemplateProcessor.new(@tracker, name, called_from, file_name)
                  when :slim
                    SlimTemplateProcessor.new(@tracker, name, called_from, file_name)
                  else
                    abort "Unknown template type: #{type} (#{name})"
                  end

      result = processor.process src
      template = processor.current_template

      # Determine where each dynamic value is emitted based on the compiled
      # template text. This must happen before the output list is used.
      #
      # Rendered versions of a template reuse an alias-processed AST which no
      # longer contains the literal text between outputs. Their output lines
      # are the same as the pristine template, so reuse its contexts.
      base_template = called_from ? @tracker.templates[name.to_sym] : nil

      if base_template and base_template != template
        base_template.output_contexts.each do |line, contexts|
          contexts.each { |context| template.add_output_context line, context }
        end
        template.annotate_output_contexts({}, base_template.output_flags)
      else
        tracker = Brakeman::TemplateContextTracker.new(src)
        contexts = tracker.scan
        template.annotate_output_contexts contexts, tracker.flags
      end

      #Each template which is rendered is stored separately
      #with a new name.
      if called_from
        name = ("#{name}.#{called_from}").to_sym
      end

      @tracker.templates[name].src = result
      @tracker.templates[name].type = type
    end

    #Process any calls to render() within a template
    def process_template_alias template
      TemplateAliasProcessor.new(@tracker, template).process_safely template.src
    end

    #Process source for initializing files
    def process_initializer file_name, src
      res = BaseProcessor.new(@tracker).process_file src, file_name
      res = AliasProcessor.new(@tracker).process_safely res, nil, file_name
      @tracker.initializers[file_name] = res
    end

    #Process source for a library file
    def process_lib src, file_name
      LibraryProcessor.new(@tracker).process_library src, file_name
    end
  end
end
