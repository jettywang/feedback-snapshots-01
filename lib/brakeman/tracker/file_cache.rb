module Brakeman
  class FileCache
    def initialize(file_list = nil, errors = nil)
      @file_list = file_list || {
        controller: {},
        initializer: {},
        lib: {},
        model: {},
        template: {},
      }

      # Parse errors stored by file path, so they can be
      # replayed when a file is not re-parsed (e.g. rescanning)
      # and invalidated when the file changes.
      @errors = errors || {}
    end

    def controllers
      @file_list[:controller]
    end

    def initializers
      @file_list[:initializer]
    end

    def libs
      @file_list[:lib]
    end

    def models
      @file_list[:model]
    end

    def templates
      @file_list[:template]
    end

    def add_file(astfile, type)
      raise "Unknown type: #{type}" unless valid_type? type
      @file_list[type][astfile.path] = astfile
    end

    def valid_type?(type)
      @file_list.key? type
    end

    def cached? path
      @file_list.any? do |name, list|
        list[path]
      end
    end

    # Record a parse error (a Tracker error hash) for a file
    def add_error path, error
      (@errors[path] ||= []) << error
    end

    # All cached parse errors
    def errors
      @errors.values.flatten(1)
    end

    def delete path
      @file_list.each do |name, list|
        list.delete path
      end

      @errors.delete path
    end

    def diff other
      @file_list.each do |name, list|
        other_list = other.send(:"#{name}s")

        if list == other_list
          next
        else
          puts "-- #{name} --"
          puts "Old: #{other_list.keys - list.keys}"
          puts "New: #{list.keys - other_list.keys}"
        end
      end
    end

    def dup
      copy_file_list = @file_list.map do |name, list|
        copy_list = list.map do |path, astfile|
          copy_astfile = astfile.dup
          copy_astfile.ast = copy_astfile.ast.deep_clone

          [path, copy_astfile]
        end.to_h

        [name, copy_list]
      end.to_h

      copy_errors = @errors.map do |path, error_list|
        copy_error_list = error_list.map do |error|
          error.merge(backtrace: error[:backtrace].dup)
        end

        [path, copy_error_list]
      end.to_h

      FileCache.new(copy_file_list, copy_errors)
    end
  end
end
