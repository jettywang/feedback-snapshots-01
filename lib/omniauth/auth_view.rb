require 'securerandom'

module OmniAuth
  # A detached, allow-listed presentation of an AuthHash for one callback.
  class AuthView # rubocop:disable Metrics/ClassLength
    CORRELATION_KEY = 'correlation_id'.freeze
    WILDCARD = '**'.freeze
    MISSING = Object.new
    private_constant :MISSING

    # One source path copied to an output path.
    class Rule
      def initialize(source_path, target_path)
        @source_path = Array(source_path)
        @target_path = Array(target_path)
      end

      def apply(source, output)
        value = read(source)
        return if MISSING.equal?(value)

        write(output, @target_path, AuthView.deep_dup(value))
      end

      private

      def read(source)
        current = source
        @source_path.each do |key|
          return MISSING unless current.is_a?(Hash) && current.key?(key)

          current = current[key]
        end
        current
      end

      def write(output, path, value)
        parent = output
        path[0...-1].each do |key|
          unless parent[key].is_a?(Hash)
            parent[key] = OmniAuth::AuthHash.new
          end
          parent = parent[key]
        end
        parent[path.last] = value
      end
    end

    # Named auth-view policies configured by the application.
    class Registry
      def initialize(correlation_key: CORRELATION_KEY)
        @correlation_key = correlation_key
        @views = {}
      end

      def register(name, policy = nil, fields: nil, correlation_key: @correlation_key)
        @views[name.to_sym] = policy || AuthView.new(
          :fields => fields || [],
          :correlation_key => correlation_key
        )
      end
      alias add register
      alias []= register

      def [](name)
        @views.fetch(name.to_sym)
      end

      def key?(name)
        @views.key?(name.to_sym)
      end

      def names
        @views.keys
      end

      def clear
        @views.clear
        self
      end

      def project(name, auth, correlation_id: nil)
        self[name].project(auth, :correlation_id => correlation_id)
      end

      def project_all(auth, correlation_id: nil)
        names.each_with_object(OmniAuth::AuthHash.new) do |name, views|
          views[name.to_s] = project(name, auth, :correlation_id => correlation_id)
        end
      end
    end

    def self.project(auth, **options)
      correlation_id = options.delete(:correlation_id)
      new(**options).project(auth, :correlation_id => correlation_id)
    end

    def self.deep_dup(value)
      case value
      when Hash
        value.each_with_object({}) do |(key, item), copy|
          copy[key] = deep_dup(item)
        end
      when Array
        value.collect { |item| deep_dup(item) }
      when String
        value.dup
      else
        duplicate(value)
      end
    end

    def self.duplicate(value)
      value.dup
    rescue TypeError
      value
    end
    private_class_method :duplicate

    attr_reader :correlation_key, :rules

    def initialize(fields: nil, only: nil, correlation_key: CORRELATION_KEY)
      @correlation_key = correlation_key.to_s
      @rules = []
      @allow_all = false
      Array(fields || only).each { |field| add(field) }
    end

    def add(field, prefix = [])
      case field
      when :all, WILDCARD
        @allow_all = true
      when Hash
        add_hash(field, prefix)
      when Array
        field.each { |item| add(item, prefix) }
      else
        path = prefix + field.to_s.split('.')
        @rules << Rule.new(path, path)
      end
      self
    end

    def map(source_path, target_path)
      @rules << Rule.new(source_path.to_s.split('.'), target_path.to_s.split('.'))
      self
    end
    alias rename map

    def project(auth, correlation_id: nil)
      source = source_hash(auth)
      output = OmniAuth::AuthHash.new
      output.merge!(self.class.deep_dup(source)) if allow_all?
      rules.each { |rule| rule.apply(source, output) }
      preserve_strict_info_subset(output)
      output[correlation_key] = correlation_id || SecureRandom.uuid
      output
    end
    alias call project

    private

    def allow_all?
      @allow_all
    end

    def source_hash(auth)
      return {} if auth.nil?

      hash = auth.respond_to?(:to_hash) ? auth.to_hash : auth.to_h
      OmniAuth::AuthHash.new(hash).to_hash
    end

    def preserve_strict_info_subset(output)
      info = output['info']
      return unless info.is_a?(OmniAuth::AuthHash::InfoHash)

      output['info'] = info.slice(*info.keys)
    end

    def add_hash(hash, prefix)
      hash.each do |key, value|
        source_path = prefix + key.to_s.split('.')
        case value
        when true
          @rules << Rule.new(source_path, source_path)
        when String, Symbol
          @rules << Rule.new(source_path, value.to_s.split('.'))
        when Hash, Array
          add(value, source_path)
        else
          raise ArgumentError, "unsupported auth view field rule: #{value.inspect}"
        end
      end
    end
  end
end
