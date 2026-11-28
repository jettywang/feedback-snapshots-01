require 'digest'
require 'uri'

module Bundler
  module Audit
    #
    # Builds stable correlation IDs for audit findings.
    #
    # A correlation ID is a deterministic digest over the evidence that makes
    # a finding what it is. It deliberately ignores incidental details such
    # as the order in which lockfile entries were parsed, so reordering
    # equivalent lockfile entries does not mint a new ID. It does include the
    # advisory, the locked gem instance (name, version, platform) and the
    # gem source, so changing any of those produces a new ID.
    #
    # Source findings and dependency findings use separate prefixes, making
    # them easy to tell apart in any output format.
    #
    module Correlation

      # Version of the correlation ID preimage format.
      FORMAT_VERSION = 1

      # Prefix for unpatched-gem (dependency) findings.
      DEPENDENCY_PREFIX = 'BA-DEP'

      # Prefix for insecure-source findings.
      SOURCE_PREFIX = 'BA-SRC'

      # Number of hex characters retained from the digest.
      DIGEST_LENGTH = 16

      # Separator placed between fields in the digest preimage.
      FIELD_SEPARATOR = "\x1f"

      #
      # Builds a correlation ID for an unpatched gem finding.
      #
      # @param [String] advisory_id
      #   The stable identifier of the advisory (its database ID).
      #
      # @param [Gem::Specification, Bundler::LazySpecification] gem
      #   The locked gem instance.
      #
      # @return [String]
      #
      def self.dependency(advisory_id,gem)
        digest(DEPENDENCY_PREFIX,[
          ['advisory', advisory_id],
          ['gem',      gem.name],
          ['version',  gem.version],
          ['platform', platform_of(gem)],
          ['source',   source_identity(gem.source)]
        ])
      end

      #
      # Builds a correlation ID for an insecure source finding.
      #
      # @param [URI, String] uri
      #   The insecure source URI.
      #
      # @return [String]
      #
      def self.source(uri)
        digest(SOURCE_PREFIX,[
          ['source', canonical_uri(uri)]
        ])
      end

      #
      # Computes the digest for the given prefix and fields.
      #
      # Each value is length-prefixed so that concatenating fields cannot
      # produce the same preimage for different evidence.
      #
      # @param [String] prefix
      # @param [Array<Array(String, Object)>] fields
      #
      # @return [String]
      #
      def self.digest(prefix,fields)
        parts = [FORMAT_VERSION.to_s,prefix]

        fields.each do |name,value|
          value = value.to_s
          parts << "#{name}:#{value.bytesize}:#{value}"
        end

        hex = ::Digest::SHA256.hexdigest(parts.join(FIELD_SEPARATOR))[0,DIGEST_LENGTH]

        "#{prefix}-#{hex}"
      end

      #
      # Returns the platform component of a locked gem instance.
      #
      # @param [Gem::Specification, Bundler::LazySpecification] gem
      #
      # @return [String]
      #
      def self.platform_of(gem)
        if gem.respond_to?(:platform) && gem.platform
          gem.platform.to_s
        else
          'ruby'
        end
      end

      #
      # Describes the source a locked gem instance came from.
      #
      # @param [Object] source
      #
      # @return [String]
      #
      def self.source_identity(source)
        return 'unspecified' if source.nil?

        klass = source.class.name.to_s

        case klass
        when 'Bundler::Source::Git'
          "git:#{canonical_uri(source.uri)}@#{git_revision(source)}"
        when 'Bundler::Source::Rubygems'
          "rubygems:#{canonical_remotes(source.remotes)}"
        when 'Bundler::Source::Path', 'Bundler::Source::Gemspec'
          "path:#{canonical_path(source)}"
        else
          generic_source_identity(source)
        end
      end

      #
      # Returns the locked revision (or ref) of a git source without
      # performing any git operations.
      #
      # @param [Bundler::Source::Git] source
      #
      # @return [String]
      #
      def self.git_revision(source)
        options = (source.respond_to?(:options) && source.options) || {}

        options['revision'] || options[:revision] ||
          options['ref']      || options[:ref]      ||
          'unlocked'
      end

      #
      # @param [Object] source
      #
      # @return [String]
      #
      def self.canonical_path(source)
        path = if source.respond_to?(:path) && source.path
                 source.path
               elsif source.respond_to?(:options) && source.options
                 source.options['path'] || source.options[:path]
               end

        path ? path.to_s : ''
      end

      #
      # @param [Array] remotes
      #
      # @return [String]
      #
      def self.canonical_remotes(remotes)
        Array(remotes).map { |remote| canonical_uri(remote) }.sort.join(',')
      end

      #
      # @param [Object] source
      #
      # @return [String]
      #
      def self.generic_source_identity(source)
        klass = source.class.name.to_s
        klass = 'unknown' if klass.empty?

        if source.respond_to?(:uri) && (uri = source.uri)
          "#{klass}:#{canonical_uri(uri)}"
        elsif source.respond_to?(:remotes) && !Array(source.remotes).empty?
          "#{klass}:rubygems:#{canonical_remotes(source.remotes)}"
        elsif klass == 'Gem::Source::Installed'
          'installed'
        elsif source.respond_to?(:spec) && source.spec &&
              source.spec.respond_to?(:path)
          "#{klass}:file:#{source.spec.path}"
        else
          klass
        end
      end

      #
      # Canonicalizes a URI for use in evidence.
      #
      # Scheme and host are lower-cased, credentials are stripped, default
      # ports are dropped and empty paths are represented consistently.
      #
      # @param [URI, String] value
      #
      # @return [String]
      #
      def self.canonical_uri(value)
        string = value.to_s.strip

        begin
          uri = URI.parse(string)
        rescue URI::InvalidURIError
          return string
        end

        return string unless uri.host

        scheme = uri.scheme ? uri.scheme.downcase : ''
        host   = uri.host.downcase

        unless uri.port.nil? || uri.port == default_port(uri)
          host = "#{host}:#{uri.port}"
        end

        path  = uri.path || ''
        query = uri.query ? "?#{uri.query}" : ''

        "#{scheme}://#{host}#{path}#{query}"
      end

      #
      # @param [URI] uri
      #
      # @return [Integer, nil]
      #
      def self.default_port(uri)
        uri.default_port
      rescue StandardError
        nil
      end

    end
  end
end
