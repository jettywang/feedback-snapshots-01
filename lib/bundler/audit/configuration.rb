#
# Copyright (c) 2013-2026 Hal Brodigan (postmodern.mod3 at gmail.com)
#
# bundler-audit is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# bundler-audit is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with bundler-audit.  If not, see <https://www.gnu.org/licenses/>.
#

require 'bundler/audit/approval'

require 'yaml'
require 'set'

module Bundler
  module Audit
    #
    # Class for storing and validating configuration for running the auditor.
    #
    # @since 0.8.0
    #
    class Configuration
      class InvalidConfigurationError < StandardError
      end

      class FileNotFound < StandardError
      end

      #
      # A constructor method for loading configuration from a YAML file.
      #
      # @param [String] file_path
      #   Path to the YAML file holding the configuration.
      #
      # @raise [FileNotFound]
      #   Will raise a file not found error when the path to the
      #   configuration YAML file does not exist.
      #
      # @raise [InvalidConfigurationError]
      #   Will raise an invalid configuration error indicating what in the
      #   YAML file is invalid for the configuration.
      #
      # @return [Configuration]
      #   A Configuration object containing the config hash loaded from the
      #   file passed.
      #
      def self.load(file_path)
        raise(FileNotFound,"Configuration file '#{file_path}' does not exist") unless File.exist?(file_path)

        doc = YAML.parse(File.new(file_path))

        unless doc.kind_of?(YAML::Nodes::Document)
          raise(InvalidConfigurationError,"Configuration found in '#{file_path}' is not YAML")
        end

        unless doc.root.kind_of?(YAML::Nodes::Mapping)
          raise(InvalidConfigurationError,"Configuration found in '#{file_path}' is not a Hash")
        end

        config = {}

        doc.root.children.each_slice(2) do |key,value|
          case key.value
          when 'ignore'
            unless value.is_a?(YAML::Nodes::Sequence)
              raise(InvalidConfigurationError,"'ignore' key found in config file, but is not an Array")
            end

            config[:ignore] = value.children.map do |node|
              case node
              when YAML::Nodes::Scalar
                node.value
              when YAML::Nodes::Mapping
                entry = {}

                node.children.each_slice(2) do |entry_key,entry_value|
                  unless entry_value.is_a?(YAML::Nodes::Scalar)
                    raise(InvalidConfigurationError,"'ignore' entry in config file contains a non-String value")
                  end

                  entry[entry_key.value] = entry_value.value
                end

                unless entry['advisory']
                  raise(InvalidConfigurationError,"'ignore' entry in config file is missing the 'advisory' key")
                end

                entry
              else
                raise(InvalidConfigurationError,"'ignore' array in config file contains a non-String")
              end
            end
          end
        end

        new(config)
      end

      #
      # The list of advisory IDs to ignore.
      #
      # @return [Set<String>]
      #
      def ignore
        Set.new(@approvals.map(&:advisory))
      end

      #
      # The list of approvals to check advisories against.
      #
      # @return [Array<Approval>]
      #
      attr_reader :approvals

      #
      # Initializes the configuration.
      #
      # @param [Hash] config
      #   The configuration hash.
      #
      # @option config [Array<String, Hash>] :ignore
      #   The list of advisory IDs or approval Hashes to ignore.
      #
      def initialize(config={})
        @approvals = Array(config[:ignore]).map do |entry|
          Approval.load(entry)
        end
      end

    end
  end
end
