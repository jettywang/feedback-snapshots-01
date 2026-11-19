# Copyright 2026 WinRM contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require 'rexml/formatters/pretty'

module WinRM
  module LogRedactor
    # Builds the single-line, allow-listed diagnostic summary for a message.
    class Summary
      def initialize(document, raw, operation, redactions)
        @document = document
        @raw = raw
        @operation = operation
        @redactions = redactions
      end

      def to_s
        fields = [@operation.to_s, "bytes=#{@raw.bytesize}", "sha256=sha256:#{LogRedactor.digest(@raw)}"]
        add_field(fields, 'op', safe_operation(body_operation))
        fields << "elements=#{element_count(@document.root)}"
        fields << "redactions=#{@redactions}"
        add_field(fields, 'message_id', LogRedactor.identifier(first_text('MessageID')))
        add_field(fields, 'relates_to', LogRedactor.identifier(first_text('RelatesTo')))
        add_field(fields, 'action', summary_url(first_text('Action')))
        add_field(fields, 'session_id', LogRedactor.identifier(first_text('SessionId')))
        add_field(fields, 'shell_id', LogRedactor.identifier(selector_value('ShellId')))
        add_field(fields, 'command_id', LogRedactor.identifier(command_id))
        fields.join(' ')
      end

      # Pretty-prints the sanitized copy, never the original message.
      def self.pretty(document)
        formatter = REXML::Formatters::Pretty.new(2)
        formatter.compact = true
        output = String.new
        formatter.write(document, output)
        output
      end

      def self.parse(raw, operation, error)
        ([operation.to_s, "bytes=#{raw.bytesize}", "sha256=sha256:#{LogRedactor.digest(raw)}", 'xml=unparseable'] +
          LogRedactor.parse_error_fields(error)).join(' ')
      end

      private

      def add_field(fields, name, value)
        return if value.nil? || value.to_s.empty?

        fields << "#{name}=#{LogRedactor.scalar(value)}"
      end

      def safe_operation(value)
        return nil if value.nil?

        text = value.to_s.strip
        return text if LogRedactor::KNOWN_OPERATIONS.include?(text)

        LogRedactor.redaction_marker('operation', text)
      end

      def summary_url(value)
        return nil if value.nil?

        text = value.to_s.strip
        text.match?(%r{\Ahttps?://\S+\z}) ? LogRedactor.sanitize_url(text) : LogRedactor.identifier(text)
      end

      def body_operation
        body = REXML::XPath.first(@document, "//*[local-name() = 'Body']")
        child = body && body.elements.to_a.first
        child&.name
      end

      def first_text(local_name)
        node = REXML::XPath.first(@document, "//*[local-name() = '#{local_name}']")
        node&.text
      end

      def selector_value(name)
        node = REXML::XPath.first(@document, "//*[local-name() = 'Selector' and @Name = '#{name}']")
        node&.text
      end

      def command_id
        REXML::XPath.each(@document, '//*[@CommandId]') do |element|
          return element.attributes['CommandId']
        end
        nil
      end

      def element_count(root)
        return 0 unless root.is_a?(REXML::Element)

        count = 0
        stack = [root]
        until stack.empty?
          node = stack.pop
          count += 1
          stack.concat(node.elements.to_a)
        end
        count
      end
    end
  end
end
