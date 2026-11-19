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

module WinRM
  module LogRedactor
    # Rewrites a parsed document in place for logging. This object only ever
    # receives a private copy; the caller's message is never passed here.
    class Sanitizer
      def initialize
        @redactions = 0
      end

      attr_reader :redactions

      def sanitize(document)
        sanitize_prolog(document)
        walk(document.root) if document.root
      end

      private

      # Comments and a DOCTYPE can carry content outside the element tree
      # (including entity declarations), so neither is reproduced.
      def sanitize_prolog(document)
        document.children.dup.each do |child|
          case child
          when REXML::Comment, REXML::Instruction, REXML::DocType
            document.delete(child)
            @redactions += 1
          when REXML::Text
            sanitize_prolog_text(document, child)
          end
        end
      end

      def sanitize_prolog_text(document, node)
        if node.value.to_s.strip.empty?
          document.delete(node)
        else
          node.value = "[OMITTED prolog sha256:#{LogRedactor.digest(node.value)}]"
          @redactions += 1
        end
      end

      def walk(node)
        return unless node.is_a?(REXML::Element)

        redact_attributes(node)
        if LogRedactor.sensitive_element?(node)
          redact_element(node)
          return
        end

        node.children.dup.each { |child| sanitize_child(child) }
        sanitize_known_element(node)
      end

      def sanitize_child(child)
        case child
        when REXML::Text
          redact_text(child)
          omit_text(child) if child.value.to_s.match?(LogRedactor::CREDENTIAL_ASSIGNMENT)
        when REXML::Comment, REXML::Instruction
          replace_with_omission(child)
        when REXML::Element
          walk(child)
        end
      end

      def redact_attributes(element)
        element.attributes.each_attribute do |attribute|
          next if attribute.prefix == 'xmlns' || attribute.expanded_name.start_with?('xmlns')

          redact_attribute(attribute)
        end
      end

      def redact_attribute(attribute)
        original = attribute.value.to_s
        if LogRedactor.sensitive_attribute?(attribute)
          replace_attribute(attribute, LogRedactor.redaction_marker("#{attribute.name} attribute", original))
        elsif LogRedactor.identifier_attribute?(attribute)
          safe = LogRedactor.identifier(original)
          replace_attribute(attribute, safe) unless safe == original || safe.nil?
        else
          redacted = LogRedactor.redact_urls(original)
          replace_attribute(attribute, redacted) unless redacted == original
        end
      end

      def replace_attribute(attribute, value)
        attribute.normalized = value
        @redactions += 1
      end

      # Correlation fields may only carry protocol-shaped identifiers. A peer
      # could otherwise smuggle content into MessageID or CommandId and have it
      # reproduced verbatim in the diagnostic copy.
      def sanitize_known_element(element)
        local = LogRedactor.normalize(element.name)
        return if element.elements.to_a.any?

        current = LogRedactor.collected_text(element)
        return if current.empty?

        replacement = known_element_replacement(local, element, current)
        return if replacement.nil? || replacement == current

        replace_children(element, replacement)
      end

      def known_element_replacement(local, element, current)
        if LogRedactor::IDENTIFIER_ELEMENTS.include?(local) ||
           (local == 'selector' && element.attributes['Name'].to_s.casecmp('ShellId').zero?)
          LogRedactor.identifier(current)
        elsif local == 'action'
          action_replacement(current)
        elsif local == 'to' && !current.include?('[REDACTED')
          LogRedactor.sanitize_url(current)
        end
      end

      def action_replacement(current)
        if current.match?(%r{\Ahttps?://\S+\z})
          LogRedactor.sanitize_url(current)
        else
          LogRedactor.identifier(current)
        end
      end

      def redact_element(element)
        value = LogRedactor.collected_text(element)
        replace_children(element, LogRedactor.redaction_marker(element.name, value))
      end

      def replace_children(element, text)
        element.children.dup.each { |child| element.delete(child) }
        element.add_text(text)
        @redactions += 1
      end

      def redact_text(node)
        original = node.value.to_s
        redacted = LogRedactor.redact_urls(original)
        node.value = redacted unless redacted == original
      end

      def omit_text(node)
        return if node.value.to_s.empty?

        node.value = "[OMITTED text sha256:#{LogRedactor.digest(node.value)}]"
        @redactions += 1
      end

      def replace_with_omission(node)
        marker = "[OMITTED #{node.class.name.split('::').last.downcase} " \
                 "sha256:#{LogRedactor.digest(node.to_s)}]"
        node.replace_with(REXML::Text.new(marker))
        @redactions += 1
      end
    end
  end
end
