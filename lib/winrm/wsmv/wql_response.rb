# Copyright 2016 Shawn Neal <sneal@sneal.net>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require 'nori'
require_relative '../exceptions'

module WinRM
  module WSMV
    # Parsed SOAP envelope for an enumerate/pull response. Correlation details
    # (Action/RelatesTo) are kept separate from the body so callers can reject
    # a response intended for another request.
    class WqlResponse
      ENUMERATE_ACTIONS = [
        'http://schemas.xmlsoap.org/ws/2004/09/enumeration/EnumerateResponse',
        'http://schemas.xmlsoap.org/ws/2004/09/enumeration/enumerateResponse'
      ].freeze
      PULL_ACTIONS = [
        'http://schemas.xmlsoap.org/ws/2004/09/enumeration/PullResponse',
        'http://schemas.xmlsoap.org/ws/2004/09/enumeration/pullResponse'
      ].freeze
      FAULT_ACTIONS = [
        'http://schemas.xmlsoap.org/ws/2004/09/enumeration/fault',
        'http://schemas.dmtf.org/wbem/wsman/1/wsman/fault'
      ].freeze

      attr_reader :document, :action, :relates_to, :body

      def initialize(raw)
        @document = parse(raw)
        envelope = @document[:envelope] || {}
        header = envelope[:header] || {}
        @action = header[:action]
        @relates_to = header[:relates_to]
        @body = envelope[:body] || {}
      end

      def enumerate_response
        @body[:enumerate_response]
      end

      def pull_response
        @body[:pull_response]
      end

      def fault?
        @body.key?(:fault)
      end

      private

      def parse(raw)
        parser = Nori.new(
          parser: :rexml,
          advanced_typecasting: false,
          convert_tags_to: ->(tag) { Nori::StringUtils.snakecase(tag).to_sym },
          strip_namespaces: true
        )
        parser.parse(raw.to_s) || {}
      rescue StandardError => e
        raise WinRMHTTPTransportError, "Unable to parse WQL enumeration response: #{e.message}"
      end
    end
  end
end
