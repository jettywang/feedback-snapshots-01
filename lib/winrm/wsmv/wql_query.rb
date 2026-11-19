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

require 'digest'
require 'securerandom'
require 'nori'
require_relative 'base'
require_relative '../exceptions'
require_relative 'wql_enumeration'
require_relative 'wql_pull'

module WinRM
  module WSMV
    # WSMV message to query Windows via WQL
    #
    # The query owns one WqlEnumerationContext. Every Pull is built from that
    # context, its response is correlated by RelatesTo, and the next
    # continuation token is only accepted when it is new for this query.
    class WqlQuery < Base
      attr_reader :context, :message_id, :session_opts, :namespace, :wql

      def initialize(transport, session_opts, wql, namespace = nil)
        @transport = transport
        @session_opts = session_opts
        @wql = wql
        @namespace = namespace || 'root/cimv2/*'
        @message_id = SecureRandom.uuid.to_s.upcase
        @context = WqlEnumerationContext.new(
          endpoint: session_opts[:endpoint],
          namespace: @namespace,
          wql: @wql,
          max_no_progress_pulls: session_opts.fetch(
            :wql_max_no_progress_pulls, WqlEnumerationContext::DEFAULT_MAX_NO_PROGRESS_PULLS
          ),
          max_pulls: session_opts.fetch(:wql_max_pulls, WqlEnumerationContext::DEFAULT_MAX_PULLS)
        )
      end

      def process_response(response, &block)
        @items = WqlResult.new(@context)
        ensure_single_run!
        run_enumeration(response, &block)
        finalize_result(@items)
      end

      protected

      def create_header(header)
        header << Gyoku.xml(wql_header)
      end

      def create_body(body)
        body.tag!("#{NS_ENUM}:Enumerate") { |en| en << Gyoku.xml(wql_body) }
      end

      private

      TRANSPORT_ERRORS = [
        WinRMWSManFault,
        WinRMSoapFault,
        WinRMWMIError,
        WinRMHTTPTransportError
      ].freeze

      def enumerate(response, &block)
        hresp = WqlResponse.new(response)
        verify_action!(hresp, WqlResponse::ENUMERATE_ACTIONS, :enumerate)
        body = hresp.enumerate_response
        raise fault_for!(hresp, :enumerate) unless body

        process_items body[:items], &block
        if body.key?(:end_of_sequence)
          @context.complete!
          @items.mark_complete!(:end_of_sequence_on_enumerate)
          return
        end

        token = @context.bind_initial(body[:enumeration_context], page_digest: page_digest(body[:items]))
        pull_until_done(token, &block)
      end

      def pull_until_done(token, &block)
        loop do
          target = pull_target(token)
          body = pull_page(target)

          # Ownership is checked before rows are ingested, so a response
          # carrying another live query's token cannot contaminate this result.
          @context.check_token_ownership!(body[:enumeration_context]) unless body[:enumeration_context].nil?

          # Every new page contributes its rows. An exact replay of a page
          # already received for the same token is not new data: re-adding it
          # would duplicate rows, so it is skipped. The response still counts
          # as no progress, so a replay loop ends in an error and can never be
          # reported as complete.
          ingest_page(body, &block)

          break if record_page(body) == :complete

          token = body[:enumeration_context]
        end
      end

      def pull_page(target)
        raw = begin
          @transport.send_request(target[:message])
        rescue *TRANSPORT_ERRORS => e
          @context.fail!(:fault, e)
          raise WqlEnumerationFailedError.new(
            "query #{@context.query_id} failed at Pull ##{@context.pull_count} " \
            "(endpoint=#{target[:endpoint]} resource_uri=#{target[:resource_uri]} " \
            "namespace=#{target[:namespace]} token=#{target[:token].inspect}): #{e.message}",
            result: @items
          ), cause: e
        end

        page = WqlResponse.new(raw)
        verify_action!(page, WqlResponse::PULL_ACTIONS, :pull, target)
        verify_correlation!(page, target)
        body = page.pull_response
        raise fault_for!(page, :pull, target) unless body

        body
      end

      def ingest_page(body, &block)
        digest = page_digest(body[:items])
        return if @context.duplicate_page?(body[:enumeration_context], digest)

        process_items body[:items], &block
      end

      def record_page(body)
        outcome = @context.record_response(
          token: body[:enumeration_context],
          end_of_sequence: body.key?(:end_of_sequence),
          rows: count_items(body[:items]),
          page_digest: page_digest(body[:items])
        )
        @items.mark_complete!(:end_of_sequence) if outcome == :complete
        outcome
      end

      # Builds and records the exact target of one Pull. The context must
      # still be active; before_pull! also enforces the hard pull ceiling.
      def pull_target(token)
        @context.before_pull!
        pull = WqlPull.new(@session_opts, @context.namespace, token, context: @context)
        target = {
          query_id: @context.query_id,
          endpoint: WqlEnumerationContext.normalize_endpoint(@session_opts[:endpoint]),
          namespace: @context.namespace,
          resource_uri: @context.resource_uri,
          token: token,
          message_id: pull.message_id,
          message: pull.build
        }.freeze
        @items.record_pull(target.reject { |key, _value| key == :message })
        target
      end

      def verify_action!(response, expected_actions, phase, target = nil)
        return if response.action.nil?

        return if expected_actions.include?(response.action)

        if WqlResponse::FAULT_ACTIONS.include?(response.action)
          raise fault_for!(response, phase, target)
        end

        raise WqlContextMismatchError.new(
          "query #{@context.query_id} expected #{phase} response#{target_suffix(target)} " \
          "but received Action #{response.action.inspect}",
          result: @items
        )
      end

      def verify_correlation!(response, target)
        return if response.relates_to.nil?

        expected = "uuid:#{target[:message_id]}"
        return if response.relates_to.casecmp(expected).zero?

        @context.fail!(:mismatched_response)
        raise WqlContextMismatchError.new(
          "query #{@context.query_id} sent MessageID #{expected} but the pulled response " \
          "relates to #{response.relates_to.inspect}; refusing to credit rows to this query",
          result: @items
        )
      end

      def fault_for!(response, phase, target = nil)
        detail = response.body[:fault]
        WqlEnumerationFailedError.new(
          "query #{@context.query_id} received a fault during #{phase}#{target_suffix(target)}: " \
          "#{fault_message(detail)}",
          result: @items
        )
      end

      def fault_message(fault)
        return 'unknown fault' unless fault.is_a?(Hash)

        reason = fault.dig(:reason, :text)
        code = fault.dig(:code, :value)
        subcode = fault.dig(:code, :subcode, :value)
        wsman_code = fault.dig(:detail, :ws_man_fault, :@code)
        parts = [code, subcode, wsman_code, reason.to_s.strip]
        parts.compact.reject(&:empty?).join(' / ').strip
      end

      def target_suffix(target)
        return '' if target.nil?

        " (endpoint=#{target[:endpoint]} resource_uri=#{target[:resource_uri]} " \
          "namespace=#{target[:namespace]} token=#{target[:token].inspect})"
      end

      def page_digest(items)
        Digest::SHA256.hexdigest(items.inspect)
      end

      def termination_for(error)
        case error
        when WqlEnumerationStalledError then :stalled
        when WqlEnumerationLimitError then :pull_limit
        when WqlContextMismatchError then :mismatched_response
        when WqlEnumerationIncompleteError then :incomplete
        else :fault
        end
      end

      def ensure_single_run!
        return if @context.state == :new

        error = WqlContextMismatchError.new(
          "query #{@context.query_id} is already #{@context.state}; " \
          'one query instance may only run one enumeration',
          result: @items
        )
        @items.mark_incomplete!(:mismatched_response, error)
        raise error
      end

      def run_enumeration(response, &block)
        enumerate(response, &block)
      rescue WqlEnumerationError => e
        record_enumeration_error(e)
        raise
      rescue *TRANSPORT_ERRORS => e
        record_enumeration_error(e, termination: :fault, wrap: true)
      end

      def record_enumeration_error(error, termination: termination_for(error), wrap: false)
        unless @context.failed?
          reason = error.is_a?(WqlContextMismatchError) ? :mismatched_response : :fault
          @context.fail!(reason, error)
        end
        @items.mark_incomplete!(termination, error) unless @items.complete?
        unless wrap
          error.result ||= @items
          raise error
        end

        failed = WqlEnumerationFailedError.new(
          "query #{@context.query_id} failed during enumeration: #{error.message}",
          result: @items
        )
        raise failed, cause: error
      end

      def finalize_result(result)
        result.mark_incomplete!(:not_terminated) unless result.complete?
        result
      end

      def process_items(items, &block)
        count = count_items(items)
        return count if items.nil?

        items.each_pair do |k, v|
          # Normalize items so the type always has an array even if it's just a single item.
          v_ary = v.is_a?(Array) ? v : [v]
          if block
            v_ary.each { |val| yield k, val }
          else
            @items[k] += v_ary
          end
        end
        @items.add_rows(count)
        count
      end

      def count_items(items)
        return 0 if items.nil?

        items.each_pair.sum do |_k, v|
          v.is_a?(Array) ? v.length : 1
        end
      end

      def wql_header
        merge_headers(
          shared_headers(@session_opts, message_id: @message_id),
          resource_uri_wmi(@namespace),
          action_enumerate
        )
      end

      def wql_body
        {
          "#{NS_WSMAN_DMTF}:OptimizeEnumeration" => nil,
          "#{NS_WSMAN_DMTF}:MaxElements" => '32000',
          "#{NS_WSMAN_DMTF}:Filter" => @wql,
          "#{NS_WSMAN_MSFT}:SessionId" => "uuid:#{@session_opts[:session_id]}",
          :attributes! => {
            "#{NS_WSMAN_DMTF}:Filter" => {
              'Dialect' => 'http://schemas.microsoft.com/wbem/wsman/1/WQL'
            }
          }
        }
      end
    end
  end
end
