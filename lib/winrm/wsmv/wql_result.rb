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

module WinRM
  module WSMV
    # Hash-compatible WQL result that also records whether a legal
    # EndOfSequence was observed, along with the targets actually pulled.
    class WqlResult < Hash
      attr_reader :context, :pull_targets, :termination, :error, :row_count

      def initialize(context = nil)
        super()
        @context = context
        @complete = false
        @termination = :not_started
        @pull_targets = []
        @row_count = 0
        @error = nil
        self.default_proc = ->(hash, key) { hash[key] = [] }
      end

      def complete?
        @complete
      end

      def incomplete?
        !@complete
      end

      def mark_complete!(termination = :end_of_sequence)
        @complete = true
        @termination = termination
        self
      end

      def mark_incomplete!(termination = :incomplete, error = nil)
        @complete = false unless @complete
        @termination = termination unless @complete
        @error ||= error
        self
      end

      def record_pull(target)
        @pull_targets << target.freeze
        self
      end

      def add_rows(count)
        @row_count += count
        self
      end

      def query_id
        @context && @context.query_id
      end

      def endpoint
        @context && @context.endpoint
      end

      def resource_uri
        @context && @context.resource_uri
      end

      def namespace
        @context && @context.namespace
      end
    end
  end
end
