# frozen_string_literal: true

module Dry
  module Schema
    module Manifest
      # Renders a change set as a reviewable Markdown document
      #
      # @api private
      class Report
        # @api private
        def initialize(change_set, current: nil, current_document: nil)
          @change_set = change_set
          @current = current
          @current_document = current_document
        end

        # @api private
        def to_s
          [
            heading,
            "",
            summary,
            "",
            table,
            "",
            approval_basis,
            evidence_gaps
          ].flatten.join("\n").rstrip + "\n"
        end

        private

        # @api private
        def heading
          "## Predicate manifest: #{@change_set.previous_name || "(none)"} -> " \
            "#{@change_set.current_name || @current&.name || "(none)"}"
        end

        # @api private
        def summary
          counts = @change_set.to_h.fetch("summary")

          "Re-approval required: **#{@change_set.approval_required?}** " \
            "(rebound: #{counts["rebound"]}, added: #{counts["added"]}, " \
            "removed: #{counts["removed"]}, order-only: #{counts["proof_order"]}, " \
            "unchanged: #{counts["unchanged"]})"
        end

        # @api private
        def table
          rows = @change_set.changes.map do |change|
            [
              change.approval_required? ? "yes" : "no",
              change.kind,
              change.field,
              change.logical_rule_path,
              change.current_stable_id || change.previous_stable_id || "(runtime binding)",
              change.reasons.join("; ")
            ]
          end

          markdown_table(
            %w[re-approve change field logical_path stable_id basis],
            rows
          )
        end

        # @api private
        def approval_basis
          changes = @change_set.approval_required
          return ["### Approval basis", "", "No field requires re-approval."] if changes.empty?

          ["### Approval basis", ""] + changes.flat_map do |change|
            [
              "#### #{change.field} / #{change.logical_rule_path} (#{change.kind})",
              "",
              "- Previous: #{describe(change.previous_binding)}",
              "- Current: #{describe(change.current_binding)}",
              "- Why: #{change.reasons.join("; ")}",
              ""
            ]
          end
        end

        # @api private
        def evidence_gaps
          document = @current.is_a?(Inventory) ? @current.to_h : (@current_document || @current)
          gaps = document&.dig("evidence_gaps")
          return [] unless gaps && !gaps.empty?

          [
            "### Runtime-only evidence gaps",
            "",
            "These bindings cannot be verified offline. Confirm them in an isolated runtime check.",
            "",
            markdown_table(
              %w[field logical_path predicate owner registry gap],
              gaps.map do |gap|
                [
                  gap["field"],
                  gap["logical_rule_path"],
                  gap["predicate"],
                  gap["owner"],
                  gap["registry"],
                  gap["evidence_gap"]
                ]
              end
            )
          ]
        end

        # @api private
        def describe(binding)
          return "(absent)" if binding.nil?

          if binding["kind"] == "runtime"
            "runtime binding via #{binding["registry"].inspect}; owner=#{binding["owner"].inspect}; " \
              "source=#{source(binding)}"
          else
            "#{binding["gem"]} #{binding["gem_version"]} #{binding["owner"]} " \
              "#{source(binding)} body=#{binding["body_sha256"]&.slice(0, 16)} " \
              "stable_id=#{binding["stable_id"]}"
          end
        end

        # @api private
        def source(binding)
          location = binding["source"]
          location ? "#{location["path"]}:#{location["line"]}" : "(unknown)"
        end

        # @api private
        def markdown_table(headers, rows)
          lines = []
          lines << "| #{headers.join(" | ")} |"
          lines << "| #{headers.map { "---" }.join(" | ")} |"
          rows.each do |row|
            lines << "| #{row.map { |cell| cell.to_s.gsub("|", "\\|") }.join(" | ")} |"
          end
          lines.join("\n")
        end
      end
    end
  end
end
