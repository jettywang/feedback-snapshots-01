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

require 'thor'

module Bundler
  module Audit
    class CLI < ::Thor
      module Formats
        #
        # The plain-text output format.
        #
        module Text
          #
          # Prints any findings as plain-text.
          #
          # @param [Report] report
          #   The results from the {Scanner}.
          #
          # @param [IO, File] output
          #   Optional output stream.
          #
          def print_report(report,output=$stdout)
            original_stdout = $stdout
            $stdout = output

            report.each do |result|
              case result
              when Results::InsecureSource
                print_warning "Insecure Source URI found: #{result.source}"
              when Results::UnpatchedGem
                print_advisory result.gem, result.advisory
              when Results::RuntimeAudit
                print_runtime_audit result
              end
            end

            if report.vulnerable?
              say "Vulnerabilities found!", :red
            elsif report.runtime_unknown?
              say "Runtime audit inconclusive", :yellow
            else
              say("No vulnerabilities found", :green) unless options.quiet?
            end

            $stdout = original_stdout
          end

          private

          def print_warning(message)
            say message, :yellow
          end

          def print_runtime_audit(result)
            assessment = result.assessment

            say "Ruby Runtime:", :yellow
            say "Target: "
            say assessment.target

            if assessment.inputs['manifest']
              say "Manifest: "
              say assessment.inputs['manifest']
            end

            if assessment.inputs['lockfile']
              say "Lockfile: "
              say assessment.inputs['lockfile']
            end

            if assessment.declaration
              say "Declared: "
              say assessment.declaration
            end

            case assessment.status
            when :affected
              say "Status: ", :red
              say "affected"
            when :unknown
              say "Status: ", :yellow
              say "unknown"
            else
              say "Status: ", :green
              say "clean"
            end

            assessment.findings.each do |finding|
              case finding.status
              when :affected
                print_runtime_advisory finding
              when :unknown
                say "Unknown: ", :yellow
                say finding.message
              end
            end

            if options.verbose?
              counter = Hash.new(0)
              assessment.findings.each { |finding| counter[finding.status] += 1 }

              say "Findings: ", :red
              say "affected=#{counter[:affected]}, patched=#{counter[:patched]}, unknown=#{counter[:unknown]}"
            end

            assessment.notes.each do |note|
              say "Note: ", :yellow
              say note[:message]
            end

            say
          end

          def print_runtime_advisory(finding)
            advisory = finding.advisory

            say "Name: ", :red
            say advisory.id

            if advisory.cve
              say "CVE: ", :red
              say advisory.cve_id
            end

            say "Engine: ", :red
            say advisory.engine

            say "Criticality: ", :red
            case advisory.criticality
            when :none     then say "None"
            when :low      then say "Low"
            when :medium   then say "Medium", :yellow
            when :high     then say "High", [:red, :bold]
            when :critical then say "Critical", [:red, :bold]
            else                say "Unknown"
            end

            say "URL: ", :red
            say advisory.url

            say "Title: ", :red
            say advisory.title

            unless advisory.patched_versions.empty?
              say "Solution: update to ", :red
              say advisory.patched_versions.map { |v| "'#{v}'" }.join(', ')
            else
              say "Solution: ", :red
              say "remove or disable this runtime until a patch is available!", [:red, :bold]
            end

            say
          end

          def print_advisory(gem, advisory)
            say "Name: ", :red
            say gem.name

            say "Version: ", :red
            say gem.version

            if advisory.cve
              say "CVE: ", :red
              say advisory.cve_id
            end

            if advisory.ghsa
              say "GHSA: ", :red
              say advisory.ghsa_id
            end

            say "Criticality: ", :red
            case advisory.criticality
            when :none     then say "None"
            when :low      then say "Low"
            when :medium   then say "Medium", :yellow
            when :high     then say "High", [:red, :bold]
            when :critical then say "Critical", [:red, :bold]
            else                say "Unknown"
            end

            say "URL: ", :red
            say advisory.url

            if options.verbose?
              say "Description:", :red
              say

              print_wrapped advisory.description, indent: 2
              say
            else
              say "Title: ", :red
              say advisory.title
            end

            unless advisory.patched_versions.empty?
              say "Solution: update to ", :red
              say advisory.patched_versions.map { |v| "'#{v}'" }.join(', ')
            else
              say "Solution: ", :red
              say "remove or disable this gem until a patch is available!", [:red, :bold]
            end

            say
          end
        end

        Formats.register :text, Text
      end
    end
  end
end
