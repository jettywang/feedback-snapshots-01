# frozen_string_literal: true
# Compare the externally-visible surface of two schema versions, per
# visibility profile, so reviewers can approve exactly what changed for
# each audience.
#
# Only differences that a real request can observe are reported: the
# comparison executes REFERENCE_QUERY against each schema with
# `context: { visibility_profile: profile }` and diffs the responses.
# Internal changes (resolver rewrites, definitions hidden from every
# profile) never show up here.
#
# CI usage:
#
#   ruby tool/visibility_surface_diff.rb path/to/schema_versions.rb [--require-unchanged]
#
# The versions file must define:
#
#   SCHEMA_V1            => Class<GraphQL::Schema> (baseline)
#   SCHEMA_V2            => Class<GraphQL::Schema> (candidate)
#   VISIBILITY_PROFILES  => Array<Symbol>          (profiles to audit)
#
# See tool/visibility_surface_diff/demo_versions.rb for an in-memory example.
#
# Exits 0 when no profile sees a difference; with `--require-unchanged`,
# exits 1 when any profile's visible surface changed.

module VisibilitySurfaceDiff
  # The reference query ("对照查询") run against both schema versions for
  # every profile. Keep it stable: it defines what "visible surface" means.
  REFERENCE_QUERY = <<~GRAPHQL
    query VisibilitySurface {
      __schema {
        types {
          name
          kind
          fields {
            name
            args { name }
          }
          possibleTypes { name }
        }
      }
    }
  GRAPHQL

  Change = Struct.new(:profile, :kind, :path)

  module_function

  # Run the reference query as a real request under `profile` and return
  # the observable surface:
  #   { "TypeName" => { "kind" => ..., "fields" => { "name" => [arg, ...] }, "possible_types" => [...] } }
  def surface_for(schema, profile)
    result = schema.execute(REFERENCE_QUERY, context: { visibility_profile: profile })
    if result["errors"]
      raise "Surface query failed for profile #{profile.inspect}: #{result["errors"].inspect}"
    end

    surface = {}
    result["data"]["__schema"]["types"].each do |type|
      fields = {}
      (type["fields"] || []).each do |field|
        fields[field["name"]] = field["args"].map { |arg| arg["name"] }.sort
      end
      surface[type["name"]] = {
        "kind" => type["kind"],
        "fields" => fields,
        "possible_types" => (type["possibleTypes"] || []).map { |t| t["name"] }.sort,
      }
    end
    surface
  end

  # Diff two schema versions for each of `profiles`. Returns an array of Change.
  def compare(old_schema, new_schema, profiles:)
    profiles.flat_map do |profile|
      diff_surfaces(profile, surface_for(old_schema, profile), surface_for(new_schema, profile))
    end
  end

  def diff_surfaces(profile, before, after)
    changes = []
    (after.keys - before.keys).sort.each do |type_name|
      changes << Change.new(profile, :type_added, type_name)
    end
    (before.keys - after.keys).sort.each do |type_name|
      changes << Change.new(profile, :type_removed, type_name)
    end
    (before.keys & after.keys).sort.each do |type_name|
      old_fields = before[type_name]["fields"]
      new_fields = after[type_name]["fields"]
      (new_fields.keys - old_fields.keys).sort.each do |field_name|
        changes << Change.new(profile, :field_added, "#{type_name}.#{field_name}")
      end
      (old_fields.keys - new_fields.keys).sort.each do |field_name|
        changes << Change.new(profile, :field_removed, "#{type_name}.#{field_name}")
      end
      (old_fields.keys & new_fields.keys).sort.each do |field_name|
        (new_fields[field_name] - old_fields[field_name]).each do |arg_name|
          changes << Change.new(profile, :argument_added, "#{type_name}.#{field_name}(#{arg_name}:)")
        end
        (old_fields[field_name] - new_fields[field_name]).each do |arg_name|
          changes << Change.new(profile, :argument_removed, "#{type_name}.#{field_name}(#{arg_name}:)")
        end
      end
      old_possible = before[type_name]["possible_types"]
      new_possible = after[type_name]["possible_types"]
      (new_possible - old_possible).each do |type_name_2|
        changes << Change.new(profile, :possible_type_added, "#{type_name} -> #{type_name_2}")
      end
      (old_possible - new_possible).each do |type_name_2|
        changes << Change.new(profile, :possible_type_removed, "#{type_name} -> #{type_name_2}")
      end
    end
    changes
  end

  def format_report(changes)
    return "No visible differences for any profile." if changes.empty?

    lines = []
    changes.group_by(&:profile).each do |profile, profile_changes|
      lines << "Profile: #{profile}"
      profile_changes.each do |change|
        lines << "  #{change.kind.to_s.upcase.ljust(22)} #{change.path}"
      end
    end
    lines.join("\n")
  end
end

if $PROGRAM_NAME == __FILE__
  require "optparse"

  options = { require_unchanged: false }
  parser = OptionParser.new do |opts|
    opts.banner = "Usage: ruby #{$PROGRAM_NAME} SCHEMA_VERSIONS_FILE [--require-unchanged]"
    opts.on("--require-unchanged", "Exit 1 if any profile's visible surface changed") do
      options[:require_unchanged] = true
    end
  end
  versions_file = parser.parse(ARGV).first or abort parser.to_s

  $LOAD_PATH.unshift(File.expand_path("../lib", __dir__))
  require "graphql"
  load File.expand_path(versions_file)

  changes = VisibilitySurfaceDiff.compare(SCHEMA_V1, SCHEMA_V2, profiles: VISIBILITY_PROFILES)
  puts VisibilitySurfaceDiff.format_report(changes)
  if options[:require_unchanged] && !changes.empty?
    exit 1
  end
end
