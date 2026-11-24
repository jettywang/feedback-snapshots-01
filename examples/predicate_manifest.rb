# frozen_string_literal: true

# Builds an offline-verifiable predicate manifest for a parent/child schema pair
#
# Demonstrates:
#
# - a field whose declaration order changed but whose predicates and bindings
#   are identical: reported as `proof_order`, no re-approval,
# - a field that keeps the `gt?` name but is bound to different code: reported
#   as `rebound` with the previous and current binding evidence,
# - a recording stub proving that manifest generation never invokes a predicate.
#
# Usage:
#
#   ruby -Ilib examples/predicate_manifest.rb [OUTPUT_DIR]
#
# With OUTPUT_DIR, writes parent.json, child.json, changes.json and approval.md.

require "dry/schema"

Dry::Schema.load_extensions(:manifest)

# --- Recording stand-in -------------------------------------------------------
#
# This module is the child's predicate registry. Every `gt?` call is recorded,
# so the example can prove that generating manifests did not execute anything.
module AuditPredicates
  include Dry::Logic::Predicates

  CALLS = []

  def self.gt?(num, input)
    CALLS << [num, input]
    input > num
  end
end

# --- Parent schema ------------------------------------------------------------
parent = Dry::Schema.define do
  required(:account).hash do
    required(:name).value(:string, min_size: 2, max_size: 32)
    required(:age).value(:integer, gt: 18)
  end

  required(:score).value(:integer, gt: 0)
end

# --- Child schema -------------------------------------------------------------
#
# `account.name` only swaps the order of `min_size` and `max_size`.
# `account.age` keeps `gt: 18` but resolves `gt?` through AuditPredicates.
child = Dry::Schema.define(parent: parent) do
  config.predicates = AuditPredicates

  required(:account).hash do
    required(:name).value(:string, max_size: 32, min_size: 2)
    required(:age).value(:integer, gt: 18)
  end
end

# --- Manifests ----------------------------------------------------------------
#
# Read-only: this inspects compiled rule objects and bound methods only.
parent_manifest = parent.manifest(name: "parent")
child_manifest = child.manifest(name: "child")

raise "predicate executed during manifest generation" unless AuditPredicates::CALLS.empty?

change_set = Dry::Schema::Manifest.compare(parent_manifest.to_h, child_manifest.to_h)
calls_during_manifest = AuditPredicates::CALLS.size
raise "predicate executed while diffing manifests" unless calls_during_manifest.zero?

# Prove the spy does record calls when a schema is actually applied. This runs
# after the manifests are built, and the counter is checked around each step so
# the zero-call assertion above is meaningful rather than vacuous.
if ENV["DEMO_RUN_SCHEMA"] == "1"
  audit = child.(account: {name: "ab", age: 18}, score: 1)
  raise "expected the spy to record a call during validation" if AuditPredicates::CALLS.empty?
  puts "Validation errors: #{audit.errors.to_h.inspect}"
  puts "Calls recorded by an actual validation: #{AuditPredicates::CALLS.inspect}"
end

# --- Output -------------------------------------------------------------------
if (dir = ARGV[0])
  require "fileutils"
  FileUtils.mkdir_p(dir)
  File.write(File.join(dir, "parent.json"), parent_manifest.to_json)
  File.write(File.join(dir, "child.json"), child_manifest.to_json)
  File.write(File.join(dir, "changes.json"), change_set.to_json)
  File.write(File.join(dir, "approval.md"), change_set.report)
end

puts <<~TEXT
  Parent manifest: #{parent_manifest.entries.size} predicates
                   #{parent_manifest.builtins.size} built-in, #{parent_manifest.runtime_bindings.size} runtime
  Child manifest:  #{child_manifest.entries.size} predicates
                   #{child_manifest.builtins.size} built-in, #{child_manifest.runtime_bindings.size} runtime

  Predicate calls during manifest generation: #{calls_during_manifest}
  Parent document digest valid: #{Dry::Schema::Manifest.verify(parent_manifest.to_json)}
  Child document digest valid:  #{Dry::Schema::Manifest.verify(child_manifest.to_json)}

  Fields requiring re-approval: #{change_set.approval_required.map(&:field).uniq.inspect}
TEXT

puts
puts change_set.report
