# frozen_string_literal: true
require "spec_helper"
require_relative "../../../../tool/visibility_surface_diff"
require_relative "../../../../tool/visibility_surface_diff/demo_versions"

describe VisibilitySurfaceDiff do
  let(:changes) do
    VisibilitySurfaceDiff.compare(SCHEMA_V1, SCHEMA_V2, profiles: VISIBILITY_PROFILES)
  end

  def paths_for(profile)
    changes.select { |change| change.profile == profile }.map(&:path)
  end

  it "reports new role-visible fields and arguments only for the matching profile" do
    admin_paths = paths_for(:admin)
    assert_includes admin_paths, "Employee.salaryBand"
    assert_includes admin_paths, "Query.search(includeArchived:)"

    public_paths = paths_for(:public)
    refute_includes public_paths, "Employee.salaryBand"
    refute_includes public_paths, "Query.search(includeArchived:)"
  end

  it "reports types hidden from an interface for the affected profile" do
    public_paths = paths_for(:public)
    assert_includes public_paths, "NamedEntity -> InternalBot"
    assert_includes public_paths, "InternalBot"

    admin_paths = paths_for(:admin)
    refute_includes admin_paths, "NamedEntity -> InternalBot"
    refute_includes admin_paths, "InternalBot"
  end

  it "ignores internal-only changes that no request can observe" do
    all_paths = changes.map(&:path)
    refute_includes all_paths, "Employee.internalMetrics"
    refute_includes all_paths, "Query.employee"
  end

  it "reports nothing when both versions expose the same surface" do
    same_changes = VisibilitySurfaceDiff.compare(SCHEMA_V2, SCHEMA_V2, profiles: VISIBILITY_PROFILES)
    assert_empty same_changes
    assert_equal "No visible differences for any profile.", VisibilitySurfaceDiff.format_report(same_changes)
  end

  it "formats a per-profile report" do
    report = VisibilitySurfaceDiff.format_report(changes)
    assert_includes report, "Profile: public"
    assert_includes report, "Profile: admin"
    assert_includes report, "FIELD_ADDED"
    assert_includes report, "Employee.salaryBand"
  end
end
