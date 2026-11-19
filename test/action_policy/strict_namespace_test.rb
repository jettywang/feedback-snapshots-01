# frozen_string_literal: true

require "test_helper"

# Two local policies share the same inferred name ("DocumentPolicy"): one inside
# the audit (component) namespace and one at the top level (the public/tenant
# fallback). The document records below both resolve to that same policy name.
module StrictNSAudit
  class Document
    def self.policy_name
      "DocumentPolicy"
    end
  end

  class DocumentPolicy
    include ActionPolicy::Policy::Core

    def show?
      true
    end
  end
end

class StrictNSDocument
  def self.policy_name
    "DocumentPolicy"
  end
end

class StrictNSDocumentPolicy
  include ActionPolicy::Policy::Core

  def show?
    false
  end
end

# A policy name that only exists at the public (top-level) level, so the
# strict lookup has nothing to resolve inside the audit namespace.
class StrictNSReportPolicy
  include ActionPolicy::Policy::Core

  def show?
    false
  end
end

class StrictNSReport
  def self.policy_name
    "StrictNSReportPolicy"
  end
end

class TestStrictNamespaceLookup < Minitest::Test
  # Minimal authorizer that pins every lookup to the audit namespace in
  # strict mode, mirroring an audit component that must not silently fall
  # back to the public/tenant policies.
  class Auditor
    include ActionPolicy::Behaviour

    def authorization_namespace
      StrictNSAudit
    end

    def authorization_strict_namespace
      true
    end

    def build_authorization_context
      {}
    end
  end

  def teardown
    ActionPolicy::LookupChain::NamespaceCache.clear
  end

  def test_explicit_namespace_prefers_the_namespaced_same_named_policy
    # Both StrictNSAudit::DocumentPolicy and the top-level StrictNSDocumentPolicy
    # resolve to the same name; the explicit namespace must pick the namespaced one.
    policy_class = ActionPolicy.lookup(
      StrictNSAudit::Document,
      namespace: StrictNSAudit,
      strict_namespace: true
    )

    assert_equal StrictNSAudit::DocumentPolicy, policy_class
  end

  def test_missing_namespaced_policy_raises_a_locatable_error
    error = assert_raises(ActionPolicy::NotFound) do
      ActionPolicy.lookup(
        :invoice,
        namespace: StrictNSAudit,
        strict_namespace: true
      )
    end

    assert_equal StrictNSAudit, error.namespace
    assert_equal true, error.strict_namespace
    assert_equal "InvoicePolicy", error.policy_name
    assert_match "strict namespace StrictNSAudit", error.message
    assert_match "InvoicePolicy", error.message
  end

  def test_missing_namespaced_policy_still_returns_nil_when_allowed
    assert_nil ActionPolicy.lookup(
      :invoice,
      namespace: StrictNSAudit,
      strict_namespace: true,
      allow_nil: true
    )
  end

  def test_explicit_delegation_to_the_public_policy
    # Strict lookup refuses to cascade out of the namespace when the policy
    # only exists at the public level...
    assert_raises(ActionPolicy::NotFound) do
      ActionPolicy.lookup(
        StrictNSReport,
        namespace: StrictNSAudit,
        strict_namespace: true
      )
    end

    # ...but an explicit `with:` still delegates to the public policy.
    record = StrictNSReport.new
    policy = Auditor.new.policy_for(record: record, with: StrictNSReportPolicy)

    assert_instance_of StrictNSReportPolicy, policy
    assert_equal record, policy.record
  end

  def test_regular_call_keeps_the_library_fallback
    # Without strict mode the lookup cascades out of the namespace
    # and resolves the public policy.
    assert_equal StrictNSReportPolicy, ActionPolicy.lookup(
      StrictNSReport,
      namespace: StrictNSAudit
    )

    # Without a namespace at all, strict mode behaves like a normal lookup
    # and resolves the public policy.
    assert_equal StrictNSReportPolicy, ActionPolicy.lookup(
      StrictNSReport,
      strict_namespace: true
    )
  end

  def test_non_strict_missing_policy_keeps_the_original_message
    error = assert_raises(ActionPolicy::NotFound) do
      ActionPolicy.lookup(:invoice)
    end

    assert_equal false, error.strict_namespace
    assert_nil error.namespace
    assert_equal "Couldn't find policy class for :invoice (Symbol)", error.message
  end
end
