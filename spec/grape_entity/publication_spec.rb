# frozen_string_literal: true

describe Grape::Entity::Publication do
  let(:ledger) { Grape::Entity::Publication::Ledger.new }

  describe 'optional field degradation' do
    let(:boundary_class) do
      Class.new(Grape::Entity) do
        publication do
          mandatory :id
          on_optional_failure :omit
        end
      end
    end

    before do
      boundary_class.expose :id
      boundary_class.expose :name, format_with: ->(value) { value.upcase }
      boundary_class.expose :note, format_with: ->(_value) { raise 'formatter detail: /secret/path' }
    end

    it 'delivers a representation without the failed optional field' do
      result = boundary_class.publish({ id: 1, name: 'alpha', note: 'n' }, publication_key: :alpha)

      expect(result.deliverable?).to be(true)
      expect(result.representation).to eq(id: 1, name: 'ALPHA')
      expect(result.event_codes).to include(:published, :optional_field_degraded)
      expect(result.outcome).to eq(:optional_field_degraded)
    end

    it 'keeps the internal failure reason on the error but out of its message' do
      result = boundary_class.publish({ id: 2, name: 'beta', note: 'n' }, publication_key: :beta)

      error = result.optional_errors.first
      expect(error.code).to eq(:formatter_failure)
      expect(error.message).not_to include('secret')
      expect(error.internal_reason.message).to include('secret')
    end
  end

  describe 'mandatory field protection' do
    let(:boundary_class) do
      Class.new(Grape::Entity) do
        publication { mandatory :id }
      end
    end

    before do
      boundary_class.expose :id, mandatory: true, format_with: ->(_value) { raise 'internal mandatory detail' }
      boundary_class.expose :name, format_with: ->(value) { value }
    end

    it 'rejects the object and never exposes the partially built hash' do
      result = boundary_class.publish({ id: 1, name: 'alpha' }, publication_key: :alpha)

      expect(result.deliverable?).to be(false)
      expect(result.representation).to be_nil
      expect(result.error_code).to eq(:mandatory_field_missing)
      expect(result.event_codes).to include(:mandatory_field_missing)
      expect(result.errors.map(&:code)).to include(:formatter_failure)
    end

    it 'exposes the retained representation instead of half-built output' do
      boundary_class.expose(:id, mandatory: true, override: true) { |object| object[:id] }
      first = boundary_class.publish({ id: 7, name: 'stable' }, publication_key: :stable)
      expect(first.deliverable?).to be(true)

      boundary_class.expose(:id, mandatory: true, override: true) { |object| raise 'boom' if object[:fail]; object[:id] }
      failed = boundary_class.publish({ id: 7, name: 'new', fail: true }, publication_key: :stable)

      expect(failed.deliverable?).to be(false)
      expect(failed.retained).to eq(id: 7, name: 'stable')
      expect(failed.review_representation).to eq(id: 7, name: 'stable')
      expect(failed.event_codes).to include(:retained_representation_used)
      expect(failed.to_h[:representation]).to eq(id: 7, name: 'stable')
    end

    it 'reports no retained representation when nothing was previously published' do
      result = boundary_class.publish({ id: 9, name: 'fresh' }, publication_key: :fresh)

      expect(result.deliverable?).to be(false)
      expect(result.retained?).to be(false)
      expect(result.errors.map(&:code)).to include(:no_retained_representation)
    end
  end

  describe 'review submission evidence' do
    let(:finding_class) do
      Class.new(Grape::Entity) do
        publication do
          mandatory :id
          on_optional_failure :omit
        end
      end
    end

    before do
      finding_class.expose :id, mandatory: true
      finding_class.expose :severity, format_with: ->(value) { value }
      finding_class.expose :note, format_with: ->(value) { raise 'flaky formatter: /internal/secret' if value == :flaky; value }
    end

    it 'submits the optional-failure object and rejects the mandatory-failure object' do
      mandatory_class = Class.new(Grape::Entity) do
        publication { mandatory :id }
      end
      mandatory_class.expose(:id, mandatory: true) { |object| raise 'mandatory boom: /internal/secret' if object[:fail]; object[:id] }
      mandatory_class.expose :severity, format_with: ->(value) { value }
      mandatory_class.expose :note, format_with: ->(value) { value }

      optional = finding_class.publish({ id: 1, severity: 'low', note: :flaky }, publication_key: :finding_a)
      mandatory = mandatory_class.publish({ id: 2, severity: 'high', note: 'n', fail: true },
                                          publication_key: :finding_b)

      # The optional failure is an intentional degradation and may be submitted.
      expect(optional.deliverable?).to be(true)
      expect(optional.outcome).to eq(:optional_field_degraded)
      expect(optional.event_codes).to contain_exactly(:published, :optional_field_degraded)
      expect(optional.error_code).to be_nil

      # The mandatory failure is rejected; only a public code is observable.
      expect(mandatory.deliverable?).to be(false)
      expect(mandatory.representation).to be_nil
      expect(mandatory.error_code).to eq(:mandatory_field_missing)
      expect(mandatory.event_codes).to include(:mandatory_field_missing)
      expect(mandatory.errors.first.message).not_to include('secret')
      expect(mandatory.internal_reasons.first.message).to include('secret')
    end

    it 'keeps the last stable representation for a repeated key after a mandatory failure' do
      finding_class.expose(:id, mandatory: true, override: true) { |object| object[:id] }
      stable = finding_class.publish({ id: 3, severity: 'medium', note: 'ok' }, publication_key: :finding_c)
      expect(stable.deliverable?).to be(true)

      finding_class.expose(:id, mandatory: true, override: true) { |_object| raise 'mandatory boom' }
      failed = finding_class.publish({ id: 3, severity: 'high', note: 'new' }, publication_key: :finding_c)

      expect(failed.deliverable?).to be(false)
      expect(failed.retained).to eq(id: 3, severity: 'medium', note: 'ok')
      expect(failed.review_representation).to eq(failed.retained)
      expect(failed.event_codes).to include(:mandatory_field_missing, :retained_representation_used)
      expect(failed.to_h[:representation]).to eq(failed.retained)
    end
  end

  describe 'batch submission' do
    let(:boundary_class) do
      Class.new(Grape::Entity) do
        publication { mandatory :id }
      end
    end

    before do
      boundary_class.expose(:id, mandatory: true) { |object| raise 'boom' if object[:broken]; object[:id] }
      boundary_class.expose :name
    end

    it 'distinguishes a deliberate per-object degradation from a batch abort' do
      objects = [{ id: 1, name: 'a' }, { id: 2, name: 'b', broken: true }, { id: 3, name: 'c' }]

      degraded = boundary_class.publish_batch(objects, on_member_failure: :degrade)
      expect(degraded.aborted?).to be(false)
      expect(degraded.partial?).to be(true)
      expect(degraded.error_code).to eq(:batch_partial)
      expect(degraded.members.map(&:deliverable?)).to eq([true, false, true])

      aborted = boundary_class.publish_batch(objects, on_member_failure: :abort_batch)
      expect(aborted.aborted?).to be(true)
      expect(aborted.deliverable?).to be(false)
      expect(aborted.error_code).to eq(:batch_aborted)
      expect(aborted.members.map(&:deliverable?)).to eq([false, false, false])
      expect(aborted.representations).to eq([nil, nil, nil])
    end

    it 'reports a complete batch when every object publishes cleanly' do
      batch = boundary_class.publish_batch([{ id: 1, name: 'a' }, { id: 2, name: 'b' }])
      expect(batch.complete?).to be(true)
      expect(batch.error_code).to eq(:batch_complete)
    end
  end

  describe 'nested mandatory exposures' do
    it 'protects a nested field declared with mandatory: true' do
      nested = Class.new(Grape::Entity) do
        expose :meta do
          expose :code, mandatory: true, format_with: ->(_value) { raise 'nested mandatory boom' }
        end
      end

      expect(nested.publication_declaration.mandatory_fields).to eq([%i[meta code]])
      result = nested.publish({ meta: { code: 'c' } })
      expect(result.deliverable?).to be(false)
      expect(result.error_code).to eq(:mandatory_field_missing)
      expect(result.error_fields).to include(%i[meta code])
    end
  end

  describe 'allowlist' do
    let(:boundary_class) do
      Class.new(Grape::Entity) do
        publication do
          allow :id, :name
        end
      end
    end

    before do
      boundary_class.expose :id
      boundary_class.expose :name
      boundary_class.expose :internal_note
    end

    it 'keeps unapproved fields out of the delivered representation' do
      result = boundary_class.publish({ id: 1, name: 'a', internal_note: 'secret' })
      expect(result.deliverable?).to be(true)
      expect(result.representation).to eq(id: 1, name: 'a')
      expect(result.event_codes).not_to include(:field_excluded)
    end

    it 'treats a missing mandatory allowlisted field as a rejection' do
      boundary_class.publication.mandatory :missing
      result = boundary_class.publish({ id: 1, name: 'a' })
      expect(result.deliverable?).to be(false)
      expect(result.error_code).to eq(:mandatory_field_missing)
    end
  end

  describe 'default behaviour' do
    let(:boundary_class) { Class.new(Grape::Entity) }

    before do
      boundary_class.expose :id
      boundary_class.expose :name
    end

    it 'leaves serialization untouched when no publication contract is declared' do
      expect(boundary_class.represent({ id: 1, name: 'a' }, serializable: true)).to eq(id: 1, name: 'a')
    end
  end
end
