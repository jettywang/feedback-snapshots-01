# frozen_string_literal: true

RSpec.describe "role_views extension" do
  before { Dry::Schema.load_extensions(:role_views) }

  # One compiled base schema shared by every role. It keeps the public
  # validation rules; role views only narrow which keys may be written.
  subject(:profile_schema) do
    Dry::Schema.Params do
      configure { config.validate_keys = true }

      required(:name).filled(:string, min_size?: 2)
      required(:age).filled(:integer, gt?: 0)
      optional(:role).filled(:string)
    end
  end

  before do
    profile_schema.register_role(:admin) { |schema| schema.view(:name, :age, :role) }
    profile_schema.register_role(:member) { |schema| schema.view(:name, :age) }
  end

  let(:admin) { profile_schema.for_role(:admin) }
  let(:member) { profile_schema.for_role(:member) }

  describe "registration" do
    it "registers the two roles against the same compiled object" do
      expect(profile_schema.role?(:admin)).to be(true)
      expect(profile_schema.role?(:member)).to be(true)
      expect(profile_schema.role?(:guest)).to be(false)
      expect(profile_schema.roles.keys).to eql(%i[admin member])
    end

    it "derives both views from the single base processor" do
      expect(admin.schema_dsl).not_to equal(profile_schema.schema_dsl)
      expect(member.schema_dsl).not_to equal(profile_schema.schema_dsl)
      expect(profile_schema.object_id).to be(profile_schema.object_id)
    end

    it "exposes only the permitted keys on each view" do
      expect(admin.key_map.to_dot_notation).to eql(%w[name age role])
      expect(member.key_map.to_dot_notation).to eql(%w[name age])
    end

    it "rejects permitting a key the base schema does not define" do
      expect { profile_schema.view(:name, :unknown) }
        .to raise_error(
          Dry::Schema::Extensions::RoleViews::UnknownKeyError,
          /:unknown/
        )
    end

    it "rejects an empty view" do
      expect { profile_schema.view }
        .to raise_error(ArgumentError, /at least one key/)
    end
  end

  describe "base schema rules stay public" do
    it "still demands its required keys" do
      result = profile_schema.call(name: "Al")

      expect(result).to be_failure
      expect(result.errors.to_h).to eql(age: ["is missing"])
    end

    it "still applies the same value predicates" do
      result = profile_schema.call(name: "A", age: -1, role: "x")

      expect(result.errors.to_h).to eql(
        name: ["size cannot be less than 2"],
        age: ["must be greater than 0"]
      )
    end
  end

  describe "interleaved full and partial updates" do
    it "lets both roles process a full valid payload" do
      admin_result = admin.call(name: "Ada", age: 36, role: "owner")
      member_result = member.call(name: "Ada", age: 36)

      expect(admin_result).to be_success
      expect(admin_result.to_h).to eql(name: "Ada", age: 36, role: "owner")
      expect(member_result).to be_success
      expect(member_result.to_h).to eql(name: "Ada", age: 36)
    end

    it "keeps base predicates on a partial update" do
      result = member.call(age: -5)

      expect(result).to be_failure
      expect(result.errors.to_h).to eql(age: ["must be greater than 0"])
    end

    it "treats omitted required keys as allowed on a partial update" do
      result = member.call(name: "Ada")

      expect(result).to be_success
      expect(result.to_h).to eql(name: "Ada")
    end

    it "accepts an empty payload as a no-op partial update" do
      expect(member.call({})).to be_success
      expect(member.call({}).to_h).to eql({})
    end

    it "rejects a non-permitted key even when the rest of the payload is valid" do
      result = member.call(name: "Ada", age: 36, role: "member")

      expect(result).to be_failure
      expect(result.errors.to_h).to eql(role: ["is not allowed"])
      expect(result.to_h).to eql(name: "Ada", age: 36)
    end

    it "reports every rule that a mixed payload trips" do
      result = admin.call(name: "A", age: 0)

      expect(result.errors.to_h).to eql(
        name: ["size cannot be less than 2"],
        age: ["must be greater than 0"]
      )
    end

    it "handles full and partial calls back-to-back without cross-contamination" do
      aggregate_failures "interleaved sequence" do
        expect(admin.call(name: "Ada", age: 1, role: "r")).to be_success
        expect(member.call(name: "Ada")).to be_success
        expect(member.call(role: "r")).to be_failure
        expect(admin.call(age: 2)).to be_success
        expect(profile_schema.call(name: "Ada")).to be_failure
      end
    end
  end

  describe "unregistered caller" do
    it "raises rather than falling back to a wider schema" do
      expect { profile_schema.for_role(:guest) }
        .to raise_error(
          Dry::Schema::Extensions::RoleViews::UnknownRoleError,
          "unknown role :guest. Registered roles: :admin, :member"
        )
    end

    it "does not register the role as a side effect" do
      expect { profile_schema.for_role(:guest) rescue nil }
        .not_to change { profile_schema.role?(:guest) }.from(false)
    end
  end

  describe "ad-hoc views" do
    it "builds a view without registering it" do
      ad_hoc = profile_schema.view(:role)

      expect(profile_schema.role?(:role)).to be(false)
      expect(ad_hoc.key_map.to_dot_notation).to eql(%w[role])
      expect(ad_hoc.call(role: "x")).to be_success
      expect(ad_hoc.call(name: "Ada")).to be_failure
    end
  end

  describe "rules and values actually applied" do
    it "keeps only the permitted rule set but preserves every base predicate" do
      expect(profile_schema.rules.keys).to eql(%i[name age role])
      expect(admin.rules.keys).to eql(%i[name age role])
      expect(member.rules.keys).to eql(%i[name age])

      predicates = member.to_ast.flatten.grep(Symbol)
      expect(predicates).to include(:filled?, :str?, :min_size?, :int?, :gt?)
      expect(predicates).not_to include(:role)
    end

    it "compiles inherited required keys as optional (implication) rules" do
      member_ast = member.to_ast
      head_ops = member_ast.last.map(&:first)

      expect(head_ops).to all(eq(:implication))
      expect(profile_schema.to_ast.last.map(&:first)).to include(:and)
    end

    it "records the rules fired and the coerced values for a partial update" do
      result = member.call("age" => "42")

      expect(result).to be_success
      expect(result.to_h).to eql(age: 42)
      expect(result.errors.to_h).to eql({})
    end

    it "records the exact failures for an invalid partial update" do
      result = member.call("name" => "A", "age" => "-5")

      expect(result).to be_failure
      expect(result.errors.to_h).to eql(
        name: ["size cannot be less than 2"],
        age: ["must be greater than 0"]
      )
      expect(result.to_h).to eql(name: "A", age: -5)
    end
  end
end
