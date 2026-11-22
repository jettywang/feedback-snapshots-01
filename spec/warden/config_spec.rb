# encoding: utf-8
# frozen_string_literal: true
RSpec.describe Warden::Config do

  before(:each) do
    @config = Warden::Config.new
  end

  it "should behave like a hash" do
    @config[:foo] = :bar
    expect(@config[:foo]).to eq(:bar)
  end

  it "should provide hash accessors" do
    @config.failure_app = :foo
    expect(@config[:failure_app]).to eq(:foo)
    @config[:failure_app] = :bar
    expect(@config.failure_app).to eq(:bar)
  end

  it "should allow to read and set default strategies" do
    @config.default_strategies :foo, :bar
    expect(@config.default_strategies).to eq([:foo, :bar])
  end

  it "should allow to silence missing strategies" do
    @config.silence_missing_strategies!
    expect(@config.silence_missing_strategies?).to eq(true)
  end

  it "should set the default_scope" do
    expect(@config.default_scope).to eq(:default)
    @config.default_scope = :foo
    expect(@config.default_scope).to eq(:foo)
  end

  it "should merge given options on initialization" do
    expect(Warden::Config.new(:foo => :bar)[:foo]).to eq(:bar)
  end

  it "should setup defaults with the scope_defaults method" do
    c = Warden::Config.new
    c.scope_defaults :foo, :strategies => [:foo, :bar], :store => false
    expect(c.default_strategies(:scope => :foo)).to eq([:foo, :bar])
    expect(c.scope_defaults(:foo)).to eq(store: false)
  end

  describe "scope inheritance" do
    it "should default to no inheritance rules" do
      expect(@config[:scope_inheritance]).to eq({})
      expect(@config.inherited_scope_for(:support)).to be_nil
      expect(@config.scope_inheritance_chain(:support)).to eq([])
    end

    it "should declare a directional rule with positional arguments" do
      @config.inherit_scope :support, :default
      expect(@config.inherited_scope_for(:support)).to eq(:default)
      expect(@config.scope_inheritance_chain(:support)).to eq([:default])
    end

    it "should declare a directional rule with the :from option" do
      @config.inherit_scope :support, :from => :default
      expect(@config.inherited_scope_for(:support)).to eq(:default)
    end

    it "should declare several rules at once with a hash" do
      @config.inherit_scope :support => :default, :auditor => :admin
      expect(@config.inherited_scope_for(:support)).to eq(:default)
      expect(@config.inherited_scope_for(:auditor)).to eq(:admin)
    end

    it "should coerce string scope names to symbols" do
      @config.inherit_scope "support", "default"
      expect(@config[:scope_inheritance]).to eq(:support => :default)
    end

    it "should not infer the reverse direction" do
      @config.inherit_scope :support, :default
      expect(@config.inherited_scope_for(:default)).to be_nil
      expect(@config.scope_inheritance_chain(:default)).to eq([])
    end

    it "should follow a declared chain nearest source first" do
      @config.inherit_scope :support => :employee, :employee => :default
      expect(@config.scope_inheritance_chain(:support)).to eq([:employee, :default])
      expect(@config.scope_inheritance_chain(:employee)).to eq([:default])
    end

    it "should replace a previously declared source when redeclared" do
      @config.inherit_scope :support, :default
      @config.inherit_scope :support, :employee
      expect(@config.inherited_scope_for(:support)).to eq(:employee)
    end

    it "should deep copy the rules when the config is duplicated" do
      @config.inherit_scope :support, :default
      copy = @config.dup
      copy[:scope_inheritance][:support] = :other
      expect(@config.inherited_scope_for(:support)).to eq(:default)
      expect(copy.inherited_scope_for(:support)).to eq(:other)
    end

    it "should reject a self inheritance rule" do
      expect {
        @config.inherit_scope :support, :support
      }.to raise_error(Warden::InvalidScopeInheritance, /cannot inherit its own identity/)
    end

    it "should reject an unknown rule with a non-symbol source" do
      expect {
        @config.inherit_scope :support, Object.new
      }.to raise_error(Warden::InvalidScopeInheritance, /scope inherited from/)
    end

    it "should reject an unknown rule with a non-symbol target" do
      expect {
        @config.inherit_scope Object.new, :default
      }.to raise_error(Warden::InvalidScopeInheritance, /inheriting scope/)
    end

    it "should reject a rule missing its source scope" do
      expect {
        @config.inherit_scope :support
      }.to raise_error(Warden::InvalidScopeInheritance, /scope inherited from/)
    end

    it "should reject a blank scope name" do
      expect {
        @config.inherit_scope :support, ""
      }.to raise_error(Warden::InvalidScopeInheritance, /cannot be blank/)
    end

    it "should reject a direct cycle at configuration time" do
      @config.inherit_scope :support, :default
      expect {
        @config.inherit_scope :default, :support
      }.to raise_error(Warden::InvalidScopeInheritance, /cycle detected/)
    end

    it "should reject a longer cycle at configuration time" do
      @config.inherit_scope :a => :b, :b => :c
      expect {
        @config.inherit_scope :c, :a
      }.to raise_error(Warden::InvalidScopeInheritance, /cycle detected/)
    end

    it "should leave unrelated rules untouched when one declaration is invalid" do
      @config.inherit_scope :support, :default
      begin
        @config.inherit_scope :admin, :admin
      rescue Warden::InvalidScopeInheritance
      end
      expect(@config.inherited_scope_for(:support)).to eq(:default)
      expect(@config.inherited_scope_for(:admin)).to be_nil
    end
  end
end
