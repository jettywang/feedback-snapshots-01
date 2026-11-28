# frozen_string_literal: true

require 'thread'

module WebMock
  # A TestScope gives a group of tests its own stub registry and request
  # registry, so matching, response rotation and request counts never leak
  # between groups that stub the same route, even when those groups run in
  # parallel.
  #
  # The active scope is kept in a thread-local (and therefore fiber-local)
  # stack. When no scope is active, WebMock falls back to its global
  # registries, preserving the historical behaviour.
  #
  #   WebMock::TestScope.activate do
  #     stub_request(:get, "www.example.com").to_return(body: "a")
  #     # ...stubs and recorded requests stay inside this block...
  #   end
  class TestScope
    STACK_KEY = :webmock_test_scope_stack
    private_constant :STACK_KEY

    @named_scopes = {}
    @registry_lock = Mutex.new

    class << self
      # Runs the given block with +scope+ as the currently active scope.
      # Scopes nest: the previously active scope is restored afterwards.
      def activate(scope = new)
        scope_stack.push(scope)
        begin
          yield scope
        ensure
          scope_stack.pop
        end
      end

      # Creates (or reuses, when +name+ is given) a scope and activates it
      # for the duration of the block.
      def create(name = nil)
        scope = name ? named(name) : new
        activate(scope) { yield scope }
      end

      def current
        scope_stack.last
      end

      def active?
        !scope_stack.empty?
      end

      # The active scope stack of the current thread, outermost first.
      def stack
        scope_stack.dup
      end

      def named(name)
        @registry_lock.synchronize do
          @named_scopes[name] ||= new
        end
      end

      def remove_named(name)
        @registry_lock.synchronize { @named_scopes.delete(name) }
      end

      # Closes every named scope and empties the current thread's stack.
      def reset!
        @registry_lock.synchronize { @named_scopes.clear }
        Thread.current[STACK_KEY] = nil
      end

      private

      def scope_stack
        Thread.current[STACK_KEY] ||= []
      end
    end

    attr_reader :stub_registry, :request_registry

    def initialize
      @stub_registry = StubRegistry.build
      @request_registry = RequestRegistry.build
      @shared_stubs = []
      @shared_lock = Mutex.new
    end

    # Marks a stub as shared with every nested scope activated inside this
    # one. Returns the stub so it can be registered inline.
    def share(stub)
      @shared_lock.synchronize do
        @shared_stubs << stub unless @shared_stubs.include?(stub)
      end
      stub
    end

    def shared_stubs
      @shared_lock.synchronize { @shared_stubs.dup }
    end

    # Stubs explicitly shared by this scope and by every scope above it on
    # the active stack, innermost first and without duplicates.
    def inherited_stubs
      self.class.stack.reverse.each_with_object([]) do |scope, stubs|
        scope.shared_stubs.each { |stub| stubs << stub unless stubs.include?(stub) }
      end
    end

    def reset!
      @stub_registry.reset!
      @request_registry.reset!
    end
  end
end
