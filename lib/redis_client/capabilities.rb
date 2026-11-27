# frozen_string_literal: true

class RedisClient
  # Raised when a command is not part of the capability scope granted for a
  # checkout. The check happens entirely on the client side, before anything is
  # written to the socket, so the offending command is never sent.
  #
  # Only the command name is exposed: command arguments can contain private
  # parameters and are deliberately kept out of the error message.
  class CapabilityDeniedError < Error
    include Final

    attr_reader :command_name

    def initialize(command_name, message = nil)
      @command_name = command_name
      super(message || "Command #{command_name.inspect} is not allowed by the capabilities granted for this checkout")
    end
  end

  # A capability scope: the set of Redis commands a caller is allowed to issue
  # during a single checkout.
  #
  # The policy only ever inspects command names (e.g. +GET+, +SET+); command
  # arguments are never passed to it, which lets callers keep private parameters
  # to themselves.
  #
  #   RedisClient::Capabilities.new(%w[GET SET])           # explicit allow list
  #   RedisClient::Capabilities.new(:all)                 # every command
  #   RedisClient::Capabilities.new { |name| name.start_with?("H") } # custom policy
  class Capabilities
    class << self
      def build(scope)
        if scope.is_a?(Capabilities)
          scope
        else
          new(scope)
        end
      end
    end

    def initialize(scope = nil, &block)
      if block
        if scope
          raise ArgumentError, "capabilities can't be defined with both a scope and a block"
        end

        @policy = block
      elsif scope.nil? || scope == :all || scope == "all" || scope == "ALL"
        @policy = nil
      elsif scope.is_a?(Array)
        allowed = scope.map { |command| normalize_name(command) }.freeze
        @policy = ->(command_name) { allowed.include?(command_name) }
      elsif scope.respond_to?(:call)
        @policy = scope
      else
        raise ArgumentError, "capabilities must be an Array of command names, :all, or a callable, got: #{scope.inspect}"
      end
    end

    # Whether a fully built command is allowed. Only the command name is used.
    def allow_command?(command)
      allow?(normalize_name(command))
    end

    # Whether a command name is allowed. The callable receives the normalized
    # upper case command name and nothing else.
    def allow?(command_name)
      return true if @policy.nil?

      @policy.call(command_name)
    end

    private

    # Accept either a bare command name ("get", :GET) or a full command (["GET", ...]).
    def normalize_name(command)
      command = command.first if command.is_a?(Array)
      command.to_s.upcase
    end
  end

  # The receipt of a single checkout. It records every authorization decision
  # taken while the capabilities are in effect, and is handed back to the caller
  # alongside the checked out client.
  #
  # A receipt only stores command names, never arguments, so it can be logged or
  # audited without exposing private parameters.
  class CapabilityReceipt
    attr_reader :capabilities, :approved, :denied

    def initialize(capabilities)
      @capabilities = capabilities
      @approved = []
      @denied = []
    end

    # Authorize one command, recording the decision. Raises
    # CapabilityDeniedError when the command is outside the granted scope.
    def authorize!(command)
      name = command.first.to_s.upcase
      if @capabilities.allow?(name)
        @approved << name
      else
        @denied << name
        raise CapabilityDeniedError.new(name)
      end
    end

    # Authorize a whole batch (pipeline or transaction) before any of it is sent.
    # The batch is decided as a whole: if a single command is non compliant the
    # whole batch is rejected and nothing is written to the connection.
    def authorize_batch!(commands)
      names = commands.map { |command| command.first.to_s.upcase }
      rejected = names.reject { |name| @capabilities.allow?(name) }

      unless rejected.empty?
        @denied.concat(rejected)
        raise CapabilityDeniedError.new(rejected.first)
      end

      @approved.concat(names)
      names
    end
  end
end
