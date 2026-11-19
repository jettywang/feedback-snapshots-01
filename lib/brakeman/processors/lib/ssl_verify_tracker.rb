require 'brakeman/processors/lib/basic_processor'

# Tracks SSL/TLS verification settings on connection objects and reports
# the effective state of the connection at the point it is used to send a
# request.
#
# The tracker never executes application code. It follows:
#
# - local/instance variable aliases and reassignments
#   (the same variable may point at different objects over time)
# - verify_mode=/use_ssl= assignments, including through aliases
# - settings supplied to Net::HTTP.new/start via option hashes
# - if/case branches by keeping every provable branch state
#
# Conclusions are only emitted when the state of the connection actually
# used by the request can be proven. Unknown branches stay unknown.
class Brakeman::SSLVerifyTracker < Brakeman::BasicProcessor

  SSL_VERIFY_NONE = s(:colon2, s(:colon2, s(:const, :OpenSSL), :SSL), :VERIFY_NONE)

  NET_HTTP = s(:colon2, s(:const, :Net), :HTTP)

  # Methods which send a request over an existing connection object.
  REQUEST_METHODS = [:get, :post, :put, :patch, :delete, :head, :options,
    :request, :request_get, :request_post, :request_put, :request_patch,
    :request_delete, :request_head, :request_options, :send_request,
    :get2, :post2, :get_response, :post_response].freeze

  # A single connection object (an abstract "instance" created in the
  # scanned code). Holds the verification state proven for the object so
  # far. Values may be plain sexps, or an :or sexp combining the states
  # reachable through different branches.
  class Connection
    attr_accessor :verify_mode, :use_ssl
    attr_reader :id

    def initialize id
      @id = id
      @verify_mode = nil
      @use_ssl = nil
    end

    def verify_none?
      concrete?(@verify_mode) and @verify_mode == SSL_VERIFY_NONE
    end

    def unknown_verify?
      @verify_mode.nil? or branched?(@verify_mode)
    end

    def uses_ssl?
      concrete?(@use_ssl) and @use_ssl.node_type == :true
    end

    private

    def concrete? state
      Sexp === state and not branched?(state)
    end

    def branched? state
      state.node_type == :or
    end
  end

  def initialize tracker
    super
    @findings = []
    @modeled_calls = []
    @variables = {}
    @connections = {}
    @next_connection_id = 0
    @suppressed_connections = []
    @current_location = nil
  end

  # Findings collected while processing. Each finding is a hash with
  # :call (the request/assignment sexp), :confidence, :message, and
  # :location keys.
  def findings
    @findings
  end

  # verify_mode=/use_ssl=/Net::HTTP.start calls that were modeled as part
  # of connection tracking, as [file, line] pairs. The check uses these to
  # avoid duplicating legacy syntactic warnings.
  def modeled_call_locations
    @modeled_calls.map do |call|
      [@current_location[:file].to_s, call.original_line || call.line]
    end
  end

  def process_source src, location
    @current_location = location
    @variables = {}
    @connections = {}
    @construction_ids = {}
    @next_connection_id = 0
    @suppressed_connections = []
    @modeled_calls = []
    @findings = []
    process src
    @findings
  end

  def process_defn exp
    process_all exp.body if exp.method_length > 0
    exp
  end

  alias process_defs process_defn

  def process_block exp
    process_default exp
    exp
  end

  alias process_rlist process_block

  def process_lasgn exp
    bind_variable s(:lvar, exp.lhs), exp.rhs
    exp
  end

  def process_iasgn exp
    bind_variable s(:ivar, exp.lhs), exp.rhs
    exp
  end

  def process_attrasgn exp
    if exp.method == :verify_mode=
      record_verify_mode exp
    elsif exp.method == :use_ssl=
      record_use_ssl exp
    else
      process_default exp
    end

    exp
  end

  def process_if exp
    process exp.condition if sexp? exp.condition

    # A missing clause (nil then for `unless`, nil else for a one-sided
    # `if`) is an implicit branch that leaves every state unchanged. It
    # must be retained so a one-sided assignment is not treated as the
    # state for all following code.
    branches = [
      sexp?(exp.then_clause) ? exp.then_clause : :implicit,
      sexp?(exp.else_clause) ? exp.else_clause : :implicit
    ]

    process_branched branches

    exp
  end

  def process_case exp
    process exp[1] if sexp? exp[1]

    branches = []

    exp.each_sexp do |node|
      branches << node if node.node_type == :when
    end

    # A case/when without an else falls through with the state unchanged.
    branches << (sexp?(exp.else_clause) ? exp.else_clause : :implicit)

    process_branched branches

    exp
  end

  def process_iter exp
    call = exp.block_call

    if call? call and call.target == NET_HTTP and call.method == :start
      @modeled_calls << call
      connection = build_start_connection(call)

      if connection.verify_none?
        # The dangerous configuration is proven on the start call itself.
        # The block runs on the same connection, so report the start call
        # rather than each request made inside the block.
        add_finding call, :high, "SSL certificate verification was bypassed"
        @suppressed_connections << connection.id
      end

      run_block exp, connection
    elsif call? call and (connection = find_connection(call.target))
      run_block exp, connection
    else
      process_default exp
    end

    exp
  end

  def process_call exp
    return exp if process_call_defn? exp

    if exp.target == NET_HTTP and exp.method == :start
      @modeled_calls << exp
      check_class_start exp
      return exp
    end

    if REQUEST_METHODS.include?(exp.method)
      check_request exp
    end

    process_default exp

    exp
  end

  private

  def run_block exp, connection
    # Net::HTTP.start(...) with a block is handled by process_iter, so the
    # block call itself is not reprocessed. For other calls (e.g. an
    # existing connection's start), still walk the call arguments.
    call = exp.block_call
    unless call.target == NET_HTTP and call.method == :start
      process_call_args call
    end

    # block_args is s(:args, :name, ...); each entry after the type tag
    # is the local variable name bound to the yielded connection.
    exp.block_args.sexp_body.each do |arg_name|
      next unless arg_name.is_a? Symbol

      @variables[s(:lvar, arg_name)] = connection.id
    end

    process exp.block if sexp? exp.block
  end

  # Bind a variable to the connection object its value refers to. A new
  # object is created for fresh construction; an alias points at the same
  # object; an unresolvable value gets its own unknown object so later
  # assignments are still tracked per variable.
  def bind_variable variable, rhs
    return unless sexp? rhs

    process rhs

    if net_http_new?(rhs)
      connection = new_connection
      apply_options connection, rhs
      @variables[variable] = connection.id
    elsif id = variable_id(rhs)
      @variables[variable] = id
    else
      connection = new_connection
      @variables[variable] = connection.id
    end
  end

  def record_verify_mode exp
    value = branch_value(exp.first_arg)

    connection = find_connection(exp.target)
    return unless connection

    # Only assignments that update a tracked connection suppress the legacy
    # syntactic check; unresolved receivers (e.g. self) stay visible to it.
    @modeled_calls << exp
    connection.verify_mode = value
  end

  def record_use_ssl exp
    value = branch_value(exp.first_arg)

    connection = find_connection(exp.target)
    return unless connection

    @modeled_calls << exp
    connection.use_ssl = value
  end

  # Reduce an assignment value to a concrete sexp, or an :or sexp when it
  # is selected by an inline if/unless. A missing branch contributes nil so
  # the combined value is treated as unknown.
  def branch_value value
    process value if sexp? value

    if sexp?(value) and value.node_type == :if
      clauses = [
        sexp?(value.then_clause) ? value.then_clause : nil,
        sexp?(value.else_clause) ? value.else_clause : nil
      ]

      combine_across(clauses)
    else
      value
    end
  end

  def check_class_start exp
    connection = build_start_connection(exp)

    if connection.verify_none?
      add_finding exp, :high, "SSL certificate verification was bypassed"
    end
  end

  def check_request exp
    connection = find_connection(exp.target)
    return unless connection

    # A dangerous Net::HTTP.start(...) with a block is reported on the
    # start call itself, so requests inside that block are not repeated.
    return if @suppressed_connections.include? connection.id

    # The verify mode only matters when TLS is actually enabled. With no
    # proven use_ssl, or an explicit use_ssl=false, nothing dangerous can
    # be claimed about the request.
    return unless connection.uses_ssl?

    if connection.verify_none?
      add_finding exp, :high, "SSL certificate verification was bypassed"
    elsif connection.unknown_verify?
      add_finding exp, :medium, "SSL certificate verification settings could not be determined"
    end
  end

  def build_start_connection call
    connection = new_connection
    apply_options connection, call
    connection
  end

  # Pull verify_mode/use_ssl out of an option hash argument.
  def apply_options connection, call
    call.args.each do |arg|
      next unless hash? arg

      if value = hash_access(arg, :verify_mode)
        connection.verify_mode = value
      end

      if value = hash_access(arg, :use_ssl)
        connection.use_ssl = value
      end
    end
  end

  def add_finding call, confidence, message
    @findings << {
      :call => call,
      :confidence => confidence,
      :message => message,
      :location => @current_location
    }
  end

  def net_http_new? exp
    call?(exp) and exp.target == NET_HTTP and exp.method == :new
  end

  def new_connection
    connection = Connection.new(@next_connection_id)
    @connections[@next_connection_id] = connection
    @next_connection_id += 1
    connection
  end

  def find_connection variable
    id = variable_id(variable)
    id && @connections[id]
  end

  def variable_id exp
    return unless sexp? exp

    if node_type? exp, :lvar, :ivar
      @variables[exp]
    elsif net_http_new?(exp)
      @construction_ids ||= {}
      @construction_ids[exp] ||= begin
        connection = new_connection
        apply_options connection, exp
        connection.id
      end
    end
  end

  # Run each branch on an independent state copy, then merge so every
  # provable branch is retained for the code following the conditional.
  # An :implicit branch means the state is left unchanged.
  def process_branched branches
    base = take_snapshot
    branch_snapshots = []

    branches.each do |branch|
      if branch == :implicit
        # The implicit branch leaves the pre-condition state unchanged.
        restore_snapshot base
        branch_snapshots << take_snapshot
        next
      end

      next unless sexp? branch

      restore_snapshot base
      process branch
      branch_snapshots << take_snapshot
    end

    restore_snapshot merge_snapshots(branch_snapshots)
  end

  def take_snapshot
    {
      :variables => @variables.dup,
      :connections => @connections.transform_values { |connection| copy_connection(connection) }
    }
  end

  def restore_snapshot snapshot
    @variables = snapshot[:variables].dup
    @connections = snapshot[:connections].transform_values { |connection| copy_connection(connection) }
  end

  def merge_snapshots branches
    variables = {}
    connections = {}

    # Every reachable branch contributes its view of each connection.
    # A state present in one branch but absent (nil) in another becomes
    # unknown rather than being silently dropped.
    all_ids = branches.flat_map { |snapshot| snapshot[:connections].keys }.uniq

    all_ids.each do |id|
      merged = Connection.new(id)
      states = branches.map { |snapshot| snapshot[:connections][id] }.compact

      # Combine the per-attribute states across branches. When the
      # attribute count differs between branches (one branch never sets
      # it and leaves it nil) the post-branch state cannot be proven.
      merged.verify_mode = combine_across(states.map(&:verify_mode))
      merged.use_ssl = combine_across(states.map(&:use_ssl))

      connections[id] = merged
    end

    branches.each do |snapshot|
      snapshot[:variables].each do |variable, id|
        variables[variable] ||= id
      end
    end

    { :variables => variables, :connections => connections }
  end

  # Combine an attribute's value across all reachable branches.
  #
  # Returns the shared value when every branch agrees (including all-nil,
  # meaning it was never set). If branches disagree, or some branch set a
  # concrete value while another left it unset, the result is wrapped in an
  # :or sexp so the state is treated as unknown rather than guessed.
  def combine_across states
    return nil if states.empty?
    return nil if states.all?(&:nil?)

    known = states.compact
    first = known.first

    # A branch left the attribute unset: the post-branch value is only
    # provable if every branch that sets it agrees, AND there is no
    # unset branch. An unset branch means the value is unconstrained.
    if known.length < states.length
      return s(:or, first, s(:nil)).line(-2)
    end

    return first if known.all? { |state| state == first }

    known.reduce { |combined, state| combined.combine(state) }
  end

  def copy_connection connection
    copy = Connection.new(connection.id)
    copy.verify_mode = connection.verify_mode.deep_clone if connection.verify_mode
    copy.use_ssl = connection.use_ssl.deep_clone if connection.use_ssl
    copy
  end
end
