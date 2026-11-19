require 'set'

module Flipper
  module Policy
    # Public: An immutable, in-memory list of employees the preflight evaluates
    # gate combinations against. It never reaches into any adapter, so it cannot
    # influence a live flag.
    class Roster
      include Enumerable

      def initialize(employees = [])
        @employees = []
        @by_id = {}
        employees.each { |employee| add(employee) }
      end

      # Public: Add an employee (or anything Employee.wrap understands) to the
      # roster. Duplicate ids replace the earlier entry so the roster keeps one
      # record per employee.
      def add(object, properties = {})
        employee = Employee.wrap(object, properties)

        unless @by_id.key?(employee.flipper_id)
          @by_id[employee.flipper_id] = employee
          @employees << employee
        end

        employee
      end

      def [](flipper_id)
        @by_id[flipper_id.to_s]
      end

      def each(&block)
        @employees.each(&block)
      end

      def size
        @employees.size
      end
      alias_method :count, :size

      def empty?
        @employees.empty?
      end

      def ids
        @employees.map(&:flipper_id)
      end

      # Public: The employees whose id appears in the given set of flipper ids.
      def with_ids(id_set)
        wanted = id_set.map(&:to_s).to_set
        @employees.select { |employee| wanted.include?(employee.flipper_id) }
      end

      # Public: The employees referenced by an id set but absent from the roster.
      # A gate can name an actor the approver did not model; that gap is surfaced
      # rather than silently dropped.
      def missing_ids(id_set)
        known = @by_id.keys.to_set
        id_set.map(&:to_s).reject { |id| known.include?(id) }.uniq
      end

      def inspect
        "#<#{self.class.name} size=#{size}>"
      end
    end
  end
end
