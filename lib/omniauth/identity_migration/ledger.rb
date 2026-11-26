module OmniAuth
  module IdentityMigration
    # In-memory, append-only review record. Applications can replace this with
    # a persistent audit sink by passing their own object responding to #record.
    class Ledger
      include Enumerable

      attr_reader :entries

      alias events entries
      alias records entries

      def initialize
        @entries = []
        @sequence = 0
      end

      def record(attributes)
        @sequence += 1
        receipt = Receipt.new(attributes.merge(:sequence => @sequence))
        entries << receipt
        receipt
      end

      def each
        return enum_for(:each) unless block_given?

        entries.each { |entry| yield entry }
      end

      def deliveries
        select { |entry| entry.kind == 'login' }
      end

      def conversions
        select(&:converted?)
      end

      def pending_reviews
        select(&:pending_review?)
      end

      def last
        entries.last
      end

      def to_h
        {'entries' => entries.collect(&:to_h)}
      end
    end
  end
end
