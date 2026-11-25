# frozen_string_literal: true

module Grape
  class Entity
    module Disclosure
      # Where an entity instance sits in the output tree of one representation.
      #
      # +path+ is made of output keys and collection indexes in output order.
      # An order rendered as the second item of the +orders+ collection of the
      # first group has +[:groups, 0, :orders, 1]+.
      #
      # The occurrence is what makes repeated references safe: a policy may
      # return a different scope for the same object when it appears at two
      # different paths.
      class Occurrence
        attr_reader :path, :group, :index

        def initialize(path: [], collection: nil)
          @path = path.map { |part| normalize_part(part) }.freeze
          @collection = collection.nil? ? @path.last.is_a?(Integer) : collection
          @index = @collection ? @path.last : nil
          @group = @path[group_position]
          freeze
        end

        def self.root
          new(path: [], collection: false)
        end

        def self.from_path(path, collection: nil)
          new(path: Array(path), collection: collection)
        end

        def collection?
          @collection
        end

        def root?
          path.empty?
        end

        def group_path
          collection? ? path[0...-1] : path
        end

        # The output key holding this occurrence. For a collection item it is
        # the key of the collection, for a nested object its own key, and nil
        # for the root occurrence.
        def field
          return path[-2] if collection? && path.length >= 2
          return path[-1] unless collection?

          nil
        end

        def to_h
          {
            path: path,
            group: group,
            group_path: group_path,
            index: index,
            collection: collection?
          }
        end

        def ==(other)
          other.is_a?(Occurrence) &&
            path == other.path &&
            collection? == other.collection?
        end
        alias eql? ==

        def hash
          [path, collection?].hash
        end

        def inspect
          "#<#{self.class.name} path=#{path.inspect} group=#{group.inspect} index=#{index.inspect}>"
        end

        private

        # Keys keep their original type: entity keys are symbols, while a
        # configured root name may be a String. Paths must compare equal to the
        # payload keys they locate.
        def normalize_part(part)
          part.frozen? ? part : part.dup.freeze
        end

        # The key holding this occurrence in its parent. For a collection item
        # that is the collection key (path[-2]); for a nested object it is the
        # object's own path. The root has no group.
        def group_position
          return -1 if path.empty?

          collection? && path.length >= 2 ? -2 : -1
        end
      end
    end
  end
end
