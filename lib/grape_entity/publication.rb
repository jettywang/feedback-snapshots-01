# frozen_string_literal: true

module Grape
  class Entity
    # Opt-in publication contract for review-grade Entity output.
    #
    # Formatting and commit are separate phases. A field failure observed while
    # formatting is recorded, but nothing is delivered until the commit phase
    # confirms the allowlist and every mandatory field. A rejected single
    # object exposes only the last retained representation, never the partial
    # hash built during the failed attempt.
    module Publication
      SESSION_KEY = :grape_entity_publication_session

      class << self
        def current_session
          Thread.current[SESSION_KEY]
        end

        def with_session(session)
          previous = Thread.current[SESSION_KEY]
          Thread.current[SESSION_KEY] = session
          yield
        ensure
          Thread.current[SESSION_KEY] = previous
        end

        def session?
          !current_session.nil?
        end

        # Wraps an exposure's value computation in publication mode. Without a
        # session this is a no-op, so the default serialization path is
        # unchanged.
        def wrap(exposure, options)
          session = current_session
          return yield unless session

          path = publication_path(options)
          return yield if path.empty?

          unless session.allowed?(path)
            session.record_excluded(path, exposure)
            return OMITTED
          end

          begin
            result = yield
            session.record_present(path)
            result
          rescue StandardError => e
            session.record_failure(path, exposure, e)
            session.replacement_for(path)
          end
        end

        def publication_path(options)
          Array(options[:attr_path]).map(&:to_sym)
        end

        def omitted?(value)
          value.equal?(OMITTED)
        end
      end
    end
  end
end

require 'grape_entity/publication/codes'
require 'grape_entity/publication/omitted'
require 'grape_entity/publication/error'
require 'grape_entity/publication/event'
require 'grape_entity/publication/field_failure'
require 'grape_entity/publication/session'
require 'grape_entity/publication/declaration'
require 'grape_entity/publication/ledger'
require 'grape_entity/publication/result'
require 'grape_entity/publication/batch_result'
require 'grape_entity/publication/executor'
