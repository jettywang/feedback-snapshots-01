module Flipper
  module Policy
    # Public: Something the preflight cannot resolve on its own. The preflight
    # never guesses: these are handed to the approver, who decides whether the
    # dependency would widen the audience.
    #
    # :kind is one of:
    #   :unknown_function   - an expression uses a function this Flipper does
    #                         not know (e.g. shipped by a newer release); Flipper
    #                         keeps that gate closed at runtime.
    #   :missing_property   - an expression reads a property some roster
    #                         employees do not have.
    #   :unregistered_group- a group gate names a group that is not registered.
    #   :percentage_of_time - a non-0/100 time rollout is probabilistic, so no
    #                         fixed employee set can be computed.
    #   :unmodeled_actor    - an actor gate names an id absent from the roster.
    UnknownDependency = Struct.new(:kind, :detail, :feature, keyword_init: true) do
      def to_h
        { kind: kind, detail: detail, feature: feature }
      end

      def explain
        case kind
        when :unknown_function
          "expression function #{detail.inspect} is not available in this Flipper; the gate stays closed until it is"
        when :missing_property
          "expression reads property #{detail.inspect} that not every roster employee has"
        when :unregistered_group
          "group #{detail.inspect} is not registered, so Flipper matches no one for it"
        when :percentage_of_time
          "#{detail}% of time is probabilistic; the affected employees cannot be enumerated"
        when :unmodeled_actor
          "actor #{detail.inspect} is enabled but is not in the supplied roster"
        else
          "#{kind}: #{detail}"
        end
      end
    end
  end
end
