require 'rollbar/util'

module Rollbar
  # A destination is an independent egress for a report. Each one defines:
  #
  # * +sender+: any object responding to +#call(payload, destination)+ that
  #   performs the actual delivery (HTTP POST, an internal on-call API, an
  #   in-memory collector for tests, ...).
  # * +data_scope+: the sections of the canonical payload this destination is
  #   allowed to receive. Sections outside of the scope are removed from the
  #   destination's own copy before its transforms run, so data that is not
  #   permitted can never reach that egress.
  # * +transform+: handlers applied only to this destination's copy of the
  #   payload. Because every destination works on its own deep copy, mutating
  #   one view never changes the representation another destination sends.
  class Destination
    # Sections that can be individually allowed or denied for a destination.
    SECTIONS = [:request, :person, :extra, :custom].freeze

    attr_accessor :name, :sender
    attr_reader :transform

    def initialize(name = nil, sender = nil, permitted_sections = nil)
      @name = name
      @sender = sender
      @permitted_sections = normalize_sections(permitted_sections)
      @transform = []
    end

    # Deep copies the procs/arrays so a cloned configuration never shares
    # mutable transform state with its parent.
    def initialize_copy(orig)
      super
      @transform = Rollbar::Util.deep_copy(orig.transform)
      @permitted_sections = Rollbar::Util.deep_copy(orig.permitted_sections)
    end

    def transform=(*handlers)
      @transform = Array(handlers).flatten
    end

    def add_transform(handler = nil, &block)
      handler ||= block
      @transform << handler if handler
      handler
    end

    # Accepts either an allowlist of sections (+:request+, +:person+,
    # +:extra+, +:custom+) or +:all+ / +nil+ to keep every section.
    def permitted_sections=(sections)
      @permitted_sections = normalize_sections(sections)
    end

    def permitted_sections
      @permitted_sections || SECTIONS.dup
    end

    def permits?(section)
      permitted_sections.include?(section.to_sym)
    end

    def data_scope
      permitted_sections
    end

    def deliver(payload)
      sender.call(payload, self)
    end

    private

    def normalize_sections(sections)
      return nil if sections.nil?

      list = Array(sections).flatten.map(&:to_sym)
      return SECTIONS.dup if list.include?(:all)

      list.keep_if { |section| SECTIONS.include?(section) }
    end
  end
end
