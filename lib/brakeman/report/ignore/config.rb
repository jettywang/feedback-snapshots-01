require 'set'
require 'json'

module Brakeman
  class IgnoreConfig
    attr_reader :shown_warnings, :ignored_warnings
    attr_accessor :file

    def initialize file, new_warnings
      @file = file
      @new_warnings = new_warnings
      @already_ignored = []
      @ignored_fingerprints = Set.new
      @used_fingerprints = Set.new
      @notes = {}
      @shown_warnings = @ignored_warnings = nil
      @changed = false
    end

    # Populate ignored_warnings and shown_warnings based on ignore
    # configuration
    def filter_ignored
      @shown_warnings = []
      @ignored_warnings = []
      @used_fingerprints = Set.new

      migrate_legacy_entries

      @new_warnings.each do |w|
        if ignored? w
          @ignored_warnings << w
        else
          @shown_warnings << w
        end
      end

      @shown_warnings
    end

    # Remove warning from ignored list
    def unignore warning
      @ignored_fingerprints.delete warning.fingerprint
      if @already_ignored.reject! { |w|w[:fingerprint] == warning.fingerprint }
        @changed = true
      end
    end

    # Determine if warning should be ignored
    def ignored? warning, mark_used: true
      fingerprint = warning.fingerprint

      @used_fingerprints << fingerprint if mark_used
      @ignored_fingerprints.include? fingerprint
    end

    def ignore warning
      @changed = true unless ignored? warning
      @ignored_fingerprints << warning.fingerprint
    end

    # Add note for warning
    def add_note warning, note
      @changed = true
      @notes[warning.fingerprint] = note
    end

    # Retrieve note for warning if it exists. Returns nil if no
    # note is found
    def note_for warning
      if warning.is_a? Warning
        fingerprint = warning.fingerprint
      else
        fingerprint = warning[:fingerprint]
      end

      @already_ignored.each do |w|
        if fingerprint == w[:fingerprint]
          return w[:note]
        end
      end

      nil
    end

    # The set of unused ignore entries
    def obsolete_fingerprints
      (@ignored_fingerprints - @used_fingerprints).to_a
    end

    def prune_obsolete
      obsolete = obsolete_fingerprints.to_set
      @ignored_fingerprints -= obsolete

      @already_ignored.reject! do |w|
        if obsolete.include?(w[:fingerprint])
          @changed = true
        end
      end
    end

    def already_ignored_entries_with_empty_notes
      @already_ignored.select { |i| i if i[:note].strip.empty? }
    end

    # Read configuration to file
    def read_from_file file = @file
      if File.exist? file
        begin
          @already_ignored = JSON.parse(File.read(file), :symbolize_names => true)[:ignored_warnings]
        rescue => e
          raise e, "\nError[#{e.class}] while reading brakeman ignore file: #{file}\n"
        end
      else
        Brakeman.alert "Could not find ignore configuration in #{file} (no file)"
        @already_ignored = []
      end

      @already_ignored.each do |w|
        @ignored_fingerprints << w[:fingerprint]
        @notes[w[:fingerprint]] = w[:note]

      end
    end

    # Save configuration to file
    def save_to_file warnings, file = @file
      warnings = warnings.map do |w|
        if w.is_a? Warning
          w = w.to_hash(absolute_paths: false)
        end

        w[:note] = @notes[w[:fingerprint]] || ""
        w
      end.sort_by { |w| [w[:fingerprint], w[:line] || 0] }

      output = {
        :ignored_warnings => warnings,
        :brakeman_version => Brakeman::Version
      }

      File.open file, "w" do |f|
        f.puts JSON.pretty_generate(output)
      end
    end

    # Older ignore files store the pre-sink-identity fingerprint.  When that
    # fingerprint now belongs to more than one real call, it is ambiguous and
    # must not be widened to cover any of them.  If exactly one warning matches
    # (for example because the other duplicate was removed), the entry can be
    # migrated safely and its note preserved.
    def migrate_legacy_entries
      @new_warnings ||= []

      @already_ignored.each do |entry|
        old = entry[:fingerprint]
        next if @new_warnings.any? { |warning| warning.fingerprint == old }

        candidates = @new_warnings.select do |warning|
          warning.legacy_fingerprint == old
        end

        # A group of structurally identical calls cannot be disambiguated by
        # the old fingerprint.  If every member is on the recorded line, the
        # only safe outcome is to leave the entry untouched (and obsolete).
        next if candidates.length > 1 && entry[:line].nil?

        if candidates.length > 1
          candidates = candidates.select { |warning| warning.line == entry[:line] }
          next unless candidates.length == 1
        end

        next unless candidates.length == 1

        # A recorded line that does not match the candidate means the entry
        # refers to a different (now removed) sink.  Do not move the exemption.
        next if entry[:line] && candidates.first.line != entry[:line]

        warning = candidates.first
        new_fingerprint = warning.fingerprint
        next if new_fingerprint == old

        @ignored_fingerprints.delete old
        @ignored_fingerprints << new_fingerprint
        entry[:fingerprint] = new_fingerprint

        @notes[new_fingerprint] = @notes.delete(old) if @notes.key? old
        @changed = true
      end
    end

    # Save old ignored warnings and newly ignored ones
    def save_with_old
      warnings = @ignored_warnings.dup

      # Only add ignored warnings not already ignored
      @already_ignored.each do |w|
        fingerprint = w[:fingerprint]

        existing = @ignored_warnings.find do |ignored_warning|
          ignored_warning.fingerprint == fingerprint ||
            (ignored_warning.respond_to?(:legacy_fingerprint) && ignored_warning.legacy_fingerprint == fingerprint)
        end

        unless existing
          warnings << w
        end
      end

      if @changed
        save_to_file warnings
      end
    end
  end
end
