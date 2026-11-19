# Extracts diff logic for consistency. Handles an array of
# Brakeman::Warnings or plain hash representations.
class Brakeman::Differ
  attr_reader :old_warnings, :new_warnings

  def initialize new_warnings, old_warnings
    @new_warnings = new_warnings
    @old_warnings = old_warnings
  end

  def diff
    new_remaining, fixed = subtract_by_identity(@new_warnings, @old_warnings)
    warnings = { :new => new_remaining, :fixed => fixed }

    second_pass(warnings)
    warnings
  end

  # Pair warnings by exact sink instance (identity + physical line).  Old
  # reports without sink metadata fall back to fingerprint + line.  Each old
  # warning can consume at most one new one, so a single old finding cannot
  # cancel out two new calls.
  def subtract_by_identity current, previous
    remaining_current = current.dup
    fixed = []

    previous.each do |old|
      old_key = instance_key(old)
      index = remaining_current.index { |warning| instance_key(warning) == old_key }

      if index
        remaining_current.delete_at index
      else
        fixed << old
      end
    end

    [remaining_current, fixed]
  end

  # Second pass cleans up warnings that changed line number only.  We pair by
  # stable structural identity (not line) using a multiset count, so pure
  # formatting moves disappear from the diff without collapsing two genuinely
  # separate calls that merely look alike.
  def second_pass(warnings)
    new_by_key = warnings[:new].group_by { |w| line_move_key(w) }
    fixed_by_key = warnings[:fixed].group_by { |w| line_move_key(w) }

    new_remaining = []
    fixed_remaining = []

    (new_by_key.keys | fixed_by_key.keys).each do |key|
      new_list = (new_by_key[key] || []).dup
      fixed_list = (fixed_by_key[key] || []).dup

      count = [new_list.length, fixed_list.length].min
      new_list.shift(count)
      fixed_list.shift(count)

      new_remaining.concat new_list
      fixed_remaining.concat fixed_list
    end

    warnings[:new] = new_remaining
    warnings[:fixed] = fixed_remaining
    warnings
  end

  # Line-independent identity used for the "moved lines only" cleanup.  For new
  # Warning objects this requires the same sink structure and exact sources.
  def line_move_key warning
    if warning.is_a?(Brakeman::Warning)
      warning.sink_move_key
    else
      # Old reports do not carry structural metadata.  Fingerprint is the only
      # available line-independent identity.
      warning[:sink_id] || warning[:fingerprint]
    end
  end

  # Exact physical occurrence.
  def instance_key warning
    if warning.is_a?(Brakeman::Warning)
      [warning.sink_id, warning.line]
    else
      [warning[:sink_id] || warning[:fingerprint], warning[:line]]
    end
  end

  # Exposed for callers that need the report-facing fingerprint.
  def fingerprint warning
    if warning.is_a?(Brakeman::Warning)
      warning.fingerprint
    else
      warning[:fingerprint]
    end
  end
end
