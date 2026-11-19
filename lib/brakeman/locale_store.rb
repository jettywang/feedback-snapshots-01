require 'yaml'
require 'date'

# Statically parses translation locale files (config/locales/*.yml) without
# executing any application or i18n code.
#
# The store keeps, for every fully-qualified dotted key:
#
#   * the raw translation value for every locale that defines it
#   * the interpolation placeholders (e.g. %{name}) each value references
#   * whether the key carries HTML semantics (a "_html" / ".html" suffix)
#   * the source file and line where the value was defined
#
# It deliberately models only what can be resolved from the files themselves so
# checks can reason about a key's capability (escaped text vs. trusted HTML)
# independently of the helper that eventually renders it.
class Brakeman::LocaleStore
  # A single resolved translation entry.
  Entry = Struct.new(:key, :values, :html_key, :placeholders, :locations, keyword_init: true) do
    def initialize(key:, values: {}, html_key:, placeholders: Set.new, locations: {})
      super
    end

    def value_for(locale)
      values[locale]
    end
  end

  # Placeholder syntax used by I18n: %{name}
  PLACEHOLDER = /%\{([^}]+)\}/

  def initialize(app_tree)
    @app_tree = app_tree
    @entries = {}
    @parsed = false
    @parse_errors = []
  end

  attr_reader :parse_errors

  # Returns the Entry for a fully-qualified dotted key, or nil when no locale
  # file defines it.
  def [](dotted_key)
    parse!
    @entries[dotted_key.to_s]
  end

  def keys
    parse!
    @entries.keys
  end

  # Static capability of a key name itself, independent of whether the key is
  # defined. Rails treats keys ending in "_html" (or a ".html" segment) as
  # trusted HTML keys.
  def self.html_semantic_key?(dotted_key)
    name = dotted_key.to_s
    name.end_with?("_html", ".html") or name.split(".").last == "html"
  end

  private

  def parse!
    return if @parsed
    @parsed = true

    locale_files.each do |file_path|
      parse_file file_path
    end
  end

  def locale_files
    pattern = File.join(@app_tree.root, "config", "locales", "**", "*.{yml,yaml}")
    Dir.glob(pattern).sort.map do |absolute|
      @app_tree.file_path(@app_tree.relative_path(absolute))
    end
  rescue StandardError => e
    @parse_errors << e.message
    []
  end

  def parse_file(file_path)
    return unless file_path.exists?

    raw = file_path.read
    data = YAML.safe_load(raw, permitted_classes: [Symbol, Date, Time], aliases: true)
    return unless data.is_a? Hash

    data.each do |locale, tree|
      next unless tree.is_a? Hash
      flatten(locale.to_s, "", tree, raw, file_path)
    end
  rescue Psych::Exception, RuntimeError => e
    @parse_errors << "#{file_path.relative}: #{e.message}"
  end

  def flatten(locale, prefix, tree, raw, file_path)
    tree.each do |segment, value|
      dotted = prefix.empty? ? segment.to_s : "#{prefix}.#{segment}"

      if value.is_a? Hash
        flatten(locale, dotted, value, raw, file_path)
      else
        record_value(locale, dotted, value, raw, file_path)
      end
    end
  end

  def record_value(locale, dotted, value, raw, file_path)
    entry = @entries[dotted] ||= Entry.new(
      key: dotted,
      html_key: self.class.html_semantic_key?(dotted)
    )

    text = value.to_s
    entry.values[locale] = text
    entry.locations[locale] = {
      file: file_path,
      line: find_line(raw, text)
    }

    text.scan(PLACEHOLDER).each do |(placeholder)|
      entry.placeholders << placeholder.to_sym
    end
  end

  # Best-effort source line for a scalar value. Falls back to the file start
  # when the literal cannot be located (e.g. folded blocks).
  def find_line(raw, text)
    needle = text.to_s
    raw.each_line.with_index(1) do |line, number|
      return number if line.include?(needle)
    end
    1
  end
end
