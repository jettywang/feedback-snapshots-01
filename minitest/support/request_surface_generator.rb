# frozen_string_literal: true

# Deterministic request-surface generator for the WebMock regression tests.
#
# Client library upgrades often rewrite a request into another equivalent
# surface form: a host gains a default port, a query value is percent-encoded,
# repeated query items switch notation, header names change case. Each
# transformation here is one of the equivalence rules WebMock documents or
# implements, and every generated URI is a legal URI.
#
# The guards are the near misses. They differ by something WebMock treats as
# significant, such as the order of repeated scalar query items or the order
# of values in a form body array, and must keep failing to match.
module WebMockSurfaceRegression
  SEED = 20_261_129
  DEFAULT_VARIANTS = 10
  DEFAULT_PORTS = { "http" => 80, "https" => 443 }.freeze

  URI_EQUIVALENCE_RULES = %i[
    http_scheme_omitted
    host_case
    default_port
    root_trailing_slash
    path_percent_encoding
    query_key_percent_encoding
    query_value_space_encoding
    query_value_percent_encoding
    query_parameter_order
    repeated_query_array_notation
    repeated_query_array_order
  ].freeze

  HEADER_EQUIVALENCE_RULES = %i[
    header_name_case_and_underscore
    extra_unmatched_header
    header_value_array_order
    header_single_value_as_array
  ].freeze

  EQUIVALENCE_RULES = (URI_EQUIVALENCE_RULES + HEADER_EQUIVALENCE_RULES).freeze

  NON_EQUIVALENCE_RULES = %i[
    scheme_changed
    non_default_port
    path_encoded_slash
    path_plus_is_not_space
    path_case
    query_key_changed
    scalar_value_changed
    extra_query_parameter
    array_value_changed
    array_value_missing
    array_value_extra
    header_value_changed
    header_value_missing
  ].freeze

  Variant = Struct.new(:uri, :rules, keyword_init: true)
  HeaderVariant = Struct.new(:headers, :rules, keyword_init: true)

  module_function

  def rng(offset = 0, seed: SEED)
    Random.new(seed + offset)
  end

  def deep_dup(value)
    case value
    when Hash then value.each_with_object({}) { |(key, item), copy| copy[key] = deep_dup(item) }
    when Array then value.map { |item| deep_dup(item) }
    when String then value.dup
    else value
    end
  end

  # Sample model ----------------------------------------------------------

  def uri_sample(id, scheme: "http", host: "example.com", segments: [], scalars: [], array: nil)
    {
      id: id, kind: :uri, method: :get, scheme: scheme, host: host,
      segments: deep_dup(segments), scalars: deep_dup(scalars),
      array: deep_dup(array)
    }
  end

  # Scalar keys are unique in these samples. WebMock keeps only the last value
  # of a repeated scalar key in subscript notation, so that ordering is not an
  # allowed equivalence rule; it has a dedicated test instead.
  def uri_samples
    [
      uri_sample("uri-root-scalars", scalars: [["q", "a"], ["lang", "en"]]),
      uri_sample("uri-escaped-path", segments: ["b c", "~user"],
                 scalars: [["q", "b c"], ["lang", "A"]]),
      uri_sample("uri-reserved-path", scheme: "https", segments: ["x:y", "a@b"],
                 scalars: [["q", "~user"]]),
      uri_sample("uri-repeated-array", segments: ["a"], scalars: [["q", "a"]],
                 array: { name: "ids", values: %w[v0 v1] }),
      uri_sample("uri-indexed-many", segments: ["a", "b c"],
                 scalars: [["q", "b c"], ["lang", "en"]],
                 array: { name: "ids", values: (0...12).map { |i| "v#{i}" } })
    ].freeze
  end

  # Encoding --------------------------------------------------------------

  def encode_path_segment(segment, percent: false)
    encoded = segment.gsub(" ", "%20")
    return encoded unless percent

    index = encoded.index(/[A-Za-z0-9~:@]/)
    return encoded unless index

    encoded[0...index] + format("%%%02X", encoded[index].ord) + encoded[(index + 1)..]
  end

  def encode_query_key(key, percent: false)
    return key unless percent

    index = key.index(/[A-Za-z]/)
    return index.nil? ? key : key[0...index] + format("%%%02X", key[index].ord) + key[(index + 1)..]
  end

  def encode_query_value(value, space: :percent, percent: false)
    encoded = space == :plus ? value.gsub(" ", "+") : value.gsub(" ", "%20")
    return encoded unless percent

    index = encoded.index(/[A-Za-z~:@]/)
    return encoded unless index

    encoded[0...index] + format("%%%02X", encoded[index].ord) + encoded[(index + 1)..]
  end

  # Rendering -------------------------------------------------------------

  def canonical_choices(sample)
    pairs = sample[:scalars].map do |key, value|
      [encode_query_key(key), encode_query_value(value)]
    end
    if (array = sample[:array])
      array[:values].each do |value|
        pairs << ["#{array[:name]}[]", encode_query_value(value)]
      end
    end

    {
      prefix: "#{sample[:scheme]}://",
      host: sample[:host],
      port: "",
      segments: sample[:segments].map { |segment| encode_path_segment(segment) },
      root_slash: sample[:segments].empty?,
      query_pairs: pairs
    }
  end

  def render_choices(sample, choices)
    path = if sample[:segments].empty?
             choices[:root_slash] ? "/" : ""
           else
             "/" + choices[:segments].join("/")
           end
    query = choices[:query_pairs].map { |key, value| "#{key}=#{value}" }.join("&")
    "#{choices[:prefix]}#{choices[:host]}#{choices[:port]}#{path}" \
      "#{query.empty? ? '' : '?'}#{query}"
  end

  def canonical_uri(sample, choices: canonical_choices(sample))
    render_choices(sample, choices)
  end

  # Equivalence-rule variants --------------------------------------------

  def generated_variant(sample, random)
    rules = []

    prefix = if sample[:scheme] == "http" && random.rand(3).zero?
               rules << :http_scheme_omitted
               ""
             else
               "#{sample[:scheme]}://"
             end

    host = case random.rand(3)
           when 0 then sample[:host]
           when 1 then sample[:host].upcase
           else sample[:host].split(".").map(&:capitalize).join(".")
           end
    rules << :host_case if host != sample[:host]

    port = if random.rand(2).zero?
             ""
           else
             rules << :default_port
             ":#{DEFAULT_PORTS.fetch(sample[:scheme])}"
           end

    segments = sample[:segments].map do |segment|
      percent = random.rand(2).zero?
      rules << :path_percent_encoding if percent
      encode_path_segment(segment, percent: percent)
    end

    root_slash = sample[:segments].empty? ? random.rand(2).zero? : true
    rules << :root_trailing_slash if sample[:segments].empty? && root_slash

    pairs = sample[:scalars].map do |key, value|
      key_percent = random.rand(2).zero?
      value_percent = random.rand(2).zero?
      space = %i[percent plus][random.rand(2)]
      rules << :query_key_percent_encoding if key_percent
      rules << :query_value_percent_encoding if value_percent
      rules << :query_value_space_encoding if space == :plus && value.include?(" ")
      [
        encode_query_key(key, percent: key_percent),
        encode_query_value(value, space: space, percent: value_percent)
      ]
    end

    if (array = sample[:array])
      style = %i[unindexed indexed unindexed_pct indexed_pct][random.rand(4)]
      rules << :repeated_query_array_notation unless style == :unindexed
      array_pairs = array[:values].each_with_index.map do |value, index|
        key = case style
              when :unindexed then "#{array[:name]}[]"
              when :indexed then "#{array[:name]}[#{index}]"
              when :unindexed_pct then "#{array[:name]}%5B%5D"
              when :indexed_pct then "#{array[:name]}%5B#{index}%5D"
              end
        value_percent = random.rand(2).zero?
        rules << :query_value_percent_encoding if value_percent
        [key, encode_query_value(value, percent: value_percent)]
      end
      if random.rand(2).zero?
        array_pairs.shuffle!(random: random)
        rules << :repeated_query_array_order if array[:values].length > 1
      end
      pairs.concat(array_pairs)
    end

    if pairs.length > 1
      array_values_before = array ? array_item_values(pairs, array[:name]) : []
      pairs.shuffle!(random: random)
      if array && array_item_values(pairs, array[:name]) != array_values_before
        rules << :repeated_query_array_order
      end
      rules << :query_parameter_order
    end

    choices = {
      prefix: prefix, host: host, port: port, segments: segments,
      root_slash: root_slash, query_pairs: pairs
    }
    Variant.new(uri: render_choices(sample, choices), rules: rules.uniq)
  end

  # The offset is supplied by the caller (the sample position), not derived
  # from String#hash, so variant output is identical across Ruby processes.
  def generated_variants(sample, count: DEFAULT_VARIANTS, seed: SEED, offset: 0)
    random = rng(offset, seed: seed)
    Array.new(count) { generated_variant(sample, random) }
  end

  # Values of the repeated array items in the order they appear, whatever
  # notation the key uses.
  def array_item_values(pairs, name)
    prefix = "#{name}["
    pairs.select do |key, _|
      unencoded(key).start_with?(prefix) || key.start_with?(prefix)
    end.map(&:last)
  end

  # Guards ----------------------------------------------------------------

  def guard_variants(sample)
    canonical = canonical_choices(sample)
    guards = []

    if sample[:scalars].any?
      key, value = sample[:scalars].first

      changed = deep_dup(canonical)
      position = changed[:query_pairs].index { |pair_key, _| pair_key == key }
      if position
        changed[:query_pairs][position] = [key, "#{value}-x"]
        guards << [:scalar_value_changed, render_choices(sample, changed)]
      end

      changed = deep_dup(canonical)
      changed[:query_pairs] << ["extra", "1"]
      guards << [:extra_query_parameter, render_choices(sample, changed)]

      changed = deep_dup(canonical)
      position = changed[:query_pairs].index { |pair_key, _| pair_key == key }
      if position
        changed[:query_pairs][position] = ["#{key}_changed", changed[:query_pairs][position][1]]
        guards << [:query_key_changed, render_choices(sample, changed)]
      end
    end

    if (array = sample[:array])
      prefix = "#{array[:name]}[]"

      changed = deep_dup(canonical)
      positions = changed[:query_pairs].each_index.select do |index|
        changed[:query_pairs][index][0] == prefix
      end
      if positions.any?
        changed[:query_pairs].delete_at(positions.last)
        guards << [:array_value_missing, render_choices(sample, changed)]
      end

      changed = deep_dup(canonical)
      position = changed[:query_pairs].rindex { |pair_key, _| pair_key == prefix }
      if position
        changed[:query_pairs][position] = [prefix, "changed"]
        guards << [:array_value_changed, render_choices(sample, changed)]
      end

      changed = deep_dup(canonical)
      changed[:query_pairs] << [prefix, "extra"]
      guards << [:array_value_extra, render_choices(sample, changed)]
    end

    if sample[:segments].length > 1
      changed = deep_dup(canonical)
      changed[:segments] = sample[:segments][0...-2].map { |segment| encode_path_segment(segment) }
      joined = "#{encode_path_segment(sample[:segments][-2])}%2F" \
               "#{encode_path_segment(sample[:segments][-1])}"
      changed[:segments] << joined
      guards << [:path_encoded_slash, render_choices(sample, changed)]
    end

    if sample[:segments].any? { |segment| segment.include?(" ") }
      changed = deep_dup(canonical)
      changed[:segments] = changed[:segments].map { |segment| segment.gsub("%20", "+") }
      guards << [:path_plus_is_not_space, render_choices(sample, changed)]
    end

    if (segment = sample[:segments].find { |item| item =~ /[a-z]/ })
      changed = deep_dup(canonical)
      position = sample[:segments].index(segment)
      changed[:segments][position] = changed[:segments][position].sub(/[a-z]/) { |char| char.upcase }
      guards << [:path_case, render_choices(sample, changed)]
    end

    changed = deep_dup(canonical)
    changed[:port] = ":8080"
    guards << [:non_default_port, render_choices(sample, changed)]

    if sample[:scheme] == "http"
      changed = deep_dup(canonical)
      changed[:prefix] = "https://"
      guards << [:scheme_changed, render_choices(sample, changed)]
    end

    guards
  end

  # Header surface --------------------------------------------------------

  def header_sample
    {
      id: "header-representations",
      kind: :header,
      method: :get,
      uri: "http://example.com/headers",
      headers: [["X-Multi", %w[alpha beta]], ["X-Single", ["one"]]]
    }
  end

  def header_hash(headers)
    headers.each_with_object({}) { |(name, values), hash| hash[name] = deep_dup(values) }
  end

  def header_variants(sample = header_sample, count: DEFAULT_VARIANTS, seed: SEED)
    random = rng(11, seed: seed)
    Array.new(count) do
      rules = []
      headers = sample[:headers].map do |name, values|
        rendered_name = case random.rand(4)
                        when 0 then name
                        when 1 then name.downcase
                        when 2 then name.upcase
                        else name.tr("-", "_")
                        end
        rules << :header_name_case_and_underscore if rendered_name != name

        rendered_values = values.dup
        if rendered_values.length > 1 && random.rand(2).zero?
          rendered_values.reverse!
          rules << :header_value_array_order
        end
        if rendered_values.length == 1 && random.rand(2).zero?
          rendered_values = rendered_values.first
          rules << :header_single_value_as_array
        end
        [rendered_name, rendered_values]
      end

      if random.rand(2).zero?
        headers << ["X-Extra", ["ignored"]]
        rules << :extra_unmatched_header
      end
      headers.shuffle!(random: random)
      HeaderVariant.new(headers: headers, rules: rules.uniq)
    end
  end

  def header_guards(sample = header_sample)
    [
      [:header_value_changed, mutate_header(sample, "X-Multi") { |values| [values[0].upcase, values[1]] }],
      [:header_value_missing, mutate_header(sample, "X-Multi") { |values| [values[0]] }],
      [:header_value_missing, mutate_header(sample, "X-Single", remove: true)]
    ]
  end

  def mutate_header(sample, name, remove: false)
    sample[:headers].each_with_object([]) do |(key, values), result|
      next if key == name && remove

      result << if key == name
                  [key, yield(values)]
                else
                  [key, values]
                end
    end
  end

  # Performing requests in-process ---------------------------------------

  # Runs a real Net::HTTP request through WebMock's adapter. The caller
  # registers a catch-all stub first, so no request can reach the network.
  def perform(uri, method: :get, headers: {}, body: nil)
    parsed = Addressable::URI.heuristic_parse(uri)
    port = parsed.port || DEFAULT_PORTS.fetch(parsed.scheme)
    path = parsed.path.to_s.empty? ? "/" : parsed.path
    path += "?#{parsed.query}" if parsed.query

    request_class = ::Net::HTTP.const_get(method.to_s.capitalize)
    request = request_class.new(path)
    headers.each do |name, values|
      Array(values).each { |value| request.add_field(name, value.to_s) }
    end
    request.body = body if body

    http = ::Net::HTTP.new(parsed.host, port)
    http.use_ssl = parsed.scheme == "https"
    http.start { |connection| connection.request(request) }
  end

  def times_executed(stub)
    WebMock::RequestRegistry.instance.times_executed(stub.request_pattern)
  end

  def recorded_request_count
    WebMock::RequestRegistry.instance.requested_signatures.hash.values.sum
  end

  def reset_network_config
    WebMock.disable_net_connect!
    config = WebMock::Config.instance
    config.allow = nil
    config.allow_localhost = nil
    config.net_http_connect_on_start = nil
    config.query_values_notation = nil
  end

  # Shrinking a failing surface pair -------------------------------------

  def parse_surface(uri, normalize: false)
    parsed = Addressable::URI.parse(uri)
    segments = parsed.path.to_s.sub(%r{\A/}, "").split("/")
    segments = [] if segments == [""]
    pairs = (parsed.query || "").split("&").reject(&:empty?).map { |pair| pair.split("=", 2) }
    surface = {
      prefix: "#{parsed.scheme}://", host: parsed.host,
      port: parsed.port ? ":#{parsed.port}" : "",
      segments: segments, pairs: pairs
    }
    normalize ? normalize_surface!(surface) : surface
  end

  def render_surface(surface)
    path = surface[:segments].empty? ? "/" : "/" + surface[:segments].join("/")
    query = surface[:pairs].map { |key, value| value.nil? ? key : "#{key}=#{value}" }.join("&")
    "#{surface[:prefix]}#{surface[:host]}#{surface[:port]}#{path}" \
      "#{query.empty? ? '' : '?'}#{query}"
  end

  # Decodes keys and values and writes indexed array keys as "name[]", so a
  # shrunk sample reads as one plain surface form.
  def normalize_surface!(surface)
    surface[:segments].map! { |segment| unencoded(segment) }
    surface[:pairs].map! do |key, value|
      semantic_name = semantic_pair_key(key)
      expanded = unencoded(key) != semantic_name
      normalized_key = expanded ? "#{semantic_name}[]" : unencoded(key)
      [normalized_key, unencoded(value)]
    end
    surface
  end

  def unencoded(value)
    Addressable::URI.unencode_component(value.to_s)
  end

  # "ids[]" and "ids[0]" name the same repeated item; scalar keys and array
  # item names are compared after decoding.
  def semantic_pair_key(key)
    unencoded(key).sub(/\[[^\]]*\]\z/, "")
  end

  def matching_pair_index(surface, pair)
    key, value = pair
    surface[:pairs].index do |other_key, other_value|
      semantic_pair_key(other_key) == semantic_pair_key(key) &&
        unencoded(other_value) == unencoded(value)
    end
  end

  # Removes pairs that are identical in both surfaces, wherever they sit,
  # while the difference still reproduces. Scanning from the front, with the
  # fixed seed upstream, makes the result stable across runs. The block
  # receives the reduced query strings.
  def shrink_pair(left, right, normalize: false, &fails)
    left_surface = parse_surface(left, normalize: normalize)
    right_surface = parse_surface(right, normalize: normalize)

    loop do
      reduced = nil

      left_surface[:pairs].each_index do |left_index|
        pair = left_surface[:pairs][left_index]
        right_index = matching_pair_index(right_surface, pair)
        next unless right_index

        candidate_left = deep_dup(left_surface)
        candidate_right = deep_dup(right_surface)
        candidate_left[:pairs].delete_at(left_index)
        candidate_right[:pairs].delete_at(right_index)
        next unless fails.call(
          render_surface(candidate_left).split("?", 2)[1].to_s,
          render_surface(candidate_right).split("?", 2)[1].to_s
        )

        reduced = [candidate_left, candidate_right]
        break
      end

      break unless reduced

      left_surface, right_surface = reduced
    end

    left_query = render_surface(left_surface).split("?", 2)[1].to_s
    right_query = render_surface(right_surface).split("?", 2)[1].to_s
    [left_query, right_query]
  end

  # Semantic items are decoded query pairs grouped by item name (array item
  # keys reduced to their name) and decoded path segments. This makes the
  # report independent of how either client happened to encode or order the
  # surface.
  def semantic_path_segments(uri)
    uri.path.to_s.split("/").reject(&:empty?).map { |segment| unencoded(segment) }
  end

  def semantic_query_groups(uri)
    groups = {}
    (uri.query || "").split("&").reject(&:empty?).each_with_index do |pair, index|
      key, value = pair.split("=", 2)
      name = semantic_pair_key(key)
      groups[name] ||= { first_index: index, key: key, values: [] }
      groups[name][:values] << unencoded(value)
    end
    groups
  end

  # Compares parsed url-encoded values, preserving array order. Used for form
  # bodies, where WebMock matches arrays element by element.
  def form_values(text)
    WebMock::Util::QueryMapper.query_to_values(text)
  end

  # True when both form bodies parse to the same keys and value multisets, but
  # at least one array is in a different order.
  def form_order_only_difference?(left, right)
    left_values = form_values(left)
    right_values = form_values(right)
    return false unless left_values.is_a?(Hash) && right_values.is_a?(Hash)
    return false unless left_values.keys.sort == right_values.keys.sort

    found = false
    left_values.each do |key, value|
      other = right_values[key]
      if value.is_a?(Array) && other.is_a?(Array)
        return false unless value.sort == other.sort
        found ||= value != other
      else
        return false unless value == other
      end
    end
    found
  end

  # Reports the first path segment or query item whose value differs, which
  # is the part a maintainer needs in order to reproduce. Query items are
  # aligned by name, so a re-ordered surface does not hide a changed value.
  def shortest_difference(left, right)
    left_uri = Addressable::URI.parse(left.include?("://") ? left : "http://example.com/?#{left}")
    right_uri = Addressable::URI.parse(right.include?("://") ? right : "http://example.com/?#{right}")

    left_segments = semantic_path_segments(left_uri)
    right_segments = semantic_path_segments(right_uri)
    index = (0...[left_segments.length, right_segments.length].min).find do |i|
      left_segments[i] != right_segments[i]
    end
    return "path segment #{index}: #{left_segments[index].inspect} != #{right_segments[index].inspect}" if index

    left_groups = semantic_query_groups(left_uri)
    right_groups = semantic_query_groups(right_uri)
    left_groups.each do |name, group|
      other = right_groups[name]
      value_index = group[:values].each_index.find do |i|
        other.nil? || other[:values][i] != group[:values][i]
      end
      next unless value_index

      position = group[:first_index] + value_index
      left_value = group[:values][value_index]
      right_value = other && other[:values][value_index]
      left_key = group[:key]
      right_key = other ? other[:key] : left_key
      return "query item #{position}: #{query_item_text(left_key, left_value).inspect} != " \
             "#{query_item_text(right_key, right_value).inspect}"
    end

    length = [left.length, right.length].min
    index = (0...length).find { |i| left[i] != right[i] } || length
    start = [index - 8, 0].max
    stop = [index + 8, [left.length, right.length].min].min
    "#{left[start, stop - start].inspect} != #{right[start, stop - start].inspect}"
  end

  def query_item_text(key, value)
    value.nil? ? key : "#{key}=#{value}"
  end

  # A deliberately incorrect stub double. It sorts repeated values before
  # comparing, so it cannot tell query or form-body multi-value order apart.
  class OrderBlindDouble
    Entry = Struct.new(:name, :location, keyword_init: true)

    def initialize
      @entries = []
      @counts = Hash.new(0)
    end

    def register(name, method:, uri:, body: nil, headers: {})
      @entries << Entry.new(
        name: name, location: location_for(method, uri, body, headers)
      )
      self
    end

    def dispatch(method:, uri:, body: nil, headers: {})
      key = location_for(method, uri, body, headers)
      entry = @entries.find { |candidate| candidate.location == key }
      @counts[entry&.name] += 1
      entry&.name
    end

    def counts(name)
      @counts[name]
    end

    private

    def location_for(method, uri, body, headers)
      parsed = Addressable::URI.parse(uri)
      path = parsed.path.to_s.empty? ? "/" : parsed.path
      [
        method.to_s.downcase, parsed.scheme.to_s.downcase,
        parsed.host.to_s.downcase, parsed.port || DEFAULT_PORTS.fetch(parsed.scheme),
        path, sorted_pairs(parsed.query), sorted_pairs(body),
        WebMock::Util::Headers.normalize_headers(headers).sort
      ]
    end

    def sorted_pairs(text)
      return [] if text.nil? || text.empty?

      pairs = WebMock::Util::QueryMapper.query_to_values(text, notation: :flat_array) || []
      pairs.map { |key, value| [key, value.to_s] }.sort
    end
  end
end
