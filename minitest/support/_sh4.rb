$LOAD_PATH.unshift File.expand_path('../../lib', __dir__)
require 'webmock'
require_relative 'request_surface_generator'
include WebMockSurfaceRegression
sample = uri_samples.find { |c| c[:id] == 'uri-repeated-array' }
offset = uri_samples.index(sample)
canonical = canonical_uri(sample)
cq = canonical.split('?',2).last
generated_variants(sample, count: 10, offset: offset).each_with_index do |v, i|
  puts "#{i} #{v.uri} #{v.rules.inspect}"
  puts "    parsed=#{form_values(v.uri.split('?',2).last).inspect} order_only=#{form_order_only_difference?(cq, v.uri.split('?',2).last)} cmp=#{v.uri.include?('ids[1]')}"
end
