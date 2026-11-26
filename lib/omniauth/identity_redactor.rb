module OmniAuth
  # Removes values present in the full identity but absent from a public view.
  class IdentityRedactor
    FILTER = '[FILTERED]'.freeze
    MIN_SECRET_LENGTH = 4

    def initialize(full_identity, public_material)
      @secrets = extract(full_identity) - extract(public_material)
    end

    def scrub(message)
      return message if message.nil? || secrets.empty?

      text = message.to_s
      secrets.sort_by(&:length).reverse_each do |secret|
        next if secret.length < MIN_SECRET_LENGTH

        text = text.gsub(Regexp.new(Regexp.escape(secret))) { FILTER }
      end
      text
    end

    private

    attr_reader :secrets

    def extract(value, found = [])
      case value
      when Hash
        value.each_value { |item| extract(item, found) }
      when Array
        value.each { |item| extract(item, found) }
      when String
        found << value
      end
      found
    end
  end
end
