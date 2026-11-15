if RUBY_VERSION < '1.9'
  require 'uuid'
else
  require 'securerandom'
end
require "openssl"

module OneLogin
  module RubySaml

    # SAML2 Auxiliary class
    #
    class Utils
      @@uuid_generator = UUID.new if RUBY_VERSION < '1.9'

      BINDINGS = { :post => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".freeze,
                   :redirect => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect".freeze }.freeze
      DSIG = "http://www.w3.org/2000/09/xmldsig#".freeze
      XENC = "http://www.w3.org/2001/04/xmlenc#".freeze
      DURATION_FORMAT = %r(^
        (-?)P                       # 1: Duration sign
        (?:
          (?:(\d+)Y)?               # 2: Years
          (?:(\d+)M)?               # 3: Months
          (?:(\d+)D)?               # 4: Days
          (?:T
            (?:(\d+)H)?             # 5: Hours
            (?:(\d+)M)?             # 6: Minutes
            (?:(\d+(?:[.,]\d+)?)S)? # 7: Seconds
          )?
          |
          (\d+)W                    # 8: Weeks
        )
      $)x.freeze

      UUID_PREFIX = '_'
      @@prefix = '_'

      # Checks if the x509 cert provided is expired.
      #
      # @param cert [OpenSSL::X509::Certificate|String] The x509 certificate.
      # @return [true|false] Whether the certificate is expired.
      def self.is_cert_expired(cert)
        cert = OpenSSL::X509::Certificate.new(cert) if cert.is_a?(String)

        cert.not_after < Time.now
      end

      # Checks if the x509 cert provided has both started and has not expired.
      #
      # @param cert [OpenSSL::X509::Certificate|String] The x509 certificate.
      # @return [true|false] Whether the certificate is currently active.
      def self.is_cert_active(cert)
        cert = OpenSSL::X509::Certificate.new(cert) if cert.is_a?(String)
        now = Time.now
        cert.not_before <= now && cert.not_after >= now
      end

      # Interprets a ISO8601 duration value relative to a given timestamp.
      #
      # @param duration [String] The duration, as a string.
      # @param timestamp [Integer] The unix timestamp we should apply the
      #                            duration to. Optional, default to the
      #                            current time.
      #
      # @return [Integer] The new timestamp, after the duration is applied.
      #
      def self.parse_duration(duration, timestamp=Time.now.utc)
        return nil if RUBY_VERSION < '1.9'  # 1.8.7 not supported

        matches = duration.match(DURATION_FORMAT)

        if matches.nil?
          raise StandardError.new("Invalid ISO 8601 duration")
        end

        sign = matches[1] == '-' ? -1 : 1

        durYears, durMonths, durDays, durHours, durMinutes, durSeconds, durWeeks =
          matches[2..8].map do |match|
            if match
              match = match.tr(',', '.').gsub(/\.0*\z/, '')
              sign * (match.include?('.') ? match.to_f : match.to_i)
            else
              0
            end
          end

        datetime = Time.at(timestamp).utc.to_datetime
        datetime = datetime.next_year(durYears)
        datetime = datetime.next_month(durMonths)
        datetime = datetime.next_day((7*durWeeks) + durDays)
        datetime.to_time.utc.to_i + (durHours * 3600) + (durMinutes * 60) + durSeconds
      end

      # Return a properly formatted x509 certificate
      #
      # @param cert [String] The original certificate
      # @return [String] The formatted certificate
      #
      def self.format_cert(cert)
        # don't try to format an encoded certificate or if is empty or nil
        if cert.respond_to?(:ascii_only?)
          return cert if cert.nil? || cert.empty? || !cert.ascii_only?
        else
          return cert if cert.nil? || cert.empty? || cert.match(/\x0d/)
        end

        if cert.scan(/BEGIN CERTIFICATE/).length > 1
          formatted_cert = []
          cert.scan(/-{5}BEGIN CERTIFICATE-{5}[\n\r]?.*?-{5}END CERTIFICATE-{5}[\n\r]?/m) {|c|
            formatted_cert << format_cert(c)
          }
          formatted_cert.join("\n")
        else
          cert = cert.gsub(/\-{5}\s?(BEGIN|END) CERTIFICATE\s?\-{5}/, "")
          cert = cert.gsub(/\r/, "")
          cert = cert.gsub(/\n/, "")
          cert = cert.gsub(/\s/, "")
          cert = cert.scan(/.{1,64}/)
          cert = cert.join("\n")
          "-----BEGIN CERTIFICATE-----\n#{cert}\n-----END CERTIFICATE-----"
        end
      end

      # Return a properly formatted private key
      #
      # @param key [String] The original private key
      # @return [String] The formatted private key
      #
      def self.format_private_key(key)
        # don't try to format an encoded private key or if is empty
        return key if key.nil? || key.empty? || key.match(/\x0d/)

        # is this an rsa key?
        rsa_key = key.match("RSA PRIVATE KEY")
        key = key.gsub(/\-{5}\s?(BEGIN|END)( RSA)? PRIVATE KEY\s?\-{5}/, "")
        key = key.gsub(/\n/, "")
        key = key.gsub(/\r/, "")
        key = key.gsub(/\s/, "")
        key = key.scan(/.{1,64}/)
        key = key.join("\n")
        key_label = rsa_key ? "RSA PRIVATE KEY" : "PRIVATE KEY"
        "-----BEGIN #{key_label}-----\n#{key}\n-----END #{key_label}-----"
      end

      # Given a certificate string, return an OpenSSL::X509::Certificate object.
      #
      # @param cert [String] The original certificate
      # @return [OpenSSL::X509::Certificate] The certificate object
      #
      def self.build_cert_object(cert)
        return nil if cert.nil? || cert.empty?

        OpenSSL::X509::Certificate.new(format_cert(cert))
      end

      # Given a private key string, return an OpenSSL::PKey::RSA object.
      #
      # @param cert [String] The original private key
      # @return [OpenSSL::PKey::RSA] The private key object
      #
      def self.build_private_key_object(private_key)
        return nil if private_key.nil? || private_key.empty?

        OpenSSL::PKey::RSA.new(format_private_key(private_key))
      end

      # Build the Query String signature that will be used in the HTTP-Redirect binding
      # to generate the Signature
      # @param params [Hash] Parameters to build the Query String
      # @option params [String] :type 'SAMLRequest' or 'SAMLResponse'
      # @option params [String] :data Base64 encoded SAMLRequest or SAMLResponse
      # @option params [String] :relay_state The RelayState parameter
      # @option params [String] :sig_alg The SigAlg parameter
      # @return [String] The Query String
      #
      def self.build_query(params)
        type, data, relay_state, sig_alg = [:type, :data, :relay_state, :sig_alg].map { |k| params[k]}

        url_string = "#{type}=#{CGI.escape(data)}"
        url_string << "&RelayState=#{CGI.escape(relay_state)}" if relay_state
        url_string << "&SigAlg=#{CGI.escape(sig_alg)}"
      end

      # Reconstruct a canonical query string from raw URI-encoded parts, to be used in verifying a signature
      #
      # @param params [Hash] Parameters to build the Query String
      # @option params [String] :type 'SAMLRequest' or 'SAMLResponse'
      # @option params [String] :raw_data URI-encoded, base64 encoded SAMLRequest or SAMLResponse, as sent by IDP
      # @option params [String] :raw_relay_state URI-encoded RelayState parameter, as sent by IDP
      # @option params [String] :raw_sig_alg URI-encoded SigAlg parameter, as sent by IDP
      # @return [String] The Query String
      #
      def self.build_query_from_raw_parts(params)
        type, raw_data, raw_relay_state, raw_sig_alg = [:type, :raw_data, :raw_relay_state, :raw_sig_alg].map { |k| params[k]}

        url_string = "#{type}=#{raw_data}"
        url_string << "&RelayState=#{raw_relay_state}" if raw_relay_state
        url_string << "&SigAlg=#{raw_sig_alg}"
      end

      # Prepare raw GET parameters (build them from normal parameters
      # if not provided).
      #
      # @param rawparams [Hash] Raw GET Parameters
      # @param params [Hash] GET Parameters
      # @param lowercase_url_encoding [bool] Lowercase URL Encoding  (For ADFS urlencode compatibility)
      # @return [Hash] New raw parameters
      #
      def self.prepare_raw_get_params(rawparams, params, lowercase_url_encoding=false)
        rawparams ||= {}

        if rawparams['SAMLRequest'].nil? && !params['SAMLRequest'].nil?
          rawparams['SAMLRequest'] = escape_request_param(params['SAMLRequest'], lowercase_url_encoding)
        end
        if rawparams['SAMLResponse'].nil? && !params['SAMLResponse'].nil?
          rawparams['SAMLResponse'] = escape_request_param(params['SAMLResponse'], lowercase_url_encoding)
        end
        if rawparams['RelayState'].nil? && !params['RelayState'].nil?
          rawparams['RelayState'] = escape_request_param(params['RelayState'], lowercase_url_encoding)
        end
        if rawparams['SigAlg'].nil? && !params['SigAlg'].nil?
          rawparams['SigAlg'] = escape_request_param(params['SigAlg'], lowercase_url_encoding)
        end

        rawparams
      end

      def self.escape_request_param(param, lowercase_url_encoding)
        CGI.escape(param).tap do |escaped|
          next unless lowercase_url_encoding

          escaped.gsub!(/%[A-Fa-f0-9]{2}/) { |match| match.downcase }
        end
      end

      # Validate the Signature parameter sent on the HTTP-Redirect binding
      # @param params [Hash] Parameters to be used in the validation process
      # @option params [OpenSSL::X509::Certificate] cert The IDP public certificate
      # @option params [String] sig_alg The SigAlg parameter
      # @option params [String] signature The Signature parameter (base64 encoded)
      # @option params [String] query_string The full GET Query String to be compared
      # @return [Boolean] True if the Signature is valid, False otherwise
      #
      def self.verify_signature(params)
        cert, sig_alg, signature, query_string = [:cert, :sig_alg, :signature, :query_string].map { |k| params[k]}
        signature_algorithm = XMLSecurity::BaseDocument.new.algorithm(sig_alg)
        return cert.public_key.verify(signature_algorithm.new, Base64.decode64(signature), query_string)
      end

      # Build the status error message
      # @param status_code [String] StatusCode value
      # @param status_message [String] StatusMessage value
      # @return [String] The status error message
      def self.status_error_msg(error_msg, raw_status_code = nil, status_message = nil)
        error_msg = error_msg.dup

        unless raw_status_code.nil?
          if raw_status_code.include? "|"
            status_codes = raw_status_code.split(' | ')
            values = status_codes.collect do |status_code|
              status_code.split(':').last
            end
            printable_code = values.join(" => ")
          else
            printable_code = raw_status_code.split(':').last
          end
          error_msg << ', was ' + printable_code
        end

        unless status_message.nil?
          error_msg << ' -> ' + status_message
        end

        error_msg
      end

      # Obtains the decrypted string from an Encrypted node element in XML,
      # given multiple private keys to try.
      # @param encrypted_node [REXML::Element] The Encrypted element
      # @param private_keys [Array<OpenSSL::PKey::RSA>] The Service provider private key
      # @param recipient [String|nil] The expected recipient of the EncryptedKey element
      # @return [String] The decrypted data
      def self.decrypt_multi(encrypted_node, private_keys, recipient = nil)
        raise ArgumentError.new('private_keys must be specified') if !private_keys || private_keys.empty?

        encrypt_data = retrieve_encrypted_data(encrypted_node)
        encrypted_key = retrieve_encrypted_key(encrypted_node, encrypt_data, recipient)

        error = nil
        private_keys.each do |private_key|
          begin
            return decrypt_data_with_key(encrypt_data, encrypted_key, private_key)
          rescue OpenSSL::PKey::PKeyError => e
            error ||= e
          rescue OpenSSL::Cipher::CipherError => e
            error ||= e
          end
        end

        raise(error) if error
        raise encryption_error(encrypted_node, 'no EncryptedKey could be decrypted')
      end

      # Obtains the single EncryptedData element that is the target of decryption.
      # @param encrypted_node [REXML::Element] The Encrypted element
      # @return [REXML::Element] The EncryptedData element
      def self.retrieve_encrypted_data(encrypted_node)
        encrypted_data_nodes =
          if encrypted_node.name == 'EncryptedData'
            [encrypted_node]
          else
            REXML::XPath.match(
              encrypted_node,
              "./xenc:EncryptedData",
              { 'xenc' => XENC }
            )
          end

        if encrypted_data_nodes.size != 1
          raise encryption_error(encrypted_node, 'the encrypted element must contain exactly one EncryptedData')
        end

        encrypt_data = encrypted_data_nodes.first
        assert_unique_encrypted_data_id(encrypted_node, encrypt_data)
        encrypt_data
      end

      # Obtains the single EncryptedKey that is bound to the EncryptedData.
      # @param encrypted_node [REXML::Element] The Encrypted element
      # @param encrypt_data [REXML::Element] The EncryptedData element
      # @param recipient [String|nil] The expected recipient of the EncryptedKey element
      # @return [REXML::Element] The EncryptedKey element
      def self.retrieve_encrypted_key(encrypted_node, encrypt_data, recipient = nil)
        encrypted_keys, rejections = retrieve_encrypted_keys(encrypted_node, encrypt_data, recipient)

        unless rejections.empty?
          raise encryption_error(encrypted_node, "conflicting EncryptedKey binding (#{rejections.join('; ')})")
        end

        if encrypted_keys.empty?
          raise encryption_error(encrypted_node, 'no EncryptedKey element found for the EncryptedData')
        end

        assert_unique_encrypted_key_ids(encrypted_node, encrypted_keys)

        if encrypted_keys.size != 1
          raise encryption_error(encrypted_node, 'multiple EncryptedKey elements are bound to the EncryptedData')
        end

        encrypted_keys.first
      end

      # Obtains the EncryptedKey elements that are bound to the EncryptedData.
      # @param encrypted_node [REXML::Element] The Encrypted element
      # @param encrypt_data [REXML::Element] The EncryptedData element
      # @param recipient [String|nil] The expected recipient of the EncryptedKey element
      # @return [Array(Array<REXML::Element>, Array<String>)] Eligible keys and rejection reasons
      def self.retrieve_encrypted_keys(encrypted_node, encrypt_data, recipient = nil)
        candidate_keys = []

        REXML::XPath.match(
          encrypt_data,
          "./ds:KeyInfo//xenc:EncryptedKey | ./KeyInfo//xenc:EncryptedKey",
          { 'ds' => DSIG, 'xenc' => XENC }
        ).each { |key| candidate_keys << key }

        REXML::XPath.match(
          encrypted_node,
          "./xenc:EncryptedKey",
          { 'xenc' => XENC }
        ).each { |key| candidate_keys << key }

        REXML::XPath.match(
          encrypt_data,
          "./ds:KeyInfo/ds:RetrievalMethod | ./ds:KeyInfo/RetrievalMethod | ./KeyInfo/ds:RetrievalMethod | ./KeyInfo/RetrievalMethod",
          { 'ds' => DSIG, 'xenc' => XENC }
        ).each do |retrieval_method|
          uri = retrieval_method.attributes['URI']
          unless uri && uri.start_with?('#') && !uri[1..-1].empty?
            raise encryption_error(encrypted_node, 'malformed EncryptedKey RetrievalMethod')
          end

          referenced_keys = REXML::XPath.match(
            encrypted_node.root,
            "//xenc:EncryptedKey[@Id=$id]",
            { 'xenc' => XENC },
            { 'id' => uri[1..-1] }
          )

          if referenced_keys.empty?
            raise encryption_error(encrypted_node, 'EncryptedKey RetrievalMethod does not resolve')
          end

          referenced_keys.each { |key| candidate_keys << key }
        end

        candidate_keys = candidate_keys.each_with_object([]) do |key, unique_keys|
          unique_keys << key unless unique_keys.any? { |unique_key| unique_key.object_id == key.object_id }
        end

        eligible_keys = []
        rejections = []

        candidate_keys.each do |key|
          if !encrypted_key_recipient_matches?(key, recipient)
            rejections << "EncryptedKey #{encrypted_key_label(key)} is for another Recipient"
            next
          end

          if !encrypted_key_references_data?(key, encrypt_data)
            rejections << "EncryptedKey #{encrypted_key_label(key)} references another EncryptedData"
            next
          end

          eligible_keys << key
        end

        [eligible_keys, rejections]
      end

      # Checks whether the EncryptedKey Recipient matches the expected recipient.
      # @param encrypted_key [REXML::Element] The EncryptedKey element
      # @param recipient [String|nil] The expected recipient
      # @return [Boolean] True when the key can be used by the recipient
      def self.encrypted_key_recipient_matches?(encrypted_key, recipient)
        return true if recipient.nil? || recipient.empty?

        key_recipient = encrypted_key.attributes['Recipient']
        return true if key_recipient.nil? || key_recipient.empty?

        key_recipient == recipient
      end

      # Checks whether the EncryptedKey references the target EncryptedData.
      # @param encrypted_key [REXML::Element] The EncryptedKey element
      # @param encrypt_data [REXML::Element] The EncryptedData element
      # @return [Boolean] True when the key is bound to the target
      def self.encrypted_key_references_data?(encrypted_key, encrypt_data)
        data_references = REXML::XPath.match(
          encrypted_key,
          "./xenc:ReferenceList/xenc:DataReference",
          { 'xenc' => XENC }
        )

        return true if data_references.empty?

        target_id = encrypt_data.attributes['Id']
        return false if target_id.nil? || target_id.empty?

        data_references.any? do |data_reference|
          uri = data_reference.attributes['URI']
          uri && uri.start_with?('#') && uri[1..-1] == target_id
        end
      end

      # Checks that the candidate EncryptedKeys do not share an Id.
      # @param encrypted_node [REXML::Element] The Encrypted element
      # @param encrypted_keys [Array<REXML::Element>] The candidate keys
      def self.assert_unique_encrypted_key_ids(encrypted_node, encrypted_keys)
        ids = encrypted_keys.map { |key| key.attributes['Id'] }.compact.reject { |id| id.empty? }

        if ids.size != ids.uniq.size
          raise encryption_error(encrypted_node, 'duplicated EncryptedKey Id')
        end

        ids.each do |id|
          matching_keys = REXML::XPath.match(
            encrypted_node.root,
            "//xenc:EncryptedKey[@Id=$id]",
            { 'xenc' => XENC },
            { 'id' => id }
          )

          if matching_keys.size != 1
            raise encryption_error(encrypted_node, 'duplicated EncryptedKey Id')
          end
        end
      end

      # Checks that the target EncryptedData does not share an Id with another node.
      # @param encrypted_node [REXML::Element] The Encrypted element
      # @param encrypt_data [REXML::Element] The EncryptedData element
      def self.assert_unique_encrypted_data_id(encrypted_node, encrypt_data)
        id = encrypt_data.attributes['Id']
        return if id.nil? || id.empty?

        matching_data = REXML::XPath.match(
          encrypted_node.root,
          "//xenc:EncryptedData[@Id=$id]",
          { 'xenc' => XENC },
          { 'id' => id }
        )

        if matching_data.size != 1
          raise encryption_error(encrypted_node, 'duplicated EncryptedData Id')
        end
      end

      def self.encrypted_key_label(encrypted_key)
        id = encrypted_key.attributes['Id']
        id.nil? || id.empty? ? 'without Id' : "##{id}"
      end

      def self.encryption_error(encrypted_node, message)
        ValidationError.new("Invalid #{encrypted_node.name}: #{message}")
      end

      # Decrypts an EncryptedData element with an already selected EncryptedKey.
      # @param encrypt_data [REXML::Element] The EncryptedData element
      # @param encrypted_key [REXML::Element] The EncryptedKey element
      # @param private_key [OpenSSL::PKey::RSA] The Service provider private key
      # @return [String] The decrypted data
      def self.decrypt_data_with_key(encrypt_data, encrypted_key, private_key)
        symmetric_key = decrypt_encrypted_key(encrypted_key, private_key)
        cipher_value = REXML::XPath.first(
          encrypt_data,
          "./xenc:CipherData/xenc:CipherValue",
          { 'xenc' => XENC }
        )
        node = Base64.decode64(element_text(cipher_value))
        encrypt_method = REXML::XPath.first(
          encrypt_data,
          "./xenc:EncryptionMethod",
          { 'xenc' => XENC }
        )
        algorithm = encrypt_method.attributes['Algorithm']
        retrieve_plaintext(node, symmetric_key, algorithm)
      end

      # Obtains the decrypted string from an Encrypted node element in XML
      # @param encrypted_node [REXML::Element] The Encrypted element
      # @param private_key [OpenSSL::PKey::RSA] The Service provider private key
      # @return [String] The decrypted data
      def self.decrypt_data(encrypted_node, private_key)
        decrypt_multi(encrypted_node, [private_key])
      end

      # Obtains the symmetric key from the EncryptedKey bound to an EncryptedData element
      # @param encrypted_node [REXML::Element] The Encrypted element
      # @param private_key [OpenSSL::PKey::RSA] The Service provider private key
      # @return [String] The symmetric key
      def self.retrieve_symmetric_key(encrypted_node, private_key)
        encrypt_data = retrieve_encrypted_data(encrypted_node)
        encrypted_key = retrieve_encrypted_key(encrypted_node, encrypt_data)
        decrypt_encrypted_key(encrypted_key, private_key)
      end

      # Decrypts an EncryptedKey element with a private key
      # @param encrypted_key [REXML::Element] The EncryptedKey element
      # @param private_key [OpenSSL::PKey::RSA] The Service provider private key
      # @return [String] The symmetric key
      def self.decrypt_encrypted_key(encrypted_key, private_key)
        encrypted_symmetric_key_element = REXML::XPath.first(
          encrypted_key,
          "./xenc:CipherData/xenc:CipherValue",
          "xenc" => XENC
        )

        cipher_text = Base64.decode64(element_text(encrypted_symmetric_key_element))

        encrypt_method = REXML::XPath.first(
          encrypted_key,
          "./xenc:EncryptionMethod",
          "xenc" => XENC
        )

        algorithm = encrypt_method.attributes['Algorithm']
        retrieve_plaintext(cipher_text, private_key, algorithm)
      end

      def self.retrieve_symetric_key_reference(encrypt_data)
        REXML::XPath.first(
          encrypt_data,
          "substring-after(./ds:KeyInfo/ds:RetrievalMethod/@URI, '#')",
          { "ds" => DSIG }
        )
      end

      # Obtains the deciphered text
      # @param cipher_text [String]   The ciphered text
      # @param symmetric_key [String] The symmetric key used to encrypt the text
      # @param algorithm [String]     The encrypted algorithm
      # @return [String] The deciphered text
      def self.retrieve_plaintext(cipher_text, symmetric_key, algorithm)
        case algorithm
          when 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc' then cipher = OpenSSL::Cipher.new('DES-EDE3-CBC').decrypt
          when 'http://www.w3.org/2001/04/xmlenc#aes128-cbc' then cipher = OpenSSL::Cipher.new('AES-128-CBC').decrypt
          when 'http://www.w3.org/2001/04/xmlenc#aes192-cbc' then cipher = OpenSSL::Cipher.new('AES-192-CBC').decrypt
          when 'http://www.w3.org/2001/04/xmlenc#aes256-cbc' then cipher = OpenSSL::Cipher.new('AES-256-CBC').decrypt
          when 'http://www.w3.org/2009/xmlenc11#aes128-gcm' then auth_cipher = OpenSSL::Cipher::AES.new(128, :GCM).decrypt
          when 'http://www.w3.org/2009/xmlenc11#aes192-gcm' then auth_cipher = OpenSSL::Cipher::AES.new(192, :GCM).decrypt
          when 'http://www.w3.org/2009/xmlenc11#aes256-gcm' then auth_cipher = OpenSSL::Cipher::AES.new(256, :GCM).decrypt
          when 'http://www.w3.org/2001/04/xmlenc#rsa-1_5' then rsa = symmetric_key
          when 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p' then oaep = symmetric_key
        end

        if cipher
          iv_len = cipher.iv_len
          data = cipher_text[iv_len..-1]
          cipher.padding, cipher.key, cipher.iv = 0, symmetric_key, cipher_text[0..iv_len-1]
          assertion_plaintext = cipher.update(data)
          assertion_plaintext << cipher.final
        elsif auth_cipher
          iv_len, text_len, tag_len = auth_cipher.iv_len, cipher_text.length, 16
          data = cipher_text[iv_len..text_len-1-tag_len]
          auth_cipher.padding = 0
          auth_cipher.key = symmetric_key
          auth_cipher.iv = cipher_text[0..iv_len-1]
          auth_cipher.auth_data = ''
          auth_cipher.auth_tag = cipher_text[text_len-tag_len..-1]
          assertion_plaintext = auth_cipher.update(data)
          assertion_plaintext << auth_cipher.final
        elsif rsa
          rsa.private_decrypt(cipher_text)
        elsif oaep
          oaep.private_decrypt(cipher_text, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)
        else
          cipher_text
        end
      end

      def self.set_prefix(value)
        @@prefix = value
      end

      def self.prefix
        @@prefix
      end

      def self.uuid
        "#{prefix}" + (RUBY_VERSION < '1.9' ? "#{@@uuid_generator.generate}" : "#{SecureRandom.uuid}")
      end

      # Given two strings, attempt to match them as URIs using Rails' parse method.  If they can be parsed,
      # then the fully-qualified domain name and the host should perform a case-insensitive match, per the
      # RFC for URIs.  If Rails can not parse the string into URL pieces, return a boolean match of the
      # two strings.  This maintains the previous functionality.
      # @return [Boolean]
      def self.uri_match?(destination_url, settings_url)
        dest_uri = URI.parse(destination_url)
        acs_uri = URI.parse(settings_url)

        if dest_uri.scheme.nil? || acs_uri.scheme.nil? || dest_uri.host.nil? || acs_uri.host.nil?
          raise URI::InvalidURIError
        else
          dest_uri.scheme.downcase == acs_uri.scheme.downcase &&
            dest_uri.host.downcase == acs_uri.host.downcase &&
            dest_uri.path == acs_uri.path &&
            dest_uri.query == acs_uri.query
        end
      rescue URI::InvalidURIError
        original_uri_match?(destination_url, settings_url)
      end

      # If Rails' URI.parse can't match to valid URL, default back to the original matching service.
      # @return [Boolean]
      def self.original_uri_match?(destination_url, settings_url)
        destination_url == settings_url
      end

      # Given a REXML::Element instance, return the concatenation of all child text nodes. Assumes
      # that there all children other than text nodes can be ignored (e.g. comments). If nil is
      # passed, nil will be returned.
      def self.element_text(element)
        element.texts.map(&:value).join if element
      end
    end
  end
end
