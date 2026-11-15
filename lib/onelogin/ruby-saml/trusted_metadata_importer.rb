require "base64"
require "openssl"
require "time"
require "nokogiri"

require "onelogin/ruby-saml/settings"
require "onelogin/ruby-saml/utils"

module OneLogin
  module RubySaml

    # Raised when trusted metadata cannot be selected under the caller's
    # trust anchor, target entity ID, and verification time.
    class TrustedMetadataError < StandardError
      attr_reader :evidence

      def initialize(message, evidence = nil)
        super(message)
        @evidence = (evidence || []).dup.freeze
      end
    end

    # Restricted import of one entity from a signed SAML 2.0 metadata
    # collection.
    #
    # Unlike IdpMetadataParser, this entry point never merges every certificate
    # it can find into a new trust pool. The caller supplies the trust anchor
    # certificates, the single target entityID, and the verification time.
    # Only the target entity's SSO endpoint and signing certificate are
    # adopted, and only when a signature that actually covers the target
    # verifies against one of the caller's anchors.
    #
    # Signature coverage rules:
    # - A signature covers the node its Reference resolves to, plus that
    #   node's descendants. That node must be the target entity or one of its
    #   ancestors.
    # - Signing one EntityDescriptor never covers a sibling entity. Signing an
    #   EntitiesDescriptor covers only the entities nested inside it.
    # - Every signature that covers the target must verify. A broken covering
    #   signature is never ignored in favour of another one.
    # - Certificates embedded in entity KeyDescriptors are never used to
    #   establish metadata-signing trust. They are only adopted as signing
    #   material after the target has been authenticated through an anchor.
    #
    # Validity rules:
    # - The effective not-after is the earliest validUntil on the target and
    #   all of its ancestors, including the document root.
    # - cacheDuration supplies a not-after only when that element has no
    #   validUntil. It is anchored at the element's IssueInstant, or the
    #   nearest enclosing IssueInstant, when one is present.
    # - A target is rejected when the verification time is at or after the
    #   effective not-after.
    class TrustedMetadataImporter
      METADATA_NS = "urn:oasis:names:tc:SAML:2.0:metadata".freeze
      SAML_ASSERTION_NS = "urn:oasis:names:tc:SAML:2.0:assertion".freeze
      DSIG_NS = "http://www.w3.org/2000/09/xmldsig#".freeze
      EXC_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#".freeze
      ENVELOPED_SIGNATURE = "http://www.w3.org/2000/09/xmldsig#enveloped-signature".freeze
      RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1".freeze
      RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256".freeze
      RSA_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384".freeze
      RSA_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512".freeze
      SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1".freeze
      SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256".freeze
      SHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384".freeze
      SHA512 = "http://www.w3.org/2001/04/xmlenc#sha512".freeze

      NAMESPACES = {
        "md" => METADATA_NS,
        "ds" => DSIG_NS,
        "saml" => SAML_ASSERTION_NS
      }.freeze

      # Evidence for an entity that was examined. Adopted evidence describes
      # the selected target; every other entry records what was not adopted.
      class EvidenceEntry
        attr_reader :entity_id, :element_path, :status, :reasons,
                    :signature_paths, :details

        def initialize(entity_id, element_path, status, reasons, signature_paths, details)
          @entity_id = entity_id
          @element_path = element_path
          @status = status
          @reasons = reasons.dup.freeze
          @signature_paths = signature_paths.dup.freeze
          @details = details.dup.freeze
          freeze
        end

        def adopted?
          @status == :adopted
        end

        def reason
          @reasons.empty? ? nil : @reasons.join("; ")
        end

        def sso_locations
          @details[:sso_locations] || []
        end

        def signing_certificate_fingerprints
          @details[:signing_certificate_fingerprints] || []
        end

        def effective_valid_until
          @details[:effective_valid_until]
        end
      end

      # Successful restricted import.
      class Result
        attr_reader :settings, :entity_id, :entity, :evidence,
                    :verification_time, :effective_valid_until

        def initialize(settings, entity_id, entity, evidence, verification_time, effective_valid_until)
          @settings = settings
          @entity_id = entity_id
          @entity = entity
          @evidence = evidence.dup.freeze
          @verification_time = verification_time
          @effective_valid_until = effective_valid_until
          freeze
        end

        # Evidence entries that were not adopted.
        def rejected
          @evidence.reject(&:adopted?)
        end

        # Paths of the signatures that covered the adopted entity.
        def signature_paths
          adopted = @evidence.find(&:adopted?)
          adopted ? adopted.signature_paths.dup : []
        end
      end

      # Internal parsed entity record.
      class EntityRecord
        attr_reader :id, :node, :path, :ancestors

        def initialize(id, node, path, ancestors)
          @id = id
          @node = node
          @path = path
          @ancestors = ancestors
        end
      end

      class << self
        # Convenience wrapper around #import.
        def import(metadata, trust_anchors, entity_id, verification_time, options = {})
          new.import(metadata, trust_anchors, entity_id, verification_time, options)
        end
        alias_method :import_entity, :import

        # Import and return only the Settings object.
        def settings(metadata, trust_anchors, entity_id, verification_time, options = {})
          import(metadata, trust_anchors, entity_id, verification_time, options).settings
        end
      end

      # @param metadata [String, IO, Nokogiri::XML::Document] signed metadata
      # @param trust_anchors [Array<OpenSSL::X509::Certificate, String>]
      #   the only certificates trusted to sign the metadata collection,
      #   direct signer certificates or CA anchors
      # @param entity_id [String] the single target entityID
      # @param verification_time [Time, DateTime, String] the effective "now"
      # @param options [Hash]
      # @option options [String, Array<String>] :sso_binding preferred SSO bindings
      # @option options [String, Array<String>] :slo_binding preferred SLO bindings
      # @option options [String, Array<String>] :name_id_format preferred NameIDFormats
      # @option options [String] :fingerprint_algorithm digest for the fingerprint
      # @return [Result]
      # @raise [TrustedMetadataError]
      def import(metadata, trust_anchors, entity_id, verification_time, options = {})
        @verification_time = normalize_time(verification_time)
        @options = options || {}
        @entity_id = entity_id
        @evidence = []

        if @entity_id.nil? || @entity_id.to_s.empty?
          raise TrustedMetadataError.new("A target entityID is required", @evidence)
        end

        @anchors = load_trust_anchors(trust_anchors)
        if @anchors.empty?
          raise TrustedMetadataError.new("At least one trust anchor certificate is required", @evidence)
        end

        @document = load_document(metadata)
        root = @document.root
        if root.nil?
          raise TrustedMetadataError.new("Metadata is empty", @evidence)
        end
        unless root.name == "EntitiesDescriptor" && root.namespace && root.namespace.href == METADATA_NS
          raise TrustedMetadataError.new("Metadata root must be md:EntitiesDescriptor", @evidence)
        end

        entities = collect_entities(root)
        duplicate_ids = entities.group_by(&:id).select { |id, records| id.nil? || records.length > 1 }

        unless duplicate_ids.empty?
          duplicated = entities.select { |entity| duplicate_ids.key?(entity.id) }
          duplicated.each do |entity|
            reason = if entity.id.nil?
                       "entity is missing entityID"
                     else
                       "duplicate entityID #{entity.id.inspect} in metadata collection"
                     end
            add_evidence(entity, :ambiguous, [reason])
          end
          add_evidence_for_others(entities, duplicated)
          if duplicate_ids.key?(@entity_id)
            raise TrustedMetadataError.new("Target entityID is not unique in the metadata collection", @evidence.dup)
          end
          labels = duplicate_ids.keys.map { |id| id.nil? ? "(missing)" : id.inspect }
          raise TrustedMetadataError.new("Metadata collection contains duplicate entityIDs: #{labels.join(", ")}", @evidence.dup)
        end

        target_entities = entities.select { |entity| entity.id == @entity_id }

        if target_entities.empty?
          add_evidence_for_others(entities, [])
          raise TrustedMetadataError.new("Target entityID was not found in the metadata collection", @evidence.dup)
        end

        target = target_entities.first
        adoption_reasons, effective_valid_until = adoption_failures(target)

        if adoption_reasons.any?
          add_evidence(target, :rejected, adoption_reasons)
          add_evidence_for_others(entities, [target])
          raise TrustedMetadataError.new("Target metadata is not trustworthy: #{adoption_reasons.join("; ")}", @evidence.dup)
        end

        settings = build_settings(target)
        add_evidence(target, :adopted, [])
        add_evidence_for_others(entities, [target])

        Result.new(settings, @entity_id, target, @evidence.dup, @verification_time, effective_valid_until)
      end

      private

      def normalize_time(value)
        case value
        when Time
          value.utc
        when DateTime
          value.to_time.utc
        when String
          begin
            Time.parse(value).utc
          rescue ArgumentError
            raise TrustedMetadataError.new("verification_time is not a valid time: #{value.inspect}")
          end
        else
          if value.respond_to?(:to_time)
            value.to_time.utc
          else
            raise TrustedMetadataError.new("verification_time must be a Time, DateTime, or parseable String")
          end
        end
      end

      def load_trust_anchors(anchors)
        Array(anchors).map do |anchor|
          case anchor
          when OpenSSL::X509::Certificate
            anchor
          when String
            begin
              OpenSSL::X509::Certificate.new(anchor)
            rescue OpenSSL::X509::CertificateError => error
              raise TrustedMetadataError.new("Invalid trust anchor certificate: #{error.message}")
            end
          else
            raise TrustedMetadataError.new("Trust anchors must be OpenSSL::X509::Certificate objects or PEM strings")
          end
        end
      end

      def load_document(metadata)
        xml = case metadata
              when Nokogiri::XML::Document
                metadata
              else
                metadata.respond_to?(:read) ? metadata.read : metadata.to_s
              end

        if xml.is_a?(String) && xml.include?("<!DOCTYPE")
          raise TrustedMetadataError.new("Metadata must not contain a DOCTYPE")
        end

        begin
          document = Nokogiri::XML(xml) { |config| config.strict.nonet }
        rescue Nokogiri::XML::SyntaxError => error
          raise TrustedMetadataError.new("Metadata XML is malformed: #{error.message}")
        end
        if document.internal_subset
          raise TrustedMetadataError.new("Metadata must not contain a DOCTYPE")
        end
        unless document.errors.empty?
          raise TrustedMetadataError.new("Metadata XML is malformed: #{document.errors.first.message}")
        end
        document
      end

      def collect_entities(root)
        entities = []
        walk_entities(root, [root], entities)
        entities
      end

      def walk_entities(element, ancestors, entities)
        element.element_children.each do |child|
          next unless child.namespace && child.namespace.href == METADATA_NS

          case child.name
          when "EntityDescriptor"
            entities << EntityRecord.new(child["entityID"], child, node_path(child), ancestors.dup)
          when "EntitiesDescriptor"
            walk_entities(child, ancestors + [child], entities)
          end
        end
      end

      def node_path(node)
        parts = []
        current = node
        while current && current.element?
          index = 1
          sibling = current.previous_sibling
          while sibling
            if sibling.element? && sibling.name == current.name &&
               sibling.namespace && current.namespace &&
               sibling.namespace.href == current.namespace.href
              index += 1
            end
            sibling = sibling.previous_sibling
          end
          parts.unshift("#{current.name}[#{index}]")
          current = current.parent
          break unless current && current.element?
        end
        "/" + parts.join("/")
      end

      def add_evidence(entity, status, reasons)
        @evidence << EvidenceEntry.new(
          entity.id,
          entity.path,
          status,
          reasons,
          covering_signature_paths(entity),
          evidence_details(entity)
        )
      end

      def add_evidence_for_others(entities, excluded)
        entities.each do |entity|
          next if excluded.include?(entity)
          add_evidence(entity, :not_selected, ["target entityID was #{@entity_id}"])
        end
      end

      def covering_signature_paths(entity)
        covering_signatures(entity).map { |signature| node_path(signature) }
      rescue TrustedMetadataError
        entity.node.xpath("./ds:Signature", NAMESPACES).map { |signature| node_path(signature) }
      end

      def evidence_details(entity)
        descriptor = entity.node.at_xpath("./md:IDPSSODescriptor", NAMESPACES)
        details = {
          :element_valid_until => entity.node["validUntil"],
          :element_cache_duration => entity.node["cacheDuration"],
          :sso_locations => descriptor ? descriptor.xpath("./md:SingleSignOnService/@Location", NAMESPACES).map(&:value) : [],
          :signing_certificate_fingerprints => []
        }
        begin
          details[:effective_valid_until] = effective_valid_until(entity)
        rescue TrustedMetadataError => error
          details[:effective_valid_until_error] = error.message
        end
        if descriptor
          begin
            details[:signing_certificate_fingerprints] = certificates_for(descriptor).map do |certificate|
              OpenSSL::Digest::SHA256.hexdigest(certificate.to_der).upcase.scan(/../).join(":")
            end
          rescue TrustedMetadataError => error
            details[:signing_certificate_fingerprints_error] = error.message
          end
        end
        details
      end

      def adoption_failures(target)
        reasons = []
        valid_until = nil
        begin
          valid_until = effective_valid_until(target)
        rescue TrustedMetadataError => error
          reasons << error.message
        end
        if valid_until && @verification_time >= valid_until
          reasons << "metadata is not valid at #{@verification_time.utc.iso8601}; effective validUntil is #{valid_until.utc.iso8601}"
        end

        begin
          reason = signature_failure(target)
          reasons << reason if reason
        rescue TrustedMetadataError => error
          reasons << "signature coverage could not be determined: #{error.message}"
        end

        descriptor = target.node.at_xpath("./md:IDPSSODescriptor", NAMESPACES)
        reasons << "target entity does not contain an IDPSSODescriptor" unless descriptor
        if descriptor
          if descriptor.xpath("./md:SingleSignOnService/@Location", NAMESPACES).empty?
            reasons << "target IDPSSODescriptor has no SingleSignOnService endpoint"
          end
          if certificates_for(descriptor).empty?
            reasons << "target IDPSSODescriptor has no signing certificate"
          end
        end

        [reasons, valid_until]
      end

      def signature_failure(target)
        covering = covering_signatures(target)
        return "no trusted signature covers the target entity" if covering.empty?

        failures = []
        covering.each do |signature|
          begin
            verify_signature(signature)
          rescue TrustedMetadataError => error
            failures << "#{node_path(signature)}: #{error.message}"
          end
        end
        failures.empty? ? nil : failures.join("; ")
      end

      # Signatures whose Reference resolves to the entity or one of its
      # ancestors. A sibling's signature is excluded because neither the
      # sibling nor its subtree is the target or an ancestor of it.
      def covering_signatures(target)
        candidates = @document.xpath("//ds:Signature", NAMESPACES)
        candidates.select do |signature|
          covered = signature_referenced_node(signature)
          covered && (covered == target.node || target.ancestors.include?(covered))
        end
      end

      def signature_referenced_node(signature)
        reference = signature.at_xpath("./ds:SignedInfo/ds:Reference", NAMESPACES)
        return nil unless reference

        uri = reference["URI"].to_s
        if uri.empty?
          # An empty same-document URI covers the whole document, hence the
          # target and every sibling as well.
          @document.root
        elsif uri.start_with?("#")
          matches = @document.xpath("//*[@ID=$id]", nil, "id" => uri[1..-1])
          if matches.length > 1
            raise TrustedMetadataError.new(
              "Signature Reference #{uri.inspect} is ambiguous: the ID occurs #{matches.length} times"
            )
          end
          matches.first
        end
      end

      def verify_signature(signature)
        signed_info = signature.at_xpath("./ds:SignedInfo", NAMESPACES)
        raise TrustedMetadataError.new("Signature lacks SignedInfo") unless signed_info

        canonicalization = signed_info.at_xpath("./ds:CanonicalizationMethod", NAMESPACES)
        raise TrustedMetadataError.new("Signature lacks CanonicalizationMethod") unless canonicalization

        signature_method = signed_info.at_xpath("./ds:SignatureMethod", NAMESPACES)
        raise TrustedMetadataError.new("Signature lacks SignatureMethod") unless signature_method
        signature_algorithm = digest_class(signature_method["Algorithm"].to_s)
        unless signature_algorithm
          raise TrustedMetadataError.new("Unsupported signature algorithm #{signature_method["Algorithm"].inspect}")
        end

        references = signed_info.xpath("./ds:Reference", NAMESPACES)
        unless references.length == 1
          raise TrustedMetadataError.new("Signature must contain exactly one Reference")
        end
        reference = references.first

        digest_method = reference.at_xpath("./ds:DigestMethod", NAMESPACES)
        raise TrustedMetadataError.new("Reference lacks DigestMethod") unless digest_method
        digest_algorithm = digest_class(digest_method["Algorithm"].to_s)
        unless digest_algorithm
          raise TrustedMetadataError.new("Unsupported digest algorithm #{digest_method["Algorithm"].inspect}")
        end

        digest_value = reference.at_xpath("./ds:DigestValue", NAMESPACES)
        raise TrustedMetadataError.new("Reference lacks DigestValue") unless digest_value

        signature_value = signature.at_xpath("./ds:SignatureValue", NAMESPACES)
        raise TrustedMetadataError.new("Signature lacks SignatureValue") unless signature_value

        certificate_text = signature.at_xpath("./ds:KeyInfo/ds:X509Data/ds:X509Certificate", NAMESPACES)
        raise TrustedMetadataError.new("Signature lacks an X509Certificate") unless certificate_text
        begin
          signing_certificate = OpenSSL::X509::Certificate.new(Base64.decode64(certificate_text.text))
        rescue OpenSSL::X509::CertificateError => error
          raise TrustedMetadataError.new("Signature certificate is invalid: #{error.message}")
        end

        verify_certificate_chain(signing_certificate, signature)

        covered = resolved_reference_node!(signature)
        canonical_covered = canonicalize_covered(covered, signature)
        unless secure_compare(digest_algorithm.digest(canonical_covered), Base64.decode64(digest_value.text.to_s))
          raise TrustedMetadataError.new("Digest mismatch")
        end

        signed_info_canonical = canonicalize_node(signed_info, canonicalization)
        unless signing_certificate.public_key.verify(
          signature_algorithm.new,
          Base64.decode64(signature_value.text.to_s),
          signed_info_canonical
        )
          raise TrustedMetadataError.new("Signature verification failed")
        end
      end

      def resolved_reference_node!(signature)
        reference = signature.at_xpath("./ds:SignedInfo/ds:Reference", NAMESPACES)
        uri = reference["URI"].to_s
        if uri.empty?
          @document.root
        elsif uri.start_with?("#")
          matches = @document.xpath("//*[@ID=$id]", nil, "id" => uri[1..-1])
          if matches.length != 1
            raise TrustedMetadataError.new(
              "Signature Reference #{uri.inspect} must resolve to exactly one element (found #{matches.length})"
            )
          end
          matches.first
        else
          raise TrustedMetadataError.new("Only same-document signature References are supported")
        end
      end

      def verify_certificate_chain(certificate, signature)
        intermediates = signature.xpath(".//ds:X509Data/ds:X509Certificate", NAMESPACES).map do |node|
          begin
            OpenSSL::X509::Certificate.new(Base64.decode64(node.text))
          rescue OpenSSL::X509::CertificateError
            nil
          end
        end.compact.reject { |candidate| candidate.to_der == certificate.to_der }

        failures = []
        @anchors.each do |anchor|
          store = OpenSSL::X509::Store.new
          store.add_cert(anchor)
          store.time = @verification_time
          store.purpose = OpenSSL::X509::PURPOSE_ANY if defined?(OpenSSL::X509::PURPOSE_ANY)
          # A caller may pin a signer certificate that is not a CA. Treat the
          # pinned certificate as a chain terminator so it can still be checked
          # for validity at the verification time.
          if defined?(OpenSSL::X509::V_FLAG_PARTIAL_CHAIN)
            store.flags = OpenSSL::X509::V_FLAG_PARTIAL_CHAIN
          end

          begin
            context = OpenSSL::X509::StoreContext.new(store, certificate, intermediates)
            context.time = @verification_time
            return true if context.verify
            failures << context.error_string
          rescue OpenSSL::X509::StoreError => error
            failures << error.message
          end
        end

        raise TrustedMetadataError.new(
          "Signature certificate is not chained to a configured trust anchor (#{failures.uniq.join(", ")})"
        )
      end

      def canonicalize_node(node, canonicalization_method)
        prefixes = nil
        if canonicalization_method
          prefix_list = canonicalization_method.at_xpath("./ec:InclusiveNamespaces/@PrefixList", "ec" => EXC_C14N)
          prefixes = prefix_list.value.split(/\s+/) if prefix_list
        end
        node.canonicalize(canonicalization_mode(canonicalization_method["Algorithm"].to_s), prefixes)
      end

      def canonicalization_mode(algorithm)
        case algorithm
        when "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
             "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"
          Nokogiri::XML::XML_C14N_1_0
        when "http://www.w3.org/2006/12/xml-c14n11",
             "http://www.w3.org/2006/12/xml-c14n11#WithComments"
          Nokogiri::XML::XML_C14N_1_1
        when EXC_C14N, "#{EXC_C14N}WithComments"
          Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0
        else
          raise TrustedMetadataError.new("Unsupported canonicalization algorithm #{algorithm.inspect}")
        end
      end

      # Prefix lists belong to the transform that declares them, never to the
      # SignedInfo signature canonicalization.
      def transform_prefixes(transform_element)
        prefix_list = transform_element.at_xpath("./ec:InclusiveNamespaces/@PrefixList", "ec" => EXC_C14N)
        prefix_list ? prefix_list.value.split(/\s+/) : nil
      end

      # The enveloped transform removes the signature being verified and
      # nothing else, wherever inside the covered subtree it is attached.
      def canonicalize_covered(covered, signature)
        reference = signature.at_xpath("./ds:SignedInfo/ds:Reference", NAMESPACES)
        transforms = reference.xpath("./ds:Transforms/ds:Transform", NAMESPACES)
        algorithms = transforms.map { |transform| transform["Algorithm"].to_s }

        unless algorithms.include?(ENVELOPED_SIGNATURE)
          raise TrustedMetadataError.new("Enveloped signature transform is missing")
        end

        mode = Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0
        prefixes = nil
        transforms.each do |transform|
          algorithm = transform["Algorithm"].to_s
          next if algorithm == ENVELOPED_SIGNATURE
          mode = canonicalization_mode(algorithm)
          prefixes = transform_prefixes(transform)
        end

        working = covered.dup(1)
        remove_matching_signature(working, covered, signature)
        scratch = Nokogiri::XML::Document.new
        scratch.root = working
        scratch.root.canonicalize(mode, prefixes)
      end

      # Remove the duplicate of +signature+ from the copied subtree. The copy
      # is located by walking the same child positions, so signatures attached
      # below the covered element are not mistaken for signatures on it.
      def remove_matching_signature(working, original, signature)
        relative_path = signature.path.sub(/\A#{Regexp.escape(original.path)}/, "")
        return if relative_path.empty?
        working_signature = working.at_xpath(".#{relative_path}", NAMESPACES)
        working_signature.remove if working_signature
      end

      def digest_class(algorithm)
        case algorithm
        when RSA_SHA1, SHA1 then OpenSSL::Digest::SHA1
        when RSA_SHA256, SHA256 then OpenSSL::Digest::SHA256
        when RSA_SHA384, SHA384 then OpenSSL::Digest::SHA384
        when RSA_SHA512, SHA512 then OpenSSL::Digest::SHA512
        end
      end

      def effective_valid_until(target)
        limits = ([target.node] + target.ancestors.reverse).compact.map do |element|
          element_valid_until(element)
        end
        limits.compact.min
      end

      def element_valid_until(element)
        valid_until = element["validUntil"]
        if valid_until
          begin
            return Time.parse(valid_until).utc
          rescue ArgumentError
            raise TrustedMetadataError.new("Invalid validUntil #{valid_until.inspect}")
          end
        end

        cache_duration = element["cacheDuration"]
        return nil unless cache_duration

        begin
          Time.at(OneLogin::RubySaml::Utils.parse_duration(cache_duration, issue_instant_for(element))).utc
        rescue StandardError => error
          raise TrustedMetadataError.new("Invalid cacheDuration #{cache_duration.inspect}: #{error.message}")
        end
      end

      # cacheDuration is relative to issuance. Use the element's IssueInstant,
      # the nearest ancestor's IssueInstant, or the caller's verification time
      # when the document carries none.
      def issue_instant_for(element)
        current = element
        while current && current.element?
          value = current["IssueInstant"]
          if value
            begin
              return Time.parse(value).utc
            rescue ArgumentError
              raise TrustedMetadataError.new("Invalid IssueInstant #{value.inspect}")
            end
          end
          current = current.parent
        end
        @verification_time
      end

      def build_settings(target)
        descriptor = target.node.at_xpath("./md:IDPSSODescriptor", NAMESPACES)
        sso_binding = preferred_binding(descriptor, "md:SingleSignOnService", @options[:sso_binding])
        sso_location = endpoint_location(descriptor, "md:SingleSignOnService", sso_binding)

        slo_binding = preferred_binding(descriptor, "md:SingleLogoutService", @options[:slo_binding])
        slo_location = slo_binding ? endpoint_location(descriptor, "md:SingleLogoutService", slo_binding) : nil
        slo_response_location = slo_binding ? endpoint_response_location(descriptor, slo_binding) : nil

        signing_certificates = certificates_for(descriptor)
        valid_until = effective_valid_until(target)

        metadata = {
          :idp_entity_id => target.id,
          :idp_sso_service_url => sso_location,
          :idp_sso_service_binding => sso_binding,
          :idp_slo_service_url => slo_location,
          :idp_slo_service_binding => slo_binding,
          :idp_slo_response_service_url => slo_response_location,
          :name_identifier_format => first_ranked_text(descriptor, "md:NameIDFormat", @options[:name_id_format]),
          :idp_attribute_names => attribute_names(descriptor),
          :valid_until => valid_until ? valid_until.utc.iso8601 : nil,
          :idp_cert => nil,
          :idp_cert_fingerprint => nil,
          :idp_cert_multi => nil
        }

        if signing_certificates.length == 1
          certificate = signing_certificates.first
          metadata[:idp_cert] = certificate.to_pem
          metadata[:idp_cert_fingerprint] = fingerprint(certificate)
        elsif signing_certificates.length > 1
          metadata[:idp_cert_multi] = { :signing => signing_certificates.map(&:to_pem) }
        end

        OneLogin::RubySaml::Settings.new(metadata)
      end

      def fingerprint(certificate)
        algorithm = digest_class(@options[:fingerprint_algorithm] || XMLSecurity::Document::SHA1) || OpenSSL::Digest::SHA1
        algorithm.hexdigest(certificate.to_der).upcase.scan(/../).join(":")
      end

      def preferred_binding(descriptor, element_name, priority)
        values = descriptor.xpath("./#{element_name}/@Binding", NAMESPACES).map(&:value)
        return nil if values.empty?
        Array(priority).each do |candidate|
          return candidate if values.include?(candidate)
        end
        values.first
      end

      def endpoint_location(descriptor, element_name, binding)
        node = descriptor.at_xpath("./#{element_name}[@Binding='#{binding}']/@Location", NAMESPACES)
        node ? node.value : nil
      end

      def endpoint_response_location(descriptor, binding)
        node = descriptor.at_xpath("./md:SingleLogoutService[@Binding='#{binding}']/@ResponseLocation", NAMESPACES)
        node ? node.value : nil
      end

      def first_ranked_text(descriptor, element_name, priority)
        values = descriptor.xpath("./#{element_name}", NAMESPACES).map { |node| node.text.to_s.strip }
        return nil if values.empty?
        Array(priority).each do |candidate|
          return candidate if values.include?(candidate)
        end
        values.first
      end

      def attribute_names(descriptor)
        descriptor.xpath("./saml:Attribute/@Name", NAMESPACES).map(&:value)
      end

      def certificates_for(descriptor)
        nodes = descriptor.xpath(
          "./md:KeyDescriptor[not(@use) or @use='signing']/ds:KeyInfo/ds:X509Data/ds:X509Certificate",
          NAMESPACES
        )
        nodes.map do |node|
          begin
            OpenSSL::X509::Certificate.new(Base64.decode64(node.text))
          rescue OpenSSL::X509::CertificateError => error
            raise TrustedMetadataError.new("Entity contains an invalid X509Certificate: #{error.message}")
          end
        end.uniq { |certificate| certificate.to_der }
      end

      def secure_compare(left, right)
        return false unless left && right && left.bytesize == right.bytesize

        result = 0
        left.bytes.zip(right.bytes) { |a, b| result |= a ^ b }
        result.zero?
      end
    end
  end
end
