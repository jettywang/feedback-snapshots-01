require "base64"
require "openssl"
require "time"

require "nokogiri"
require "xml_security"

require "onelogin/ruby-saml/utils"
require "onelogin/ruby-saml/validation_error"
require "onelogin/ruby-saml/settings"

# Only supports SAML 2.0
module OneLogin
  module RubySaml
    # Restricted import of metadata published in an EntitiesDescriptor.
    #
    # Unlike IdpMetadataParser, this importer never selects an entity based on
    # its position in the document. The caller must provide the entityID to
    # adopt, one or more trust anchors used to validate XML signatures, and the
    # time at which the metadata is being evaluated. Only a target entity that
    # is covered by a signature chaining to one of those anchors, and whose
    # inherited validity allows use at that time, produces Settings.
    #
    # Certificates carried inside the metadata (ds:KeyInfo or
    # md:KeyDescriptor) are never added to the trust store. A document cannot
    # bootstrap trust by publishing its own signing certificate.
    #
    class TrustedMetadata
      METADATA_NAMESPACE = "urn:oasis:names:tc:SAML:2.0:metadata".freeze
      DSIG_NAMESPACE     = "http://www.w3.org/2000/09/xmldsig#".freeze
      EXC_C14N_NAMESPACE = "http://www.w3.org/2001/10/xml-exc-c14n#".freeze

      C14N_ALGORITHMS = {
        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315" => [Nokogiri::XML::XML_C14N_1_0, false],
        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments" => [Nokogiri::XML::XML_C14N_1_0, true],
        "http://www.w3.org/2006/12/xml-c14n11" => [Nokogiri::XML::XML_C14N_1_1, false],
        "http://www.w3.org/2006/12/xml-c14n11#WithComments" => [Nokogiri::XML::XML_C14N_1_1, true],
        EXC_C14N_NAMESPACE => [Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0, false],
        "#{EXC_C14N_NAMESPACE}WithComments" => [Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0, true]
      }.freeze

      DIGEST_ALGORITHMS = {
        "http://www.w3.org/2001/04/xmlenc#sha256" => OpenSSL::Digest::SHA256,
        "http://www.w3.org/2001/04/xmldsig-more#sha384" => OpenSSL::Digest::SHA384,
        "http://www.w3.org/2001/04/xmlenc#sha512" => OpenSSL::Digest::SHA512
      }.freeze

      SIGNATURE_ALGORITHMS = {
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" => OpenSSL::Digest::SHA256,
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384" => OpenSSL::Digest::SHA384,
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" => OpenSSL::Digest::SHA512
      }.freeze

      ENVELOPED_SIGNATURE = "http://www.w3.org/2000/09/xmldsig#enveloped-signature".freeze

      # Outcome of a restricted metadata import.
      #
      # settings is nil unless the requested entity was adopted. evidence
      # describes both the adopted entity and every candidate that was left
      # out, including the reason it was not adopted.
      class Result
        attr_reader :settings, :evidence, :errors

        def initialize(settings, evidence, errors)
          @settings = settings
          @evidence = evidence
          @errors = errors
        end

        def adopted?
          !@settings.nil?
        end

        alias_method :accepted?, :adopted?
      end

      # Import metadata and return a Result. Rejected targets do not raise;
      # their reasons are available from Result#errors and Result#evidence.
      #
      # @param metadata [String, Nokogiri::XML::Document] metadata document
      # @param trust_anchors [OpenSSL::X509::Certificate, String, Array] trust anchors
      # @param entity_id [String] entityID of the only entity allowed to be adopted
      # @param verification_time [Time, String] time used for signature chains and validity
      # @param retrieved_at [Time, String, nil] optional retrieval time used for cacheDuration
      # @param options [Hash] :settings, :sso_binding, :slo_binding and :name_id_format
      # @return [Result]
      def self.import(metadata, trust_anchors:, entity_id:, verification_time:, retrieved_at: nil, options: {})
        new(
          trust_anchors: trust_anchors,
          verification_time: verification_time,
          retrieved_at: retrieved_at
        ).import(metadata, entity_id: entity_id, options: options)
      end

      # Like .import, but raises ValidationError when the target is not adopted.
      def self.import!(metadata, trust_anchors:, entity_id:, verification_time:, retrieved_at: nil, options: {})
        result = import(
          metadata,
          trust_anchors: trust_anchors,
          entity_id: entity_id,
          verification_time: verification_time,
          retrieved_at: retrieved_at,
          options: options
        )
        unless result.adopted?
          raise ValidationError.new(result.errors.join("; "))
        end
        result
      end

      def initialize(trust_anchors:, verification_time:, retrieved_at: nil)
        @trust_anchors = normalize_trust_anchors(trust_anchors)
        if @trust_anchors.empty?
          raise ArgumentError.new("trust_anchors must contain at least one certificate")
        end

        @verification_time = coerce_time(verification_time, "verification_time")
        # cacheDuration is relative to the retrieval of the document. When the
        # caller does not supply a separate retrieval time, the verification
        # time is the only point in time at which the document is known to be
        # in hand, so use it rather than silently ignoring cacheDuration.
        @retrieved_at = if retrieved_at.nil?
                          @verification_time
                        else
                          coerce_time(retrieved_at, "retrieved_at")
                        end
      end

      # @return [Result]
      def import(metadata, entity_id:, options: {})
        target_id = entity_id.to_s
        if target_id.empty?
          raise ArgumentError.new("entity_id must be a non-empty String")
        end

        begin
          import_target(metadata, target_id, options || {})
        rescue StandardError => error
          Result.new(nil, {}, ["Trusted metadata import failed: #{error.message}"])
        end
      end

      private

      def import_target(metadata, target_id, options)
        errors = []
        document = load_document(metadata, errors)
        return rejected_result(errors, target_id, nil, nil, nil) if document.nil?

        id_index, duplicate_ids = index_ids(document)
        entity_infos = collect_entities(document)
        duplicate_entity_ids = duplicate_entity_ids(entity_infos)
        unless duplicate_ids.empty?
          errors << "Metadata contains duplicate ID attributes: #{duplicate_ids.uniq.sort.join(', ')}"
          return rejected_result(errors, target_id, entity_infos, id_index, document,
                                 duplicate_entity_ids: duplicate_entity_ids,
                                 duplicate_ids: duplicate_ids)
        end

        candidates = entity_infos.select { |info| info[:entity_id] == target_id }

        if candidates.empty?
          errors << "No EntityDescriptor found for entityID #{target_id.inspect}"
          return rejected_result(errors, target_id, entity_infos, id_index, document,
                                 duplicate_entity_ids: duplicate_entity_ids)
        end
        if candidates.size > 1
          errors << "EntityID #{target_id.inspect} appears more than once; the target is ambiguous"
          return rejected_result(errors, target_id, entity_infos, id_index, document,
                                 duplicate_entity_ids: duplicate_entity_ids)
        end

        target = candidates.first
        signatures = collect_signatures(document, id_index)
        target_info = analyze_target(
          target,
          signatures,
          duplicate_entity_ids,
          options
        )

        evidence = build_evidence(
          target_id,
          target_info,
          entity_infos,
          signatures,
          duplicate_ids,
          duplicate_entity_ids,
          target[:node]
        )

        if errors.empty? && target_info[:adopted]
          Result.new(target_info[:settings], evidence, [])
        else
          errors = target_info[:reasons].map { |reason| reason[:message] } if errors.empty?
          Result.new(nil, evidence, errors)
        end
      rescue ValidationError => error
        Result.new(nil, {}, [error.message])
      end

      def load_document(metadata, errors)
        xml = if metadata.is_a?(Nokogiri::XML::Document)
                metadata.to_xml(:save_with => Nokogiri::XML::Node::SaveOptions::AS_XML)
              else
                metadata.to_s
              end

        document = XMLSecurity::BaseDocument.safe_load_xml(xml, true)
        root = document.root
        if root.nil? || !metadata_element?(root) ||
           !["EntitiesDescriptor", "EntityDescriptor"].include?(root.name)
          errors << "Metadata root must be a SAML 2.0 EntitiesDescriptor or EntityDescriptor"
          return nil
        end
        document
      rescue StandardError => error
        errors << "Metadata is not a safe SAML metadata document: #{error.message}"
        nil
      end

      def index_ids(document)
        index = {}
        duplicates = []
        document.xpath("//*[@ID]").each do |node|
          value = node["ID"]
          (index[value] ||= []) << node
        end
        index.each do |value, nodes|
          duplicates << value if nodes.size > 1
        end
        [index, duplicates]
      end

      # Collect every EntityDescriptor with enough detail for evidence, even
      # those that can never be adopted.
      def collect_entities(document)
        document.xpath("//*[local-name()=$ln and namespace-uri()=$ns]", nil,
                       { "ln" => "EntityDescriptor", "ns" => METADATA_NAMESPACE }).map do |node|
          {
            :node => node,
            :entity_id => node["entityID"],
            :idp => idp_descriptor(node)
          }
        end
      end

      def duplicate_entity_ids(entity_infos)
        ids = entity_infos.map { |info| info[:entity_id] }
        ids.select { |entity_id| entity_id && ids.count(entity_id) > 1 }.uniq
      end

      def metadata_element?(node)
        node.element? && node.namespace && node.namespace.href == METADATA_NAMESPACE
      end

      def idp_descriptors(entity_node)
        entity_node.xpath("./*[local-name()=$ln and namespace-uri()=$ns]", nil,
                          { "ln" => "IDPSSODescriptor", "ns" => METADATA_NAMESPACE })
      end

      def idp_descriptor(entity_node)
        idp_descriptors(entity_node).first
      end

      # Verify every XML signature once. Results are reused for coverage and
      # evidence, but only signature nodes are targets of adoption.
      def collect_signatures(document, id_index)
        document.xpath("//*[local-name()=$ln and namespace-uri()=$ns]", nil,
                       { "ln" => "Signature", "ns" => DSIG_NAMESPACE }).map do |signature|
          verify_signature(document, signature, id_index)
        end
      end

      def verify_signature(document, signature, id_index)
        result = {
          :node => signature,
          :owner_name => signature.parent && signature.parent.name,
          :reference_id => nil,
          :referenced_node => nil,
          :referenced_entity_id => nil,
          :signer_certificate => nil,
          :certificate_chain => [],
          :valid => false,
          :errors => []
        }

        signed_info = ds_child(signature, "SignedInfo")
        if signed_info.nil?
          result[:errors] << "Signature has no SignedInfo"
          return result
        end

        reference = ds_child(signed_info, "Reference")
        if reference.nil?
          result[:errors] << "SignedInfo has no Reference"
          return result
        end

        references = ds_children(signed_info, "Reference")
        if references.size != 1
          result[:errors] << "SignedInfo must contain exactly one Reference"
          return result
        end

        uri = reference["URI"].to_s
        unless uri =~ /\A#(.+)\z/
          result[:errors] << "Signature Reference URI must point to an ID in this document"
          return result
        end
        reference_id = $1
        result[:reference_id] = reference_id

        referenced_nodes = id_index[reference_id] || []
        if referenced_nodes.size != 1
          result[:errors] << "Signature Reference ID #{reference_id.inspect} does not identify exactly one element"
          return result
        end

        referenced = referenced_nodes.first
        result[:referenced_node] = referenced
        result[:referenced_entity_id] = referenced["entityID"] if referenced.name == "EntityDescriptor"

        if !metadata_element?(referenced) ||
           !["EntitiesDescriptor", "EntityDescriptor"].include?(referenced.name)
          result[:errors] << "Signature Reference must cover an EntitiesDescriptor or EntityDescriptor"
          return result
        end

        unless signature.parent.equal?(referenced)
          result[:errors] << "Signature must be a direct child of the element it covers"
          return result
        end

        transforms = ds_path(reference, [["Transforms", 1], ["Transform", nil]])
        transform_info = analyze_transforms(transforms, result[:errors])
        return result if transform_info.nil?

        digest_method = ds_child(reference, "DigestMethod")
        digest_value = ds_child(reference, "DigestValue")
        if digest_method.nil? || digest_value.nil?
          result[:errors] << "Signature Reference is missing DigestMethod or DigestValue"
          return result
        end
        digest_class = DIGEST_ALGORITHMS[digest_method["Algorithm"]]
        if digest_class.nil?
          result[:errors] << "Unsupported digest algorithm #{digest_method['Algorithm'].inspect}"
          return result
        end

        signature_method = ds_child(signed_info, "SignatureMethod")
        signature_digest = SIGNATURE_ALGORITHMS[signature_method && signature_method["Algorithm"]]
        if signature_digest.nil?
          result[:errors] << "Unsupported signature algorithm"
          return result
        end

        canonicalization = ds_child(signed_info, "CanonicalizationMethod")
        signed_info_c14n = canonicalization_for(canonicalization, result[:errors])
        return result if signed_info_c14n.nil?

        signature_value = ds_child(signature, "SignatureValue")
        if signature_value.nil?
          result[:errors] << "Signature has no SignatureValue"
          return result
        end

        begin
          signature_bytes = Base64.strict_decode64(signature_value.text.to_s.gsub(/\s+/, ""))
        rescue ArgumentError
          result[:errors] << "SignatureValue is not valid Base64"
          return result
        end

        cert_nodes = signature.xpath(
          "./*[local-name()=$ki and namespace-uri()=$ds]" \
          "/*[local-name()=$xd and namespace-uri()=$ds]" \
          "/*[local-name()=$xc and namespace-uri()=$ds]",
          nil,
          { "ki" => "KeyInfo", "xd" => "X509Data", "xc" => "X509Certificate", "ds" => DSIG_NAMESPACE }
        )
        if cert_nodes.empty?
          result[:errors] << "Signature has no X509Certificate in KeyInfo"
          return result
        end

        signer_certificates = cert_nodes.map do |node|
          parse_certificate(node.text, result[:errors])
        end.compact
        if signer_certificates.empty?
          result[:errors] << "Signature KeyInfo does not contain a usable X509Certificate"
          return result
        end

        signed_info_text = canonicalize(signed_info, signed_info_c14n)

        certificate = nil
        signature_ok = false
        signer_certificates.each do |candidate|
          next unless candidate.public_key.is_a?(OpenSSL::PKey::RSA)

          if candidate.public_key.verify(signature_digest.new, signature_bytes, signed_info_text)
            certificate = candidate
            signature_ok = true
            break
          end
        end
        unless signature_ok
          result[:errors] << "Signature value does not verify with the KeyInfo certificate"
          return result
        end
        result[:signer_certificate] = certificate

        chain_ok, chain, chain_error = certificate_chains_to_anchor?(
          certificate,
          signer_certificates.reject { |candidate| candidate.to_der == certificate.to_der }
        )
        result[:certificate_chain] = chain || []
        unless chain_ok
          result[:errors] << "Signing certificate does not chain to a configured trust anchor: #{chain_error}"
          return result
        end

        working = duplicate_document(document)
        working_signature = node_at_path(working, node_path(signature))
        if working_signature.nil?
          result[:errors] << "Could not locate the signature while checking its digest"
          return result
        end
        working_signature.remove

        working_referenced = find_by_id(working, reference_id)
        if working_referenced.nil?
          result[:errors] << "Could not locate the signed element while checking its digest"
          return result
        end

        actual_digest = digest_class.digest(canonicalize(working_referenced, transform_info))
        expected_digest = nil
        begin
          expected_digest = Base64.strict_decode64(digest_value.text.to_s.gsub(/\s+/, ""))
        rescue ArgumentError
          result[:errors] << "DigestValue is not valid Base64"
          return result
        end

        unless secure_compare(actual_digest, expected_digest)
          result[:errors] << "Signature digest does not match the referenced element"
          return result
        end

        result[:valid] = true
        result
      rescue StandardError => error
        result[:valid] = false
        result[:errors] << "Signature validation failed: #{error.message}"
        result
      end

      def analyze_transforms(transform_nodes, errors)
        if transform_nodes.empty?
          errors << "Signature Reference has no transforms"
          return nil
        end

        # Only the canonical metadata profile is accepted: the enveloped
        # signature is removed first, then at most one canonicalization step.
        algorithm = transform_nodes.first["Algorithm"].to_s
        unless algorithm == ENVELOPED_SIGNATURE
          errors << "The enveloped-signature transform must be the first transform"
          return nil
        end

        c14n = nil
        transform_nodes[1..-1].each do |transform|
          algorithm = transform["Algorithm"].to_s
          if ENVELOPED_SIGNATURE == algorithm
            errors << "Signature Reference contains more than one enveloped-signature transform"
            return nil
          elsif C14N_ALGORITHMS.key?(algorithm)
            if c14n
              errors << "Signature Reference contains more than one canonicalization transform"
              return nil
            end
            c14n = canonicalization_for(transform, errors)
            return nil if c14n.nil?
          else
            errors << "Unsupported transform #{algorithm.inspect}"
            return nil
          end
        end

        c14n || canonicalization_for(nil, errors, default: Nokogiri::XML::XML_C14N_1_0)
      end

      def canonicalization_for(node, errors, default: nil)
        if node.nil?
          if default
            return { :mode => default, :inclusive_namespaces => nil, :with_comments => false }
          end
          errors << "Signature has no canonicalization method"
          return nil
        end

        algorithm = node["Algorithm"].to_s
        settings = C14N_ALGORITHMS[algorithm]
        if settings.nil?
          errors << "Unsupported canonicalization algorithm #{algorithm.inspect}"
          return nil
        end

        {
          :mode => settings[0],
          :with_comments => settings[1],
          :inclusive_namespaces => inclusive_namespaces(node)
        }
      end

      def inclusive_namespaces(node)
        inclusive = node.xpath("./*[local-name()=$ln and namespace-uri()=$ns]", nil,
                               { "ln" => "InclusiveNamespaces", "ns" => EXC_C14N_NAMESPACE }).first
        return nil if inclusive.nil?

        list = inclusive["PrefixList"].to_s.split(/\s+/).reject(&:empty?)
        list.empty? ? nil : list
      end

      def canonicalize(node, info)
        begin
          if info[:inclusive_namespaces]
            node.canonicalize(info[:mode], info[:inclusive_namespaces], info[:with_comments])
          else
            node.canonicalize(info[:mode], nil, info[:with_comments])
          end
        rescue ArgumentError
          # Older Nokogiri versions do not accept the with_comments argument.
          # Only fall back when comments are not part of the signed range.
          raise if info[:with_comments]
          if info[:inclusive_namespaces]
            node.canonicalize(info[:mode], info[:inclusive_namespaces])
          else
            node.canonicalize(info[:mode])
          end
        end
      end

      def certificate_chains_to_anchor?(certificate, extra_certificates)
        store = OpenSSL::X509::Store.new
        @trust_anchors.each { |anchor| store.add_cert(anchor) }
        begin
          if defined?(OpenSSL::X509::PURPOSE_ANY) && store.respond_to?(:purpose=)
            store.purpose = OpenSSL::X509::PURPOSE_ANY
          end
          if defined?(OpenSSL::X509::V_FLAG_PARTIAL_CHAIN) && store.respond_to?(:flags=)
            store.flags = OpenSSL::X509::V_FLAG_PARTIAL_CHAIN
          end
        rescue NotImplementedError, ArgumentError
          # Some backends, notably older JRuby OpenSSL, reject store-level
          # verification options. The verification below still pins time.
        end

        # Verification must happen at the caller's time, never at wall-clock
        # time. If this OpenSSL binding cannot be pinned to a time, fail closed
        # instead of silently validating a different moment.
        if store.respond_to?(:time=)
          store.time = @verification_time
          ok = store.verify(certificate, extra_certificates)
          [ok, store.chain, store.error_string]
        elsif defined?(OpenSSL::X509::StoreContext) &&
              OpenSSL::X509::StoreContext.method_defined?(:time=)
          context = OpenSSL::X509::StoreContext.new(store, certificate, extra_certificates)
          context.time = @verification_time
          if defined?(OpenSSL::X509::PURPOSE_ANY) && context.respond_to?(:purpose=)
            context.purpose = OpenSSL::X509::PURPOSE_ANY
          end
          [context.verify, context.chain, context.error_string]
        else
          [false, [], "OpenSSL cannot verify a certificate chain at a specified time"]
        end
      rescue OpenSSL::X509::StoreError, NotImplementedError, ArgumentError => error
        [false, [], error.message]
      end

      def analyze_target(target, signatures, duplicate_entity_ids, options)
        info = {
          :entity_id => target[:entity_id],
          :node => target[:node],
          :adopted => false,
          :reasons => [],
          :settings => nil,
          :signatures => [],
          :valid_until => nil,
          :validity_limits => []
        }

        if duplicate_entity_ids.include?(target[:entity_id])
          info[:reasons] << reason("EntityID appears more than once", :duplicate_entity_id)
        end

        candidates = idp_descriptors(target[:node])
        if candidates.empty?
          info[:reasons] << reason("Target EntityDescriptor has no IDPSSODescriptor", :missing_idp)
          return info
        end
        if candidates.size > 1
          info[:reasons] << reason("Target EntityDescriptor contains more than one IDPSSODescriptor", :ambiguous_idp)
          return info
        end
        idp = candidates.first

        valid_until, limits, validity_errors = effective_validity(target[:node], idp)
        info[:valid_until] = valid_until
        info[:validity_limits] = limits
        validity_errors.each { |message| info[:reasons] << reason(message, :invalid_validity) }

        if valid_until && @verification_time >= valid_until
          message = "Metadata validity ended at #{format_time(valid_until)}"
          if limits.size > 0
            limiting = limits.select { |limit| limit[:value] == valid_until }.last
            message << " (#{limiting[:source]})" if limiting
          end
          info[:reasons] << reason(message, :expired)
        end

        covering = signatures.select do |signature|
          signature[:valid] && ancestor_or_self?(signature[:referenced_node], target[:node])
        end
        info[:signatures] = covering

        if covering.empty?
          target_signature_errors = signatures.select do |signature|
            signature[:referenced_node] && ancestor_or_self?(signature[:referenced_node], target[:node])
          end.flat_map { |signature| signature[:errors] }
          if target_signature_errors.empty?
            info[:reasons] << reason("No trusted signature covers the target entity", :no_trusted_signature)
          else
            target_signature_errors.uniq.each do |message|
              info[:reasons] << reason("Signature covering the target is invalid: #{message}", :invalid_signature)
            end
          end
        end

        signing_certificates, certificate_errors = signing_certificates_for(idp)
        certificate_errors.each { |message| info[:reasons] << reason(message, :invalid_certificate) }
        if signing_certificates.empty? && certificate_errors.empty?
          info[:reasons] << reason("Target IDPSSODescriptor publishes no signing certificate", :missing_signing_certificate)
        end

        if info[:reasons].empty?
          info[:settings] = build_settings(target, idp, signing_certificates, valid_until, options)
          info[:adopted] = true
        end

        info
      end

      def signing_certificates_for(idp)
        nodes = idp.xpath(
          "./*[local-name()=$ln and namespace-uri()=$ns][@use='signing' or not(@use)]" \
          "/*[local-name()=$ki and namespace-uri()=$ds]" \
          "/*[local-name()=$xd and namespace-uri()=$ds]" \
          "/*[local-name()=$xc and namespace-uri()=$ds]",
          nil,
          {
            "ln" => "KeyDescriptor", "ns" => METADATA_NAMESPACE,
            "ki" => "KeyInfo", "xd" => "X509Data", "xc" => "X509Certificate",
            "ds" => DSIG_NAMESPACE
          }
        )

        certificates = []
        errors = []
        nodes.each do |node|
          certificate = parse_certificate(node.text, errors)
          next if certificate.nil?
          der = certificate.to_der
          next if certificates.any? { |existing| existing.to_der == der }
          certificates << certificate
        end

        [certificates, errors]
      end

      def effective_validity(entity_node, idp_node)
        values = []
        limits = []
        errors = []
        inherited = entity_node.ancestors.select do |ancestor|
          metadata_element?(ancestor) && ancestor.name == "EntitiesDescriptor"
        end.reverse
        (inherited + [entity_node, idp_node]).each do |node|
          source = if node.equal?(entity_node)
                     "target EntityDescriptor"
                   elsif node.equal?(idp_node)
                     "target IDPSSODescriptor"
                   elsif node["Name"]
                     "ancestor EntitiesDescriptor #{node['Name'].inspect}"
                   elsif node["ID"]
                     "ancestor EntitiesDescriptor ##{node['ID']}"
                   else
                     "ancestor EntitiesDescriptor"
                   end
          valid_until = node["validUntil"]
          unless valid_until.nil? || valid_until.to_s.empty?
            begin
              time = Time.iso8601(valid_until.to_s)
              values << time
              limits << { :source => source, :attribute => "validUntil", :value => time }
            rescue ArgumentError
              errors << "Invalid validUntil #{valid_until.inspect} on #{source}"
            end
          end

          unless @retrieved_at.nil?
            cache_duration = node["cacheDuration"]
            unless cache_duration.nil? || cache_duration.to_s.empty?
              begin
                timestamp = Utils.parse_duration(cache_duration.to_s, @retrieved_at)
                time = Time.at(timestamp).utc
                values << time
                limits << { :source => source, :attribute => "cacheDuration", :value => time }
              rescue StandardError
                errors << "Invalid cacheDuration #{cache_duration.inspect} on #{source}"
              end
            end
          end
        end

        [values.min, limits, errors]
      end

      def build_settings(target, idp, signing_certificates, valid_until, options)
        attributes = {
          :idp_entity_id => target[:entity_id],
          :name_identifier_format => selected_name_id_format(idp, options[:name_id_format]),
          :idp_sso_service_url => nil,
          :idp_sso_service_binding => nil,
          :idp_slo_service_url => nil,
          :idp_slo_service_binding => nil,
          :idp_slo_response_service_url => nil,
          :idp_attribute_names => attribute_names(idp),
          :idp_cert => nil,
          :idp_cert_fingerprint => nil,
          :idp_cert_multi => { :signing => [], :encryption => [] },
          :valid_until => valid_until && format_time(valid_until)
        }

        sso = select_endpoint(idp, "SingleSignOnService", options[:sso_binding])
        if sso
          attributes[:idp_sso_service_url] = sso["Location"]
          attributes[:idp_sso_service_binding] = sso["Binding"]
        end

        slo = select_endpoint(idp, "SingleLogoutService", options[:slo_binding])
        if slo
          attributes[:idp_slo_service_url] = slo["Location"]
          attributes[:idp_slo_service_binding] = slo["Binding"]
          attributes[:idp_slo_response_service_url] = slo["ResponseLocation"]
        end

        encoded = signing_certificates.map { |certificate| Base64.strict_encode64(certificate.to_der) }
        attributes[:idp_cert_multi] = { :signing => encoded, :encryption => [] }
        if signing_certificates.size == 1
          attributes[:idp_cert] = encoded.first
          attributes[:idp_cert_fingerprint] = fingerprint(signing_certificates.first)
        end

        settings = options[:settings]
        if settings.nil?
          Settings.new(attributes)
        elsif settings.is_a?(Hash)
          Settings.new(settings.merge(attributes))
        else
          attributes.each do |key, value|
            settings.send("#{key}=".to_sym, value)
          end
          settings
        end
      end

      def selected_name_id_format(idp, priority)
        nodes = idp.xpath("./*[local-name()=$ln and namespace-uri()=$ns]", nil,
                          { "ln" => "NameIDFormat", "ns" => METADATA_NAMESPACE })
        return nil if nodes.empty?

        values = nodes.map(&:text)
        Array(priority).each do |candidate|
          return candidate if values.include?(candidate)
        end
        nodes.first.text
      end

      def attribute_names(idp)
        idp.xpath("./*[local-name()=$ln and namespace-uri()=$ns]/@Name", nil,
                  { "ln" => "Attribute", "ns" => "urn:oasis:names:tc:SAML:2.0:assertion" }).map(&:value)
      end

      def select_endpoint(idp, element_name, priority)
        nodes = idp.xpath("./*[local-name()=$ln and namespace-uri()=$ns]", nil,
                          { "ln" => element_name, "ns" => METADATA_NAMESPACE })
        return nil if nodes.empty?

        bindings = nodes.map { |node| node["Binding"] }
        selected_binding = Array(priority).detect { |candidate| bindings.include?(candidate) }
        selected_binding ||= bindings.first
        nodes.detect { |node| node["Binding"] == selected_binding }
      end

      def fingerprint(certificate)
        OpenSSL::Digest::SHA1.hexdigest(certificate.to_der).upcase.scan(/../).join(":")
      end

      def analyze_sibling(info, signatures, duplicate_entity_ids, target_node)
        record = {
          :entity_id => info[:entity_id],
          :reasons => [],
          :covered_by_trusted_signature => false,
          :sso_endpoints => [],
          :slo_endpoints => [],
          :signing_certificates => [],
          :encryption_certificates => [],
          :valid_until => nil
        }

        record[:reasons] << :not_target unless target_node && info[:node].equal?(target_node)
        if duplicate_entity_ids.include?(info[:entity_id])
          record[:reasons] << :duplicate_entity_id
        end

        idp = info[:idp]
        if idp.nil?
          record[:reasons] << :missing_idp
          return record
        end

        valid_until, _limits, validity_errors = effective_validity(info[:node], idp)
        record[:valid_until] = valid_until && format_time(valid_until)
        record[:reasons] << :invalid_validity unless validity_errors.empty?
        record[:reasons] << :expired if valid_until && @verification_time >= valid_until

        record[:covered_by_trusted_signature] = signatures.any? do |signature|
          signature[:valid] && ancestor_or_self?(signature[:referenced_node], info[:node])
        end
        record[:reasons] << :no_trusted_signature unless record[:covered_by_trusted_signature]

        record[:sso_endpoints] = endpoints(idp, "SingleSignOnService")
        record[:slo_endpoints] = endpoints(idp, "SingleLogoutService")
        signing, signing_errors = signing_certificates_for(idp)
        encryption = encryption_certificates_for(idp)
        record[:signing_certificates] = signing.map { |certificate| Base64.strict_encode64(certificate.to_der) }
        record[:encryption_certificates] = encryption.map { |certificate| Base64.strict_encode64(certificate.to_der) }
        record[:reasons] << :invalid_certificate unless signing_errors.empty?

        record
      end

      def endpoints(idp, element_name)
        idp.xpath("./*[local-name()=$ln and namespace-uri()=$ns]", nil,
                  { "ln" => element_name, "ns" => METADATA_NAMESPACE }).map do |node|
          {
            :binding => node["Binding"],
            :location => node["Location"],
            :response_location => node["ResponseLocation"]
          }
        end
      end

      def encryption_certificates_for(idp)
        nodes = idp.xpath(
          "./*[local-name()=$ln and namespace-uri()=$ns][@use='encryption']" \
          "/*[local-name()=$ki and namespace-uri()=$ds]" \
          "/*[local-name()=$xd and namespace-uri()=$ds]" \
          "/*[local-name()=$xc and namespace-uri()=$ds]",
          nil,
          {
            "ln" => "KeyDescriptor", "ns" => METADATA_NAMESPACE,
            "ki" => "KeyInfo", "xd" => "X509Data", "xc" => "X509Certificate",
            "ds" => DSIG_NAMESPACE
          }
        )
        nodes.map { |node| parse_certificate(node.text, []) }.compact
      end

      def build_evidence(target_id, target_info, entity_infos, signatures, duplicate_ids, duplicate_entity_ids, target)
        evidence = {
          :entity_id => target_id,
          :verification_time => format_time(@verification_time),
          :trust_anchors => @trust_anchors.map { |anchor| certificate_summary(anchor) },
          :duplicate_xml_ids => duplicate_ids.uniq.sort,
          :duplicate_entity_ids => duplicate_entity_ids,
          :signatures => signatures.map { |signature| signature_evidence(signature) },
          :adopted => nil,
          :not_adopted => []
        }

        if target_info && target_info[:adopted]
          evidence[:adopted] = {
            :entity_id => target_info[:entity_id],
            :valid_until => target_info[:valid_until] && format_time(target_info[:valid_until]),
            :validity_limits => target_info[:validity_limits].map do |limit|
              {
                :source => limit[:source],
                :attribute => limit[:attribute],
                :value => format_time(limit[:value])
              }
            end,
            :coverage => target_info[:signatures].map { |signature| signature_summary(signature) },
            :sso_url => target_info[:settings].idp_sso_service_url,
            :sso_binding => target_info[:settings].idp_sso_service_binding,
            :signing_certificates => target_info[:settings].idp_cert_multi[:signing]
          }
        elsif target_info
          evidence[:not_adopted] << {
            :entity_id => target_id,
            :reasons => target_info[:reasons].map { |reason| reason[:code] },
            :messages => target_info[:reasons].map { |reason| reason[:message] },
            :valid_until => target_info[:valid_until] && format_time(target_info[:valid_until]),
            :covered_by_trusted_signature => target_info[:signatures].any?
          }
        end

        entity_infos.each do |info|
          next if info[:node].equal?(target)
          evidence[:not_adopted] << analyze_sibling(info, signatures, duplicate_entity_ids, target)
        end

        evidence
      end

      def signature_evidence(signature)
        referenced = signature[:referenced_node]
        {
          :owner_name => signature[:owner_name],
          :reference_id => signature[:reference_id],
          :referenced_name => referenced && referenced.name,
          :referenced_entity_id => signature[:referenced_entity_id],
          :valid => signature[:valid],
          :errors => signature[:errors],
          :signer_certificate => signature[:signer_certificate] && certificate_summary(signature[:signer_certificate]),
          :certificate_chain => signature[:certificate_chain].map { |certificate| certificate_summary(certificate) }
        }
      end

      def signature_summary(signature)
        {
          :reference_id => signature[:reference_id],
          :signer_subject => signature[:signer_certificate] && signature[:signer_certificate].subject.to_s
        }
      end

      def certificate_summary(certificate)
        {
          :subject => certificate.subject.to_s,
          :issuer => certificate.issuer.to_s,
          :serial => certificate.serial.to_s,
          :not_before => certificate.not_before.utc.iso8601,
          :not_after => certificate.not_after.utc.iso8601
        }
      end

      def reason(message, code)
        { :message => message, :code => code }
      end

      def rejected_result(errors, target_id, entity_infos, id_index, document,
                          duplicate_entity_ids: [], duplicate_ids: [])
        entity_infos ||= []
        signatures = document ? collect_signatures(document, id_index || {}) : []
        evidence = {
          :entity_id => target_id,
          :verification_time => format_time(@verification_time),
          :trust_anchors => @trust_anchors.map { |anchor| certificate_summary(anchor) },
          :duplicate_xml_ids => duplicate_ids.uniq.sort,
          :duplicate_entity_ids => duplicate_entity_ids,
          :signatures => signatures.map { |signature| signature_evidence(signature) },
          :adopted => nil,
          :not_adopted => entity_infos.map { |info| analyze_sibling(info, signatures, duplicate_entity_ids, nil) }
        }
        Result.new(nil, evidence, errors)
      end

      def parse_certificate(text, errors)
        return nil if text.nil? || text.to_s.strip.empty?

        der = Base64.strict_decode64(text.to_s.gsub(/\s+/, ""))
        OpenSSL::X509::Certificate.new(der)
      rescue ArgumentError, OpenSSL::X509::CertificateError => error
        errors << "Invalid X509Certificate: #{error.message}"
        nil
      end

      def normalize_trust_anchors(input)
        Array(input).flat_map do |anchor|
          case anchor
          when OpenSSL::X509::Certificate
            [anchor]
          when String
            blocks = anchor.scan(/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/m)
            blocks = [anchor] if blocks.empty?
            blocks.map { |block| OpenSSL::X509::Certificate.new(block) }
          else
            raise ArgumentError.new("trust_anchors must contain OpenSSL::X509::Certificate objects or PEM strings")
          end
        end
      end

      def coerce_time(value, name)
        case value
        when Time
          value.utc
        when String
          Time.iso8601(value).utc
        else
          raise ArgumentError.new("#{name} must be a Time or an ISO 8601 String")
        end
      rescue ArgumentError
        raise ArgumentError.new("#{name} must be a valid Time or ISO 8601 String")
      end

      def duplicate_document(document)
        # Serializing without pretty printing keeps every existing whitespace
        # text node, which is significant for the canonicalized digest.
        xml = document.to_xml(:save_with => Nokogiri::XML::Node::SaveOptions::AS_XML)
        Nokogiri::XML.parse(xml) { |config| config.strict.nonet }
      end

      def node_path(node)
        path = []
        current = node
        while current && current.respond_to?(:parent) && current.parent
          path.unshift(current.parent.children.index(current))
          current = current.parent
        end
        path
      end

      def node_at_path(document, path)
        current = document
        path.each do |index|
          return nil unless current && current.children
          current = current.children[index]
        end
        current
      end

      def find_by_id(document, id)
        nodes = document.xpath("//*[@ID=$id]", nil, { "id" => id })
        nodes.size == 1 ? nodes.first : nil
      end

      def ancestor_or_self?(ancestor, node)
        return false if ancestor.nil? || node.nil?
        return true if ancestor.equal?(node)
        node.ancestors.any? { |candidate| candidate.equal?(ancestor) }
      end

      def ds_child(node, local_name)
        ds_children(node, local_name).first
      end

      def ds_children(node, local_name)
        node.xpath("./*[local-name()=$ln and namespace-uri()=$ns]", nil,
                   { "ln" => local_name, "ns" => DSIG_NAMESPACE })
      end

      # path is [[name, max_count or nil], ...]; nil max_count means any.
      def ds_path(node, path)
        current = [node]
        path.each do |step|
          name, max = step
          current = current.flat_map do |parent|
            parent.xpath("./*[local-name()=$ln and namespace-uri()=$ns]", nil,
                         { "ln" => name, "ns" => DSIG_NAMESPACE })
          end
          current = current.first(max) if max
        end
        current
      end

      def secure_compare(left, right)
        return false unless left && right && left.bytesize == right.bytesize

        result = 0
        left.unpack("C*").zip(right.unpack("C*")) { |a, b| result |= a ^ b }
        result == 0
      end

      def format_time(time)
        time.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
      end
    end
  end
end
