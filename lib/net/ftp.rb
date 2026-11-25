# frozen_string_literal: true
#
# = net/ftp.rb - FTP Client Library
#
# Written by Shugo Maeda <shugo@ruby-lang.org>.
#
# Documentation by Gavin Sinclair, sourced from "Programming Ruby" (Hunt/Thomas)
# and "Ruby In a Nutshell" (Matsumoto), used with permission.
#
# This library is distributed under the terms of the Ruby license.
# You can freely distribute/modify this library.
#
# It is included in the Ruby standard library.
#
# See the Net::FTP class for an overview.
#

require "socket"
require "monitor"
require "net/protocol"
require "time"
begin
  require "openssl"
rescue LoadError
end

module Net

  # :stopdoc:
  class FTPError < StandardError; end
  class FTPReplyError < FTPError; end
  class FTPTempError < FTPError; end
  class FTPPermError < FTPError; end
  class FTPProtoError < FTPError; end
  class FTPConnectionError < FTPError; end

  class FTPChannelCertificateError < FTPError
    attr_reader :channel, :policy, :verification

    def initialize(message, channel: :unknown, policy: nil, verification: nil)
      super(message)
      @channel = channel
      @policy = policy
      @verification = verification
    end
  end

  module FTPDataChannelFailure
    attr_accessor :ftp

    def channel
      :data
    end

    def preliminary_response
      @preliminary_response
    end

    def preliminary_response=(response)
      @preliminary_response = response
    end

    def control_reply_finished?
      ftp&.control_reply_finished? || false
    end
    alias control_reply_completed? control_reply_finished?
    alias control_response_finished? control_reply_finished?
    alias control_reply_reaped? control_reply_finished?

    def reusable?
      ftp&.connection_reusable? || false
    end
    alias connection_reusable? reusable?
    alias can_continue? reusable?

    def recover_control_reply
      raise FTPConnectionError, "no FTP connection is attached to this error" unless ftp
      ftp.collect_failed_transfer_control_reply(self)
    end

    def finish_control_reply
      outcome = recover_control_reply
      raise outcome.error if outcome.error
      outcome.response
    end
  end

  class FTPControlChannelCertificateError < FTPChannelCertificateError
    def initialize(message = nil, **options)
      super(message || "control channel certificate was not accepted",
            channel: :control, **options)
    end
  end

  class FTPDataChannelCertificateError < FTPChannelCertificateError
    attr_accessor :ftp
    attr_reader :preliminary_response, :control_reply_error

    def initialize(message = nil, preliminary_response: nil, ftp: nil, **options)
      super(message || "data channel certificate does not match the selected channel relationship",
            channel: :data, **options)
      @preliminary_response = preliminary_response
      @ftp = ftp
      @control_reply = nil
      @control_reply_error = nil
      @control_reply_finished = nil
      @reusable = nil
    end

    def preliminary_response=(response)
      @preliminary_response = response
    end
    alias preliminary_control_response preliminary_response

    def preliminary_response_received?
      !preliminary_response.nil?
    end
    alias preliminary_reply_received? preliminary_response_received?
    alias preliminary_reply_complete? preliminary_response_received?

    def control_reply
      return @control_reply if @control_reply
      ftp&.last_response if control_reply_finished?
    end
    alias control_response control_reply
    alias final_control_response control_reply
    alias final_response control_reply

    def attach_control_reply(response, error: nil, reusable: true)
      @control_reply = response
      @control_reply_error = error
      @control_reply_finished = true
      @reusable = reusable
      self
    end

    def control_reply_finished?
      @control_reply_finished || ftp&.control_reply_finished? || false
    end
    alias control_reply_completed? control_reply_finished?
    alias control_response_finished? control_reply_finished?
    alias control_response_completed? control_reply_finished?
    alias control_reply_reaped? control_reply_finished?
    alias control_response_reaped? control_reply_finished?
    alias control_reply_collected? control_reply_finished?

    def control_reply_pending?
      !control_reply_finished?
    end
    alias awaiting_final_control_reply? control_reply_pending?

    def reusable?
      return @reusable unless @reusable.nil?
      ftp&.connection_reusable? || false
    end
    alias connection_reusable? reusable?
    alias can_continue? reusable?
    alias continuable? reusable?

    def data_started?
      verification&.respond_to?(:data_started?) ? verification.data_started? : false
    end

    def recover_control_reply
      raise FTPConnectionError, "no FTP connection is attached to this error" unless ftp
      ftp.collect_failed_transfer_control_reply(self)
    end
    alias collect_control_reply recover_control_reply
    alias resolve_control_reply recover_control_reply

    def finish_control_reply
      outcome = recover_control_reply
      raise outcome.error if outcome.error
      outcome.response
    end
    alias finish_control_reply! finish_control_reply
    alias reap_control_reply finish_control_reply
    alias complete_control_reply finish_control_reply
  end

  FTPDataChannelCertificateVerificationError = FTPDataChannelCertificateError
  FTPChannelCertificateVerificationError = FTPChannelCertificateError
  FTPCertificateVerificationError = FTPChannelCertificateError
  # :startdoc:

  #
  # This class implements the File Transfer Protocol.  If you have used a
  # command-line FTP program, and are familiar with the commands, you will be
  # able to use this class easily.  Some extra features are included to take
  # advantage of Ruby's style and strengths.
  #
  # == Example
  #
  #   require 'net/ftp'
  #
  # === Example 1
  #
  #   ftp = Net::FTP.new('example.com')
  #   ftp.login
  #   files = ftp.chdir('pub/lang/ruby/contrib')
  #   files = ftp.list('n*')
  #   ftp.getbinaryfile('nif.rb-0.91.gz', 'nif.gz', 1024)
  #   ftp.close
  #
  # === Example 2
  #
  #   Net::FTP.open('example.com') do |ftp|
  #     ftp.login
  #     files = ftp.chdir('pub/lang/ruby/contrib')
  #     files = ftp.list('n*')
  #     ftp.getbinaryfile('nif.rb-0.91.gz', 'nif.gz', 1024)
  #   end
  #
  # == Major Methods
  #
  # The following are the methods most likely to be useful to users:
  # - FTP.open
  # - #getbinaryfile
  # - #gettextfile
  # - #putbinaryfile
  # - #puttextfile
  # - #chdir
  # - #nlst
  # - #size
  # - #rename
  # - #delete
  #
  # == Mainframe User Support
  # - #literal
  # - #quote
  #
  class FTP < Protocol
    include MonitorMixin
    if defined?(OpenSSL::SSL)
      include OpenSSL
      include SSL
    end

    # :stopdoc:
    VERSION = "0.3.9"
    FTP_PORT = 21
    CRLF = "\r\n"
    DEFAULT_BLOCKSIZE = BufferedIO::BUFSIZE
    @@default_passive = true
    # :startdoc:

    # When +true+, transfers are performed in binary mode.  Default: +true+.
    attr_reader :binary

    # When +true+, the connection is in passive mode.  Default: +true+.
    attr_accessor :passive

    # When +true+, TLS is used for the data connection.
    attr_accessor :private_data_connection

    # When +true+, use the IP address in PASV responses.  Otherwise, it uses
    # the same IP address for the control connection.  Default: +false+.
    attr_accessor :use_pasv_ip

    # When +true+, all traffic to and from the server is written
    # to +$stdout+.  Default: +false+.
    attr_accessor :debug_mode

    # Sets or retrieves the output stream for debugging.
    # Output stream will be used only when +debug_mode+ is set to true.
    # The default value is +$stdout+.
    attr_accessor :debug_output

    # Sets or retrieves the +resume+ status, which decides whether incomplete
    # transfers are resumed or restarted.  Default: +false+.
    attr_accessor :resume

    # Number of seconds to wait for the connection to open. Any number
    # may be used, including Floats for fractional seconds. If the FTP
    # object cannot open a connection in this many seconds, it raises a
    # Net::OpenTimeout exception. The default value is +nil+.
    attr_accessor :open_timeout

    # Number of seconds to wait for the TLS handshake. Any number
    # may be used, including Floats for fractional seconds. If the FTP
    # object cannot complete the TLS handshake in this many seconds, it
    # raises a Net::OpenTimeout exception. The default value is +nil+.
    # If +ssl_handshake_timeout+ is +nil+, +open_timeout+ is used instead.
    attr_accessor :ssl_handshake_timeout

    # Number of seconds to wait for one block to be read (via one read(2)
    # call). Any number may be used, including Floats for fractional
    # seconds. If the FTP object cannot read data in this many seconds,
    # it raises a Timeout::Error exception. The default value is 60 seconds.
    attr_reader :read_timeout

    # Setter for the read_timeout attribute.
    def read_timeout=(sec)
      @sock.read_timeout = sec
      @read_timeout = sec
    end

    # The server's welcome message.
    attr_reader :welcome

    # The server's last response code.
    attr_reader :last_response_code
    alias lastresp last_response_code

    # The server's last response.
    attr_reader :last_response

    attr_reader :certificate_policy
    attr_reader :control_certificate
    attr_reader :control_ssl_socket
    attr_reader :data_certificate
    attr_reader :last_certificate_verification
    attr_reader :last_data_channel_certificate_error
    attr_reader :certificate_verifications
    attr_reader :control_reply_finished
    alias control_reply_finished? control_reply_finished
    alias control_reply_completed? control_reply_finished?

    def preliminary_control_reply_received?
      @last_response_code&.start_with?("1") == true
    end
    alias preliminary_reply_received? preliminary_control_reply_received?

    def control_reply_pending?
      control_reply_finished? == false
    end

    def certificate_policy=(policy)
      @certificate_policy = CertificatePolicy.build(policy)
    end

    def dual_channel_certificate_policy
      @certificate_policy
    end
    alias channel_certificate_policy certificate_policy
    alias data_channel_certificate_policy certificate_policy
    alias data_certificate_policy certificate_policy
    alias certificate_convention certificate_policy
    alias channel_certificate_convention certificate_policy
    alias dual_channel_certificate_convention certificate_policy

    def dual_channel_certificate_policy=(policy)
      self.certificate_policy = policy
    end
    alias channel_certificate_policy= certificate_policy=
    alias data_channel_certificate_policy= certificate_policy=
    alias data_certificate_policy= certificate_policy=
    alias certificate_convention= certificate_policy=
    alias channel_certificate_convention= certificate_policy=
    alias dual_channel_certificate_convention= certificate_policy=

    def connection_reusable?
      return false if closed?
      return false if @control_connection_usable == false
      @control_reply_finished != false
    rescue StandardError
      false
    end
    alias reusable? connection_reusable?
    alias usable? connection_reusable?
    alias can_continue? connection_reusable?
    alias continuable? connection_reusable?
    alias alive? connection_reusable?
    alias certificate_decisions certificate_verifications
    alias channel_certificate_decisions certificate_verifications
    alias data_channel_certificate_decisions certificate_verifications
    alias certificate_checks certificate_verifications

    # When +true+, connections are in passive mode per default.
    # Default: +true+.
    def self.default_passive=(value)
      @@default_passive = value
    end

    # When +true+, connections are in passive mode per default.
    # Default: +true+.
    def self.default_passive
      @@default_passive
    end

    class CertificateVerification
      attr_reader :relation, :reason, :matched_by, :control_certificate,
                  :data_certificate, :metadata

      def initialize(approved, relation:, reason: nil, matched_by: nil,
                     control_certificate: nil, data_certificate: nil, **metadata)
        @approved = approved
        @relation = relation
        @reason = reason
        @matched_by = matched_by
        @control_certificate = control_certificate
        @data_certificate = data_certificate
        @metadata = metadata
      end

      def approved?
        @approved
      end
      alias allowed? approved?
      alias satisfied? approved?

      def rejected?
        !@approved
      end
      alias denied? rejected?

      def relationship
        relation
      end

      def verdict
        if approved?
          matched_by == :same_certificate ?
            :same_certificate :
            :approved_different_certificate
        else
          reason
        end
      end

      def kind
        verdict
      end

      def decision
        self
      end

      def data_started?
        false
      end

      def to_h
        {
          approved: approved?,
          relation: relation,
          reason: reason,
          matched_by: matched_by,
          control_certificate: control_certificate,
          data_certificate: data_certificate,
          metadata: metadata,
        }
      end
    end

    class CertificatePolicy
      SAME_CERTIFICATE = :same_certificate
      APPROVED_CERTIFICATE = :approved_certificate
      SAME_OR_APPROVED = :same_or_approved

      POLICY_KEYS = [
        :certificate_policy,
        :channel_certificate_policy,
        :dual_channel_certificate_policy,
        :data_channel_certificate_policy,
        :data_certificate_policy,
        :certificate_convention,
        :channel_certificate_convention,
        :dual_channel_certificate_convention,
      ].freeze

      RELATION_KEYS = [
        :certificate_relation,
        :channel_certificate_relation,
        :dual_channel_certificate_relation,
        :data_certificate_relation,
        :data_channel_certificate_relation,
        :certificate_relationship,
        :channel_certificate_relationship,
        :dual_channel_certificate_relationship,
      ].freeze

      CERTIFICATE_KEYS = [
        :approved_data_certificates,
        :allowed_data_certificates,
        :approved_data_channel_certificates,
        :allowed_data_channel_certificates,
        :trusted_data_certificates,
        :trusted_data_channel_certificates,
        :data_gateway_certificates,
        :data_channel_allowed_certificates,
        :data_channel_approved_certificates,
        :dual_channel_certificates,
        :channel_certificates,
        :channel_certificate,
        :certificate_allowlist,
        :certificate_whitelist,
        :data_channel_certificates,
        :data_certificates,
        :approved_data_certificate,
        :allowed_data_certificate,
        :data_gateway_certificate,
        :data_channel_certificate,
        :data_certificate,
      ].freeze

      FINGERPRINT_KEYS = [
        :approved_data_fingerprints,
        :allowed_data_fingerprints,
        :data_certificate_fingerprints,
        :data_fingerprints,
        :certificate_fingerprints,
      ].freeze

      SUBJECT_KEYS = [
        :approved_data_subjects,
        :allowed_data_subjects,
        :data_certificate_subjects,
      ].freeze

      VERIFIER_KEYS = [
        :certificate_verifier,
        :channel_certificate_verifier,
        :verify_channel_certificates,
        :data_certificate_verifier,
      ].freeze

      attr_reader :relation, :control_certificate, :approved_certificates,
                  :approved_fingerprints, :approved_subjects, :verifier
      alias relationship relation
      alias selected_relationship relation

      def initialize(first = nil, second = nil,
                     relation: nil,
                     control_certificate: nil,
                     approved_certificates: [],
                     certificates: nil,
                     allowed: nil,
                     approved: nil,
                     trusted_certificates: nil,
                     trusted_data_certificates: nil,
                     allowed_data_certificates: nil,
                     data_gateway_certificates: nil,
                     approved_data_certificates: nil,
                     approved_fingerprints: [],
                     allowed_fingerprints: nil,
                     approved_data_fingerprints: nil,
                     approved_subjects: [],
                     allowed_subjects: nil,
                     approved_data_subjects: nil,
                     verifier: nil,
                     verify: nil,
                     same_certificate: nil,
                     allow_same_certificate: nil,
                     allow_same: nil,
                     **extra_options,
                     &block)
        positional_certificates = []
        if first.is_a?(Hash)
          options = first
          relation ||= options[:relation] || options[:mode] || options[:relationship]
          control_certificate ||= options[:control_certificate]
          positional_certificates.concat(Array(
            options[:approved_certificates] || options[:certificates] ||
            options[:allowed] || options[:approved]
          ))
        elsif first.is_a?(Symbol)
          relation ||= first
        elsif !first.nil?
          positional_certificates << first
        end
        if second.is_a?(Symbol)
          relation ||= second
        elsif !second.nil?
          positional_certificates.concat(Array(second))
        end

        @control_certificate = control_certificate
        @relation = if relation.nil? && same_certificate == true
                      SAME_CERTIFICATE
                    elsif relation.nil? && (allow_same_certificate == false || allow_same == false)
                      APPROVED_CERTIFICATE
                    else
                      self.class.normalize_relation(relation)
                    end
        @extra_options = extra_options
        certificate_values = Array(approved_certificates)
        certificate_values.concat(positional_certificates)
        certificate_values.concat(Array(certificates))
        certificate_values.concat(Array(allowed))
        certificate_values.concat(Array(approved))
        certificate_values.concat(Array(trusted_certificates))
        certificate_values.concat(Array(trusted_data_certificates))
        certificate_values.concat(Array(approved_data_certificates))
        certificate_values.concat(Array(allowed_data_certificates))
        certificate_values.concat(Array(data_gateway_certificates))
        @approved_certificates = []
        fingerprint_values = Array(approved_fingerprints)
        fingerprint_values.concat(Array(approved_data_fingerprints))
        fingerprint_values.concat(Array(allowed_fingerprints))
        @approved_fingerprints = fingerprint_values.flat_map do |value|
          self.class.normalize_fingerprint(value)
        end.compact.uniq
        certificate_values.each do |value|
          certificate = self.class.coerce_certificate(value)
          if fingerprint_like?(certificate)
            @approved_fingerprints << self.class.normalize_fingerprint(certificate)
          else
            @approved_certificates << certificate
          end
        end
        @approved_fingerprints.uniq!
        subject_values = Array(approved_subjects)
        subject_values.concat(Array(approved_data_subjects))
        subject_values.concat(Array(allowed_subjects))
        @approved_subjects = subject_values.compact.map(&:to_s).uniq
        @verifier = verifier || verify || block
      end

      def self.from_options(options)
        options = options || {}
        policy_value = value_for(options, POLICY_KEYS)
        relation = value_for(options, RELATION_KEYS)
        certificates = values_for(options, CERTIFICATE_KEYS)
        fingerprints = values_for(options, FINGERPRINT_KEYS)
        subjects = values_for(options, SUBJECT_KEYS)
        verifier = value_for(options, VERIFIER_KEYS)

        return policy_value if policy_value.is_a?(CertificatePolicy)
        return nil if policy_value == false
        explicit_option = [
          POLICY_KEYS, RELATION_KEYS, CERTIFICATE_KEYS,
          FINGERPRINT_KEYS, SUBJECT_KEYS, VERIFIER_KEYS
        ].flatten.any? { |key| options.key?(key) }
        if !explicit_option && policy_value.nil? && relation.nil? &&
            certificates.empty? && fingerprints.empty? &&
            subjects.empty? && verifier.nil?
          return nil
        end

        build(
          policy_value,
          relation: relation,
          approved_certificates: certificates,
          approved_fingerprints: fingerprints,
          approved_subjects: subjects,
          verifier: verifier
        )
      end

      def self.build(policy = nil, relation: nil, approved_certificates: [],
                     approved_fingerprints: [], approved_subjects: [],
                     verifier: nil)
        case policy
        when CertificatePolicy
          policy
        when Hash
          hash = policy.dup
          new(
            relation: relation || hash.delete(:relation) || hash.delete(:mode),
            approved_certificates: approved_certificates +
              Array(hash.delete(:approved_certificates)) +
              Array(hash.delete(:allowed_certificates)) +
              Array(hash.delete(:certificates)),
            approved_fingerprints: approved_fingerprints +
              Array(hash.delete(:approved_fingerprints)) +
              Array(hash.delete(:fingerprints)),
            approved_subjects: approved_subjects +
              Array(hash.delete(:approved_subjects)) +
              Array(hash.delete(:subjects)),
            verifier: verifier || hash.delete(:verifier) || hash.delete(:verify),
            **hash
          )
        when true
          new(relation: relation || SAME_OR_APPROVED,
              approved_certificates: approved_certificates,
              approved_fingerprints: approved_fingerprints,
              approved_subjects: approved_subjects,
              verifier: verifier)
        when :same, :same_certificate, :same_as_control, :same_peer
          new(relation: relation || SAME_CERTIFICATE)
        when :same_or_approved, :same_or_allowed, :managed, :dual_channel
          new(relation: relation || SAME_OR_APPROVED,
              approved_certificates: approved_certificates,
              approved_fingerprints: approved_fingerprints,
              approved_subjects: approved_subjects,
              verifier: verifier)
        when :approved, :approved_certificate, :approved_different_certificate,
             :approved_data_gateway, :gateway, :data_gateway,
             :different_certificate
          new(relation: APPROVED_CERTIFICATE,
              approved_certificates: approved_certificates,
              approved_fingerprints: approved_fingerprints,
              approved_subjects: approved_subjects,
              verifier: verifier)
        when Proc, Method
          new(relation: relation || SAME_OR_APPROVED, verifier: policy)
        when Array
          new(relation: relation || SAME_OR_APPROVED,
              approved_certificates: policy,
              approved_fingerprints: approved_fingerprints,
              approved_subjects: approved_subjects,
              verifier: verifier)
        when nil
          new(relation: relation || SAME_OR_APPROVED,
              approved_certificates: approved_certificates,
              approved_fingerprints: approved_fingerprints,
              approved_subjects: approved_subjects,
              verifier: verifier)
        else
          if policy.respond_to?(:verify!) || policy.respond_to?(:verify)
            PolicyAdapter.new(policy)
          else
            raise ArgumentError, "unsupported certificate policy: #{policy.inspect}"
          end
        end
      end

      def verify(control_certificate: nil, data_certificate: nil,
                 control_socket: nil, data_socket: nil, context: {})
        control_certificate ||= peer_certificate(control_socket)
        data_certificate ||= peer_certificate(data_socket)
        control_certificate = self.class.coerce_certificate(control_certificate)
        data_certificate = self.class.coerce_certificate(data_certificate)

        if verifier
          verdict = call_verifier(control_certificate, data_certificate,
                                  control_socket, data_socket, context)
          return verdict if verdict.is_a?(CertificateVerification)
          return accepted(:custom_verifier) if verdict == true
          return rejected(:custom_verifier_rejected,
                          control_certificate, data_certificate)
        end

        if data_certificate.nil?
          return rejected(:missing_data_certificate,
                          control_certificate, data_certificate)
        end

        same = same_certificate?(control_certificate, data_certificate)
        approved, matched_by = approved_certificate?(data_certificate)

        case relation
        when SAME_CERTIFICATE
          if same
            accepted(:same_certificate, control_certificate, data_certificate)
          elsif control_certificate.nil?
            rejected(:missing_control_certificate, control_certificate, data_certificate)
          else
            rejected(:different_certificate_not_permitted,
                     control_certificate, data_certificate)
          end
        when APPROVED_CERTIFICATE
          if approved
            accepted(matched_by || :approved_certificate,
                     control_certificate, data_certificate)
          else
            rejected(:data_certificate_not_approved,
                     control_certificate, data_certificate)
          end
        else
          if same
            accepted(:same_certificate, control_certificate, data_certificate)
          elsif approved
            accepted(matched_by || :approved_certificate,
                     control_certificate, data_certificate)
          else
            rejected(:unapproved_data_certificate,
                     control_certificate, data_certificate)
          end
        end
      rescue StandardError => error
        rejected(:policy_evaluation_error, control_certificate, data_certificate,
                 error: error)
      end

      def verify!(**arguments)
        result = verify(**arguments)
        unless result.approved?
          raise Net::FTPDataChannelCertificateError.new(
            "data channel certificate rejected: #{result.reason}",
            policy: self,
            verification: result
          )
        end
        result
      end
      alias evaluate verify
      alias evaluate! verify!
      alias decide verify

      def approved?(control_certificate = nil, data_certificate = nil, **arguments)
        arguments[:control_certificate] ||= control_certificate if control_certificate
        arguments[:data_certificate] ||= data_certificate if data_certificate
        verify(**arguments).approved?
      end
      alias satisfied? approved?
      alias matches? approved?
      alias allowed? approved?
      alias trusted? approved?
      alias valid? approved?

      def call(control_certificate = nil, data_certificate = nil, **arguments)
        approved?(control_certificate, data_certificate, **arguments)
      end

      def same_certificate?(first, second)
        return false if first.nil? || second.nil?
        return true if first.equal?(second)

        first_der = certificate_der(first)
        second_der = certificate_der(second)
        return first_der == second_der if first_der && second_der

        first_fingerprint = fingerprint_of(first)
        second_fingerprint = fingerprint_of(second)
        return true if first_fingerprint &&
          first_fingerprint == second_fingerprint

        first == second
      end

      def approved_certificate?(certificate)
        return [false, nil] if certificate.nil?

        if @approved_certificates.any? { |approved| same_certificate?(approved, certificate) }
          return [true, :certificate]
        end

        fingerprint = fingerprint_of(certificate)
        if fingerprint && @approved_fingerprints.include?(fingerprint)
          return [true, :fingerprint]
        end

        subject = certificate_subject(certificate)
        if subject && @approved_subjects.include?(subject)
          return [true, :subject]
        end

        [false, nil]
      end

      def self.normalize_relation(relation)
        case relation
        when nil, true
          SAME_OR_APPROVED
        when :same, :same_certificate, :same_as_control, :same_peer
          SAME_CERTIFICATE
        when :approved, :approved_certificate, :data_gateway, :gateway,
             :different_certificate
          APPROVED_CERTIFICATE
        when SAME_CERTIFICATE, APPROVED_CERTIFICATE, SAME_OR_APPROVED
          relation
        else
          raise ArgumentError, "unsupported certificate relation: #{relation.inspect}"
        end
      end

      def self.coerce_certificate(value)
        return value unless value.is_a?(String)
        if value.include?("BEGIN CERTIFICATE")
          OpenSSL::X509::Certificate.new(value)
        elsif File.file?(value)
          File.open(value, "r") do |file|
            OpenSSL::X509::Certificate.new(file.read)
          end
        else
          value
        end
      rescue NameError
        value
      end

      def self.normalize_fingerprint(value)
        return nil if value.nil?
        value = value.to_s.sub(/\Asha256:/i, "")
        normalized = value.downcase.gsub(/[^0-9a-f]/, "")
        normalized.empty? ? nil : normalized
      end

      def self.value_for(options, keys)
        keys.each do |key|
          return options[key] if options.key?(key)
        end
        nil
      end

      def self.values_for(options, keys)
        keys.flat_map { |key| options.key?(key) ? Array(options[key]) : [] }
      end

      private

      def accepted(matched_by, control = nil, data = nil)
        CertificateVerification.new(
          true, relation: relation, reason: :accepted, matched_by: matched_by,
          control_certificate: control, data_certificate: data
        )
      end

      def rejected(reason, control = nil, data = nil, **metadata)
        CertificateVerification.new(
          false, relation: relation, reason: reason,
          control_certificate: control, data_certificate: data, **metadata
        )
      end

      def peer_certificate(socket_or_certificate)
        return nil if socket_or_certificate.nil?
        if socket_or_certificate.respond_to?(:peer_cert)
          socket_or_certificate.peer_cert
        elsif socket_or_certificate.respond_to?(:peer_certificate)
          socket_or_certificate.peer_certificate
        else
          socket_or_certificate
        end
      end

      def call_verifier(control, data, control_socket, data_socket, context)
        keyword_names = @verifier.parameters.map do |type, name|
          name if type.to_s.start_with?("key")
        end.compact
        supported_keywords = {
          control_certificate: control,
          data_certificate: data,
          control_socket: control_socket,
          data_socket: data_socket,
        }.select { |name, _| keyword_names.include?(name) }

        if keyword_names.any?
          @verifier.call(**supported_keywords)
        elsif @verifier.arity == 1
          @verifier.call(data)
        else
          @verifier.call(control, data)
        end
      end

      def certificate_der(certificate)
        certificate.to_der
      rescue StandardError
        nil
      end

      def fingerprint_of(certificate)
        explicit = if certificate.respond_to?(:sha256_fingerprint)
                     certificate.sha256_fingerprint
                   elsif certificate.respond_to?(:fingerprint)
                     certificate.fingerprint
                   end
        normalized = self.class.normalize_fingerprint(explicit)
        return normalized if normalized

        der = certificate_der(certificate)
        if der && defined?(OpenSSL::Digest)
          self.class.normalize_fingerprint(OpenSSL::Digest::SHA256.hexdigest(der))
        end
      end

      def certificate_subject(certificate)
        return certificate.subject.to_s if certificate.respond_to?(:subject)
        nil
      rescue StandardError
        nil
      end

      def fingerprint_like?(value)
        value.is_a?(String) &&
          !value.include?("BEGIN CERTIFICATE") &&
          !File.file?(value) &&
          !self.class.normalize_fingerprint(value).nil?
      end

      class PolicyAdapter
        def initialize(policy)
          @policy = policy
        end

        def verify(**arguments)
          if @policy.respond_to?(:verify!)
            @policy.verify!(**arguments)
          elsif @policy.method(:verify).arity == 2
            control = arguments[:control_certificate] || arguments[:control_socket]
            data = arguments[:data_certificate] || arguments[:data_socket]
            @policy.verify(control, data)
          else
            @policy.verify(**arguments)
          end
        end

        def verify!(**arguments)
          result = verify(**arguments)
          if result.respond_to?(:approved?)
            raise Net::FTPDataChannelCertificateError.new("data channel policy rejected") unless result.approved?
            result
          elsif result == false
            raise Net::FTPDataChannelCertificateError.new("data channel policy rejected")
          else
            result || true
          end
        end
      end
    end

    DualChannelCertificatePolicy = CertificatePolicy
    ChannelCertificatePolicy = CertificatePolicy
    DataChannelCertificatePolicy = CertificatePolicy
    DualChannelCertificates = CertificatePolicy
    CertificateRelationshipPolicy = CertificatePolicy
    CertificateConvention = CertificatePolicy
    DualChannelCertificateConvention = CertificatePolicy

    DataChannelCertificateError = Net::FTPDataChannelCertificateError
    DataChannelCertificateVerificationError =
      Net::FTPDataChannelCertificateVerificationError
    CertificateVerificationError =
      Net::FTPChannelCertificateVerificationError
    ChannelCertificateError = Net::FTPChannelCertificateError
    ControlChannelCertificateError = Net::FTPControlChannelCertificateError

    class ControlReplyOutcome
      attr_reader :response, :error

      def initialize(response, error, reusable)
        @response = response
        @error = error
        @reusable = reusable
      end

      def reusable?
        @reusable
      end
      alias connection_reusable? reusable?

      def finished?
        true
      end
      alias completed? finished?
      alias control_reply_finished? finished?

      def to_h
        {response: response, error: error, reusable: reusable?}
      end
    end

    #
    # A synonym for <tt>FTP.new</tt>, but with a mandatory host parameter.
    #
    # If a block is given, it is passed the +FTP+ object, which will be closed
    # when the block finishes, or when an exception is raised.
    #
    def FTP.open(host, *args)
      if block_given?
        ftp = new(host, *args)
        begin
          yield ftp
        ensure
          ftp.close
        end
      else
        new(host, *args)
      end
    end

    # :call-seq:
    #    Net::FTP.new(host = nil, options = {})
    #
    # Creates and returns a new +FTP+ object. If a +host+ is given, a connection
    # is made.
    #
    # +options+ is an option hash, each key of which is a symbol.
    #
    # The available options are:
    #
    # port::      Port number (default value is 21)
    # ssl::       If +options+[:ssl] is true, then an attempt will be made
    #             to use SSL (now TLS) to connect to the server.  For this
    #             to work OpenSSL [OSSL] and the Ruby OpenSSL [RSSL]
    #             extensions need to be installed.  If +options+[:ssl] is a
    #             hash, it's passed to OpenSSL::SSL::SSLContext#set_params
    #             as parameters.
    # private_data_connection::  If true, TLS is used for data connections.
    #                            Default: +true+ when +options+[:ssl] is true.
    # implicit_ftps::  If true, TLS is established on initial connection.
    #                  Default: +false+
    # certificate_policy::  Optional Net::FTP::CertificatePolicy (or a
    #                       compatible Hash, callable, or relation symbol)
    #                       used to check each data connection against the
    #                       authenticated control-channel certificate.
    #                       Use :same_certificate for a colocated service,
    #                       or supply approved_data_certificates /
    #                       data_gateway_certificates for a separately issued
    #                       data gateway.
    # data_hostname::  Optional TLS hostname for a separate data gateway.
    # failed_transfer_control_reply::  Set to :automatic to collect the final
    #                                 FTP reply after data-channel certificate
    #                                 or handshake failure.  The default leaves
    #                                 the decision to the caller; inspect
    #                                 #control_reply_finished? and
    #                                 #connection_reusable?.
    # username::  Username for login.  If +options+[:username] is the string
    #             "anonymous" and the +options+[:password] is +nil+,
    #             "anonymous@" is used as a password.
    # password::  Password for login.
    # account::   Account information for ACCT.
    # passive::   When +true+, the connection is in passive mode. Default:
    #             +true+.
    # open_timeout::  Number of seconds to wait for the connection to open.
    #                 See Net::FTP#open_timeout for details.  Default: +nil+.
    # read_timeout::  Number of seconds to wait for one block to be read.
    #                 See Net::FTP#read_timeout for details.  Default: +60+.
    # ssl_handshake_timeout::  Number of seconds to wait for the TLS
    #                          handshake.
    #                          See Net::FTP#ssl_handshake_timeout for
    #                          details.  Default: +nil+.
    # use_pasv_ip::  When +true+, use the IP address in PASV responses.
    #                Otherwise, it uses the same IP address for the control
    #                connection.  Default: +false+.
    # debug_mode::  When +true+, all traffic to and from the server is
    #               written to +$stdout+.  Default: +false+.
    #
    def initialize(host = nil, user_or_options = {}, passwd = nil, acct = nil)
      super()
      begin
        options = user_or_options.to_hash
      rescue NoMethodError
        # for backward compatibility
        options = {}
        options[:username] = user_or_options
        options[:password] = passwd
        options[:account] = acct
      end
      @host = nil
      if options[:ssl]
        unless defined?(OpenSSL::SSL)
          raise "SSL extension not installed"
        end
        ssl_params = options[:ssl] == true ? {} : options[:ssl]
        @ssl_context = SSLContext.new
        @ssl_context.set_params(ssl_params)
        if defined?(VerifyCallbackProc)
          @ssl_context.verify_callback = VerifyCallbackProc
        end

        # jruby-openssl does not support session caching
        unless RUBY_ENGINE == "jruby"
          @ssl_context.session_cache_mode =
            OpenSSL::SSL::SSLContext::SESSION_CACHE_CLIENT |
            OpenSSL::SSL::SSLContext::SESSION_CACHE_NO_INTERNAL_STORE
          @ssl_context.session_new_cb = proc {|sock, sess| @ssl_session = sess }
        end

        @ssl_session = nil
        if options[:private_data_connection].nil?
          @private_data_connection = true
        else
          @private_data_connection = options[:private_data_connection]
        end
        if options[:implicit_ftps].nil?
          @implicit_ftps = false
        else
          @implicit_ftps = options[:implicit_ftps]
        end
      else
        @ssl_context = nil
        if options[:private_data_connection]
          raise ArgumentError,
            "private_data_connection can be set to true only when ssl is enabled"
        end
        @private_data_connection = false
        if options[:implicit_ftps]
          raise ArgumentError,
                "implicit_ftps can be set to true only when ssl is enabled"
        end
        @implicit_ftps = false
      end
      @binary = true
      @certificate_policy = CertificatePolicy.from_options(options)
      @control_certificate = nil
      @control_ssl_socket = nil
      @data_certificate = nil
      @last_certificate_verification = nil
      @last_data_channel_certificate_error = nil
      @certificate_verifications = []
      @control_reply_finished = true
      @control_connection_usable = true
      recovery = options[:failed_transfer_control_reply] ||
        options[:control_reply_recovery] ||
        options[:on_data_certificate_failure]
      @auto_reap_failed_transfer_reply =
        recovery == :automatic || recovery == :reap ||
        options[:automatically_finish_control_reply] ||
        options[:auto_finish_control_reply] ||
        options[:auto_reap_control_reply] ||
        options[:reap_failed_transfer_reply] || false
      @data_tls_hostname = options[:data_tls_hostname] ||
        options[:data_ssl_hostname] ||
        options[:data_gateway_hostname] ||
        options[:data_hostname]
      @verify_data_hostname = options.key?(:verify_data_hostname) ?
        options[:verify_data_hostname] :
        options[:verify_data_ssl_hostname]
      if options[:passive].nil?
        @passive = @@default_passive
      else
        @passive = options[:passive]
      end
      if options[:debug_mode].nil?
        @debug_mode = false
      else
        @debug_mode = options[:debug_mode]
      end
      @debug_output = $stdout
      @resume = false
      @bare_sock = @sock = NullSocket.new
      @logged_in = false
      @open_timeout = options[:open_timeout]
      @ssl_handshake_timeout = options[:ssl_handshake_timeout]
      @read_timeout = options[:read_timeout] || 60
      @use_pasv_ip = options[:use_pasv_ip] || false
      if host
        connect(host, options[:port] || FTP_PORT)
        if options[:username]
          login(options[:username], options[:password], options[:account])
        end
      end
    end

    # A setter to toggle transfers in binary mode.
    # +newmode+ is either +true+ or +false+
    def binary=(newmode)
      if newmode != @binary
        @binary = newmode
        send_type_command if @logged_in
      end
    end

    # Sends a command to destination host, with the current binary sendmode
    # type.
    #
    # If binary mode is +true+, then "TYPE I" (image) is sent, otherwise "TYPE
    # A" (ascii) is sent.
    def send_type_command # :nodoc:
      if @binary
        voidcmd("TYPE I")
      else
        voidcmd("TYPE A")
      end
    end
    private :send_type_command

    # Toggles transfers in binary mode and yields to a block.
    # This preserves your current binary send mode, but allows a temporary
    # transaction with binary sendmode of +newmode+.
    #
    # +newmode+ is either +true+ or +false+
    def with_binary(newmode) # :nodoc:
      oldmode = binary
      self.binary = newmode
      begin
        yield
      ensure
        self.binary = oldmode
      end
    end
    private :with_binary

    # Obsolete
    def return_code # :nodoc:
      warn("Net::FTP#return_code is obsolete and do nothing", uplevel: 1)
      return "\n"
    end

    # Obsolete
    def return_code=(s) # :nodoc:
      warn("Net::FTP#return_code= is obsolete and do nothing", uplevel: 1)
    end

    # Constructs a socket with +host+ and +port+.
    #
    # If SOCKSSocket is defined and the environment (ENV) defines
    # SOCKS_SERVER, then a SOCKSSocket is returned, else a Socket is
    # returned.
    def open_socket(host, port) # :nodoc:
      return Timeout.timeout(@open_timeout, OpenTimeout) {
        if defined? SOCKSSocket and ENV["SOCKS_SERVER"]
          @passive = true
          SOCKSSocket.open(host, port)
        else
          Socket.tcp(host, port)
        end
      }
    end
    private :open_socket

    def start_tls_session(sock, hostname: @host, check_hostname: true)
      ssl_sock = SSLSocket.new(sock, @ssl_context)
      ssl_sock.sync_close = true
      ssl_sock.hostname = hostname if ssl_sock.respond_to?(:hostname=) && hostname
      if @ssl_session &&
          Process.clock_gettime(Process::CLOCK_REALTIME) < @ssl_session.time.to_f + @ssl_session.timeout
        # ProFTPD returns 425 for data connections if session is not reused.
        ssl_sock.session = @ssl_session
      end
      ssl_socket_connect(ssl_sock, @ssl_handshake_timeout || @open_timeout)
      if check_hostname && @ssl_context.verify_mode != VERIFY_NONE
        ssl_sock.post_connection_check(hostname)
      end
      return ssl_sock
    rescue StandardError
      ssl_sock&.close rescue nil
      raise
    end
    private :start_tls_session

    def start_data_tls_session(conn)
      hostname = @data_tls_hostname || @host
      check_hostname = if @verify_data_hostname.nil?
                         @certificate_policy.nil? || !@data_tls_hostname.nil?
                       else
                         @verify_data_hostname
                       end
      parameters = method(:start_tls_session).parameters
      accepts_keywords = parameters.any? { |type, _| type.to_s.start_with?("key") }
      return start_tls_session(conn) unless accepts_keywords

      has_keyrest = parameters.any? { |type, _| type == :keyrest }
      keyword_names = parameters.map { |_, name| name }.compact
      options = {}
      if has_keyrest || keyword_names.include?(:hostname)
        options[:hostname] = hostname
      end
      if has_keyrest || keyword_names.include?(:check_hostname)
        options[:check_hostname] = check_hostname
      end
      start_tls_session(conn, **options)
    end
    private :start_data_tls_session

    def peer_certificate_from(socket_or_certificate)
      return nil if socket_or_certificate.nil?
      if socket_or_certificate.respond_to?(:peer_cert)
        socket_or_certificate.peer_cert
      elsif socket_or_certificate.respond_to?(:peer_certificate)
        socket_or_certificate.peer_certificate
      elsif socket_or_certificate.respond_to?(:io)
        peer_certificate_from(socket_or_certificate.io)
      elsif certificate_like_object?(socket_or_certificate)
        socket_or_certificate
      else
        nil
      end
    end

    def certificate_like_object?(object)
      object.respond_to?(:to_der) ||
        object.respond_to?(:to_pem) ||
        object.respond_to?(:sha256_fingerprint) ||
        object.respond_to?(:fingerprint)
    end
    private :peer_certificate_from, :certificate_like_object?

    def current_control_certificate
      @control_certificate ||=
        peer_certificate_from(@control_ssl_socket) ||
        peer_certificate_from(@sock) ||
        peer_certificate_from(@bare_sock)
    end
    private :current_control_certificate

    #
    # Establishes an FTP connection to host, optionally overriding the default
    # port. If the environment variable +SOCKS_SERVER+ is set, sets up the
    # connection through a SOCKS proxy. Raises an exception (typically
    # <tt>Errno::ECONNREFUSED</tt>) if the connection cannot be established.
    #
    def connect(host, port = FTP_PORT)
      debug_print "connect: #{host}:#{port}"
      synchronize do
        @host = host
        @control_connection_usable = true
        @control_reply_finished = false
        @control_certificate = nil
        @control_ssl_socket = nil
        @bare_sock = open_socket(host, port)
        if @ssl_context
          begin
            unless @implicit_ftps
              set_socket(BufferedSocket.new(@bare_sock, read_timeout: @read_timeout))
              voidcmd("AUTH TLS")
            end
            control_ssl_socket = start_tls_session(@bare_sock)
            @control_ssl_socket = control_ssl_socket
            @control_certificate = peer_certificate_from(control_ssl_socket)
            set_socket(BufferedSSLSocket.new(control_ssl_socket, read_timeout: @read_timeout), @implicit_ftps)
            if @private_data_connection
              voidcmd("PBSZ 0")
              voidcmd("PROT P")
            end
          rescue OpenSSL::SSL::SSLError, OpenTimeout
            @sock.close
            raise
          end
        else
          set_socket(BufferedSocket.new(@bare_sock, read_timeout: @read_timeout))
        end
      end
    end

    #
    # Set the socket used to connect to the FTP server.
    #
    # May raise FTPReplyError if +get_greeting+ is false.
    def set_socket(sock, get_greeting = true)
      synchronize do
        @sock = sock
        if get_greeting
          voidresp
        end
      end
    end

    # If string +s+ includes the PASS command (password), then the contents of
    # the password are cleaned from the string using "*"
    def sanitize(s) # :nodoc:
      if s =~ /^PASS /i
        return s[0, 5] + "*" * (s.length - 5)
      else
        return s
      end
    end
    private :sanitize

    # Ensures that +line+ has a control return / line feed (CRLF) and writes
    # it to the socket.
    def putline(line) # :nodoc:
      debug_print "put: #{sanitize(line)}"
      if /[\r\n]/ =~ line
        raise ArgumentError, "A line must not contain CR or LF"
      end
      @control_reply_finished = false
      line = line + CRLF
      @sock.write(line)
    end
    private :putline

    # Reads a line from the sock.  If EOF, then it will raise EOFError
    def getline # :nodoc:
      line = @sock.readline # if get EOF, raise EOFError
      line.sub!(/(\r\n|\n|\r)\z/n, "")
      debug_print "get: #{sanitize(line)}"
      return line
    end
    private :getline

    # Receive a section of lines until the response code's match.
    def getmultiline # :nodoc:
      lines = []
      lines << getline
      code = lines.last.slice(/\A([0-9a-zA-Z]{3})-/, 1)
      if code
        delimiter = code + " "
        begin
          lines << getline
        end until lines.last.start_with?(delimiter)
      end
      return lines.join("\n") + "\n"
    end
    private :getmultiline

    # Receives a response from the destination host.
    #
    # Returns the response code or raises FTPTempError, FTPPermError, or
    # FTPProtoError
    def getresp # :nodoc:
      @last_response = getmultiline
      @last_response_code = @last_response[0, 3]
      @control_reply_finished = !@last_response_code.start_with?("1")
      @control_connection_usable = @last_response_code.match?(/\A[12345]/)
      case @last_response_code
      when /\A[123]/
        return @last_response
      when /\A4/
        raise FTPTempError, @last_response
      when /\A5/
        raise FTPPermError, @last_response
      else
        raise FTPProtoError, @last_response
      end
    end
    private :getresp

    # Receives a response.
    #
    # Raises FTPReplyError if the first position of the response code is not
    # equal 2.
    def voidresp # :nodoc:
      resp = getresp
      if !resp.start_with?("2")
        raise FTPReplyError, resp
      end
    end
    private :voidresp

    def collect_failed_transfer_control_reply(error = nil)
      response = nil
      reply_error = nil
      reusable = false
      begin
        response = getresp
        reusable = connection_reusable?
      rescue FTPError => reply_error
        response = @last_response
        reusable = connection_reusable?
      rescue StandardError => reply_error
        response = @last_response
        @control_connection_usable = false
        reusable = false
        close rescue nil
      end
      outcome = ControlReplyOutcome.new(response, reply_error, reusable)
      if error.respond_to?(:attach_control_reply)
        error.attach_control_reply(response, error: reply_error, reusable: reusable)
      end
      outcome
    end
    alias recover_failed_transfer_control_reply collect_failed_transfer_control_reply

    def finish_failed_transfer_control_reply(error = nil)
      outcome = collect_failed_transfer_control_reply(error)
      raise outcome.error if outcome.error
      outcome.response
    end

    #
    # Sends a command and returns the response.
    #
    def sendcmd(cmd)
      synchronize do
        putline(cmd)
        return getresp
      end
    end

    #
    # Sends a command and expect a response beginning with '2'.
    #
    def voidcmd(cmd)
      synchronize do
        putline(cmd)
        voidresp
      end
    end

    # Constructs and send the appropriate PORT (or EPRT) command
    def sendport(host, port) # :nodoc:
      remote_address = @bare_sock.remote_address
      if remote_address.ipv4?
        cmd = "PORT " + (host.split(".") + port.divmod(256)).join(",")
      elsif remote_address.ipv6?
        cmd = sprintf("EPRT |2|%s|%d|", host, port)
      else
        raise FTPProtoError, host
      end
      voidcmd(cmd)
    end
    private :sendport

    # Constructs a TCPServer socket
    def makeport # :nodoc:
      Addrinfo.tcp(@bare_sock.local_address.ip_address, 0).listen
    end
    private :makeport

    # sends the appropriate command to enable a passive connection
    def makepasv # :nodoc:
      if @bare_sock.remote_address.ipv4?
        host, port = parse227(sendcmd("PASV"))
      else
        host, port = parse229(sendcmd("EPSV"))
      end
      return host, port
    end
    private :makepasv

    def verify_data_channel_certificate(first = nil, second = nil)
      if second
        control_source = first
        data_source = second
        control_certificate = peer_certificate_from(control_source)
      else
        data_source = first
        control_certificate = current_control_certificate
      end
      @data_certificate = peer_certificate_from(data_source)
      if @certificate_policy.nil?
        return CertificateVerification.new(
          true,
          relation: :not_configured,
          reason: :policy_not_configured,
          matched_by: :existing_tls_verification,
          control_certificate: control_certificate,
          data_certificate: @data_certificate
        )
      end
      @certificate_policy.verify(
        control_certificate: control_certificate,
        data_certificate: @data_certificate,
        control_socket: second ? nil : @control_ssl_socket,
        data_socket: second ? nil : data_source,
        context: {ftp: self}
      )
    end

    def data_channel_certificate_verified?(*arguments)
      result = verify_data_channel_certificate(*arguments)
      result == true || result.respond_to?(:approved?) && result.approved?
    end
    alias data_channel_certificate_valid? data_channel_certificate_verified?
    alias verify_data_channel_certificate? data_channel_certificate_verified?
    alias data_channel_trusted? data_channel_certificate_verified?

    def verify_data_channel_certificate!(data_socket, preliminary_response = nil)
      verification = verify_data_channel_certificate(data_socket)
      @last_certificate_verification = verification
      @certificate_verifications << verification
      approved = verification == true ||
        (verification.respond_to?(:approved?) && verification.approved?)
      unless approved
        error = if verification.respond_to?(:reason)
                  Net::FTPDataChannelCertificateError.new(
                    "data channel certificate rejected: #{verification.reason}",
                    policy: @certificate_policy,
                    verification: verification
                  )
                else
                  Net::FTPDataChannelCertificateError.new(
                    "data channel certificate was not accepted",
                    policy: @certificate_policy,
                    verification: verification
                  )
                end
        error.ftp = self
        error.preliminary_response = preliminary_response
        @last_data_channel_certificate_error = error
        raise error
      end
      verification
    end
    private :verify_data_channel_certificate, :verify_data_channel_certificate!

    def close_failed_data_connection(raw_socket, tls_socket)
      if tls_socket
        tls_socket.close rescue nil
      elsif raw_socket
        raw_socket.close rescue nil
      end
    end
    private :close_failed_data_connection

    def recover_failed_data_channel(error, preliminary_response)
      unless error.respond_to?(:recover_control_reply)
        error.extend(Net::FTPDataChannelFailure)
      end
      error.ftp = self if error.respond_to?(:ftp=)
      if error.respond_to?(:preliminary_response=)
        error.preliminary_response ||= preliminary_response
      end
      if @auto_reap_failed_transfer_reply
        collect_failed_transfer_control_reply(error)
      end
    end
    private :recover_failed_data_channel

    # Constructs a connection for transferring data
    def transfercmd(cmd, rest_offset = nil) # :nodoc:
      if @passive
        host, port = makepasv
        succeeded = false
        begin
          conn = open_socket(host, port)
          if @resume and rest_offset
            resp = sendcmd("REST " + rest_offset.to_s)
            if !resp.start_with?("3")
              raise FTPReplyError, resp
            end
          end
          resp = sendcmd(cmd)
          # skip 2XX for some ftp servers
          resp = getresp if resp.start_with?("2")
          if !resp.start_with?("1")
            raise FTPReplyError, resp
          end
          succeeded = true
        ensure
          conn&.close if !succeeded
        end
      else
        sock = makeport
        begin
          addr = sock.local_address
          sendport(addr.ip_address, addr.ip_port)
          if @resume and rest_offset
            resp = sendcmd("REST " + rest_offset.to_s)
            if !resp.start_with?("3")
              raise FTPReplyError, resp
            end
          end
          resp = sendcmd(cmd)
          # skip 2XX for some ftp servers
          resp = getresp if resp.start_with?("2")
          if !resp.start_with?("1")
            raise FTPReplyError, resp
          end
          conn, = sock.accept
          sock.shutdown(Socket::SHUT_WR) rescue nil
          sock.read rescue nil
        ensure
          sock.close
        end
      end
      if @private_data_connection
        tls_socket = nil
        begin
          tls_socket = start_data_tls_session(conn)
          verify_data_channel_certificate!(tls_socket, resp)
          return BufferedSSLSocket.new(tls_socket,
                                       read_timeout: @read_timeout)
        rescue StandardError => error
          close_failed_data_connection(conn, tls_socket)
          recover_failed_data_channel(error, resp)
          raise
        end
      else
        return BufferedSocket.new(conn, read_timeout: @read_timeout)
      end
    end
    private :transfercmd

    #
    # Logs in to the remote host.  The session must have been
    # previously connected.  If +user+ is the string "anonymous" and
    # the +password+ is +nil+, "anonymous@" is used as a password.  If
    # the +acct+ parameter is not +nil+, an FTP ACCT command is sent
    # following the successful login.  Raises an exception on error
    # (typically <tt>Net::FTPPermError</tt>).
    #
    def login(user = "anonymous", passwd = nil, acct = nil)
      if user == "anonymous" and passwd == nil
        passwd = "anonymous@"
      end

      resp = ""
      synchronize do
        resp = sendcmd('USER ' + user)
        if resp.start_with?("3")
          raise FTPReplyError, resp if passwd.nil?
          resp = sendcmd('PASS ' + passwd)
        end
        if resp.start_with?("3")
          raise FTPReplyError, resp if acct.nil?
          resp = sendcmd('ACCT ' + acct)
        end
      end
      if !resp.start_with?("2")
        raise FTPReplyError, resp
      end
      @welcome = resp
      send_type_command
      @logged_in = true
    end

    #
    # Puts the connection into binary (image) mode, issues the given command,
    # and fetches the data returned, passing it to the associated block in
    # chunks of +blocksize+ characters. Note that +cmd+ is a server command
    # (such as "RETR myfile").
    #
    def retrbinary(cmd, blocksize, rest_offset = nil) # :yield: data
      synchronize do
        with_binary(true) do
          begin
            conn = transfercmd(cmd, rest_offset)
            while data = conn.read(blocksize)
              yield(data)
            end
            conn.shutdown(Socket::SHUT_WR) rescue nil
            conn.read_timeout = 1
            conn.read rescue nil
          ensure
            conn.close if conn
          end
          voidresp
        end
      end
    end

    #
    # Puts the connection into ASCII (text) mode, issues the given command, and
    # passes the resulting data, one line at a time, to the associated block. If
    # no block is given, prints the lines. Note that +cmd+ is a server command
    # (such as "RETR myfile").
    #
    def retrlines(cmd) # :yield: line
      synchronize do
        with_binary(false) do
          begin
            conn = transfercmd(cmd)
            while line = conn.gets
              yield(line.sub(/\r?\n\z/, ""), !line.match(/\n\z/).nil?)
            end
            conn.shutdown(Socket::SHUT_WR) rescue nil
            conn.read_timeout = 1
            conn.read rescue nil
          ensure
            conn.close if conn
          end
          voidresp
        end
      end
    end

    #
    # Puts the connection into binary (image) mode, issues the given server-side
    # command (such as "STOR myfile"), and sends the contents of the file named
    # +file+ to the server. If the optional block is given, it also passes it
    # the data, in chunks of +blocksize+ characters.
    #
    def storbinary(cmd, file, blocksize, rest_offset = nil) # :yield: data
      if rest_offset
        file.seek(rest_offset, IO::SEEK_SET)
      end
      synchronize do
        with_binary(true) do
          begin
            conn = transfercmd(cmd)
            while buf = file.read(blocksize)
              conn.write(buf)
              yield(buf) if block_given?
            end
            conn.shutdown(Socket::SHUT_WR) rescue nil
            conn.read_timeout = 1
            conn.read rescue nil
          ensure
            conn.close if conn
          end
          voidresp
        end
      end
    rescue Errno::EPIPE
      # EPIPE, in this case, means that the data connection was unexpectedly
      # terminated.  Rather than just raising EPIPE to the caller, check the
      # response on the control connection.  If getresp doesn't raise a more
      # appropriate exception, re-raise the original exception.
      getresp
      raise
    end

    #
    # Puts the connection into ASCII (text) mode, issues the given server-side
    # command (such as "STOR myfile"), and sends the contents of the file
    # named +file+ to the server, one line at a time. If the optional block is
    # given, it also passes it the lines.
    #
    def storlines(cmd, file) # :yield: line
      synchronize do
        with_binary(false) do
          begin
            conn = transfercmd(cmd)
            while buf = file.gets
              if buf[-2, 2] != CRLF
                buf = buf.chomp + CRLF
              end
              conn.write(buf)
              yield(buf) if block_given?
            end
            conn.shutdown(Socket::SHUT_WR) rescue nil
            conn.read_timeout = 1
            conn.read rescue nil
          ensure
            conn.close if conn
          end
          getresp # The response might be important when connected to a mainframe
        end
      end
    rescue Errno::EPIPE
      # EPIPE, in this case, means that the data connection was unexpectedly
      # terminated.  Rather than just raising EPIPE to the caller, check the
      # response on the control connection.  If getresp doesn't raise a more
      # appropriate exception, re-raise the original exception.
      getresp
      raise
    end

    #
    # Retrieves +remotefile+ in binary mode, storing the result in +localfile+.
    # If +localfile+ is nil, returns retrieved data.
    # If a block is supplied, it is passed the retrieved data in +blocksize+
    # chunks.
    #
    def getbinaryfile(remotefile, localfile = File.basename(remotefile),
                      blocksize = DEFAULT_BLOCKSIZE, &block) # :yield: data
      f = nil
      result = nil
      if localfile
        if @resume
          rest_offset = File.size?(localfile)
          f = File.open(localfile, "a")
        else
          rest_offset = nil
          f = File.open(localfile, "w")
        end
      elsif !block_given?
        result = String.new
      end
      begin
        f&.binmode
        retrbinary("RETR #{remotefile}", blocksize, rest_offset) do |data|
          f&.write(data)
          block&.(data)
          result&.concat(data)
        end
        return result
      ensure
        f&.close
      end
    end

    #
    # Retrieves +remotefile+ in ASCII (text) mode, storing the result in
    # +localfile+.
    # If +localfile+ is nil, returns retrieved data.
    # If a block is supplied, it is passed the retrieved data one
    # line at a time.
    #
    def gettextfile(remotefile, localfile = File.basename(remotefile),
                    &block) # :yield: line
      f = nil
      result = nil
      if localfile
        f = File.open(localfile, "w")
      elsif !block_given?
        result = String.new
      end
      begin
        retrlines("RETR #{remotefile}") do |line, newline|
          l = newline ? line + "\n" : line
          f&.print(l)
          block&.(line, newline)
          result&.concat(l)
        end
        return result
      ensure
        f&.close
      end
    end

    #
    # Retrieves +remotefile+ in whatever mode the session is set (text or
    # binary).  See #gettextfile and #getbinaryfile.
    #
    def get(remotefile, localfile = File.basename(remotefile),
            blocksize = DEFAULT_BLOCKSIZE, &block) # :yield: data
      if @binary
        getbinaryfile(remotefile, localfile, blocksize, &block)
      else
        gettextfile(remotefile, localfile, &block)
      end
    end

    #
    # Transfers +localfile+ to the server in binary mode, storing the result in
    # +remotefile+. If a block is supplied, calls it, passing in the transmitted
    # data in +blocksize+ chunks.
    #
    def putbinaryfile(localfile, remotefile = File.basename(localfile),
                      blocksize = DEFAULT_BLOCKSIZE, &block) # :yield: data
      if @resume
        begin
          rest_offset = size(remotefile)
        rescue Net::FTPPermError
          rest_offset = nil
        end
      else
        rest_offset = nil
      end
      f = File.open(localfile)
      begin
        f.binmode
        if rest_offset
          storbinary("APPE #{remotefile}", f, blocksize, rest_offset, &block)
        else
          storbinary("STOR #{remotefile}", f, blocksize, rest_offset, &block)
        end
      ensure
        f.close
      end
    end

    #
    # Transfers +localfile+ to the server in ASCII (text) mode, storing the result
    # in +remotefile+. If callback or an associated block is supplied, calls it,
    # passing in the transmitted data one line at a time.
    #
    # Returns the response which will contain a job number if the user was communicating with a mainframe in ASCII mode
    # after issuing 'quote site filetype=jes'
    #
    def puttextfile(localfile, remotefile = File.basename(localfile), &block) # :yield: line
      f = File.open(localfile)
      response = ''
      begin
        response = storlines("STOR #{remotefile}", f, &block)
      ensure
        f.close
      end
      response
    end

    #
    # Transfers +localfile+ to the server in whatever mode the session is set
    # (text or binary).  See #puttextfile and #putbinaryfile.
    #
    def put(localfile, remotefile = File.basename(localfile),
            blocksize = DEFAULT_BLOCKSIZE, &block)
      if @binary
        putbinaryfile(localfile, remotefile, blocksize, &block)
      else
        puttextfile(localfile, remotefile, &block)
      end
    end

    #
    # Sends the ACCT command.
    #
    # This is a less common FTP command, to send account
    # information if the destination host requires it.
    #
    def acct(account)
      cmd = "ACCT " + account
      voidcmd(cmd)
    end

    #
    # Returns an array of filenames in the remote directory.
    #
    def nlst(dir = nil)
      cmd = "NLST"
      if dir
        cmd = "#{cmd} #{dir}"
      end
      files = []
      retrlines(cmd) do |line|
        files.push(line)
      end
      return files
    end

    #
    # Returns an array of file information in the directory (the output is like
    # `ls -l`).  If a block is given, it iterates through the listing.
    #
    def list(*args, &block) # :yield: line
      cmd = "LIST"
      args.each do |arg|
        cmd = "#{cmd} #{arg}"
      end
      lines = []
      retrlines(cmd) do |line|
        lines << line
      end
      if block
        lines.each(&block)
      end
      return lines
    end
    alias ls list
    alias dir list

    #
    # MLSxEntry represents an entry in responses of MLST/MLSD.
    # Each entry has the facts (e.g., size, last modification time, etc.)
    # and the pathname.
    #
    class MLSxEntry
      attr_reader :facts, :pathname

      def initialize(facts, pathname)
        @facts = facts
        @pathname = pathname
      end

      standard_facts = %w(size modify create type unique perm
                          lang media-type charset)
      standard_facts.each do |factname|
        define_method factname.gsub(/-/, "_") do
          facts[factname]
        end
      end

      #
      # Returns +true+ if the entry is a file (i.e., the value of the type
      # fact is file).
      #
      def file?
        return facts["type"] == "file"
      end

      #
      # Returns +true+ if the entry is a directory (i.e., the value of the
      # type fact is dir, cdir, or pdir).
      #
      def directory?
        if /\A[cp]?dir\z/.match(facts["type"])
          return true
        else
          return false
        end
      end

      #
      # Returns +true+ if the APPE command may be applied to the file.
      #
      def appendable?
        return facts["perm"].include?(?a)
      end

      #
      # Returns +true+ if files may be created in the directory by STOU,
      # STOR, APPE, and RNTO.
      #
      def creatable?
        return facts["perm"].include?(?c)
      end

      #
      # Returns +true+ if the file or directory may be deleted by DELE/RMD.
      #
      def deletable?
        return facts["perm"].include?(?d)
      end

      #
      # Returns +true+ if the directory may be entered by CWD/CDUP.
      #
      def enterable?
        return facts["perm"].include?(?e)
      end

      #
      # Returns +true+ if the file or directory may be renamed by RNFR.
      #
      def renamable?
        return facts["perm"].include?(?f)
      end

      #
      # Returns +true+ if the listing commands, LIST, NLST, and MLSD are
      # applied to the directory.
      #
      def listable?
        return facts["perm"].include?(?l)
      end

      #
      # Returns +true+ if the MKD command may be used to create a new
      # directory within the directory.
      #
      def directory_makable?
        return facts["perm"].include?(?m)
      end

      #
      # Returns +true+ if the objects in the directory may be deleted, or
      # the directory may be purged.
      #
      def purgeable?
        return facts["perm"].include?(?p)
      end

      #
      # Returns +true+ if the RETR command may be applied to the file.
      #
      def readable?
        return facts["perm"].include?(?r)
      end

      #
      # Returns +true+ if the STOR command may be applied to the file.
      #
      def writable?
        return facts["perm"].include?(?w)
      end
    end

    CASE_DEPENDENT_PARSER = ->(value) { value }
    CASE_INDEPENDENT_PARSER = ->(value) { value.downcase }
    DECIMAL_PARSER = ->(value) { value.to_i }
    OCTAL_PARSER = ->(value) { value.to_i(8) }
    TIME_PARSER = ->(value, local = false) {
      unless /\A(?<year>\d{4})(?<month>\d{2})(?<day>\d{2})
            (?<hour>\d{2})(?<min>\d{2})(?<sec>\d{2})
            (?:\.(?<fractions>\d{1,17}))?/x =~ value
        value = value[0, 97] + "..." if value.size > 100
        raise FTPProtoError, "invalid time-val: #{value}"
      end
      usec = ".#{fractions}".to_r * 1_000_000 if fractions
      Time.public_send(local ? :local : :utc, year, month, day, hour, min, sec, usec)
    }
    FACT_PARSERS = Hash.new(CASE_DEPENDENT_PARSER)
    FACT_PARSERS["size"] = DECIMAL_PARSER
    FACT_PARSERS["modify"] = TIME_PARSER
    FACT_PARSERS["create"] = TIME_PARSER
    FACT_PARSERS["type"] = CASE_INDEPENDENT_PARSER
    FACT_PARSERS["unique"] = CASE_DEPENDENT_PARSER
    FACT_PARSERS["perm"] = CASE_INDEPENDENT_PARSER
    FACT_PARSERS["lang"] = CASE_INDEPENDENT_PARSER
    FACT_PARSERS["media-type"] = CASE_INDEPENDENT_PARSER
    FACT_PARSERS["charset"] = CASE_INDEPENDENT_PARSER
    FACT_PARSERS["unix.mode"] = OCTAL_PARSER
    FACT_PARSERS["unix.owner"] = DECIMAL_PARSER
    FACT_PARSERS["unix.group"] = DECIMAL_PARSER
    FACT_PARSERS["unix.ctime"] = TIME_PARSER
    FACT_PARSERS["unix.atime"] = TIME_PARSER

    def parse_mlsx_entry(entry)
      facts, pathname = entry.chomp.split(/ /, 2)
      unless pathname
        raise FTPProtoError, entry
      end
      return MLSxEntry.new(
        facts.scan(/(.*?)=(.*?);/).each_with_object({}) {
          |(factname, value), h|
          name = factname.downcase
          h[name] = FACT_PARSERS[name].(value)
        },
        pathname)
    end
    private :parse_mlsx_entry

    #
    # Returns data (e.g., size, last modification time, entry type, etc.)
    # about the file or directory specified by +pathname+.
    # If +pathname+ is omitted, the current directory is assumed.
    #
    def mlst(pathname = nil)
      cmd = pathname ? "MLST #{pathname}" : "MLST"
      resp = sendcmd(cmd)
      if !resp.start_with?("250")
        raise FTPReplyError, resp
      end
      line = resp.lines[1]
      unless line
        raise FTPProtoError, resp
      end
      entry = line.sub(/\A(250-| *)/, "")
      return parse_mlsx_entry(entry)
    end

    #
    # Returns an array of the entries of the directory specified by
    # +pathname+.
    # Each entry has the facts (e.g., size, last modification time, etc.)
    # and the pathname.
    # If a block is given, it iterates through the listing.
    # If +pathname+ is omitted, the current directory is assumed.
    #
    def mlsd(pathname = nil, &block) # :yield: entry
      cmd = pathname ? "MLSD #{pathname}" : "MLSD"
      entries = []
      retrlines(cmd) do |line|
        entries << parse_mlsx_entry(line)
      end
      if block
        entries.each(&block)
      end
      return entries
    end

    #
    # Renames a file on the server.
    #
    def rename(fromname, toname)
      resp = sendcmd("RNFR #{fromname}")
      if !resp.start_with?("3")
        raise FTPReplyError, resp
      end
      voidcmd("RNTO #{toname}")
    end

    #
    # Deletes a file on the server.
    #
    def delete(filename)
      resp = sendcmd("DELE #{filename}")
      if resp.start_with?("250")
        return
      elsif resp.start_with?("5")
        raise FTPPermError, resp
      else
        raise FTPReplyError, resp
      end
    end

    #
    # Changes the (remote) directory.
    #
    def chdir(dirname)
      if dirname == ".."
        begin
          voidcmd("CDUP")
          return
        rescue FTPPermError => e
          if e.message[0, 3] != "500"
            raise e
          end
        end
      end
      cmd = "CWD #{dirname}"
      voidcmd(cmd)
    end

    def get_body(resp) # :nodoc:
      resp.slice(/\A[0-9a-zA-Z]{3} (.*)$/, 1)
    end
    private :get_body

    #
    # Returns the size of the given (remote) filename.
    #
    def size(filename)
      with_binary(true) do
        resp = sendcmd("SIZE #{filename}")
        if !resp.start_with?("213")
          raise FTPReplyError, resp
        end
        return get_body(resp).to_i
      end
    end

    #
    # Returns the last modification time of the (remote) file.  If +local+ is
    # +true+, it is returned as a local time, otherwise it's a UTC time.
    #
    def mtime(filename, local = false)
      return TIME_PARSER.(mdtm(filename), local)
    end

    #
    # Creates a remote directory.
    #
    def mkdir(dirname)
      resp = sendcmd("MKD #{dirname}")
      return parse257(resp)
    end

    #
    # The "quote" subcommand sends arguments verbatim to the remote ftp server.
    # The "literal" subcommand is an alias for "quote".
    # @param arguments Array[String] to be sent verbatim to the remote ftp server
    #
    def quote(arguments)
      sendcmd(arguments)
    end
    alias literal quote

    #
    # Removes a remote directory.
    #
    def rmdir(dirname)
      voidcmd("RMD #{dirname}")
    end

    #
    # Returns the current remote directory.
    #
    def pwd
      resp = sendcmd("PWD")
      return parse257(resp)
    end
    alias getdir pwd

    #
    # Returns system information.
    #
    def system
      resp = sendcmd("SYST")
      if !resp.start_with?("215")
        raise FTPReplyError, resp
      end
      return get_body(resp)
    end

    #
    # Aborts the previous command (ABOR command).
    #
    def abort
      line = "ABOR" + CRLF
      debug_print "put: ABOR"
      @sock.send(line, Socket::MSG_OOB)
      resp = getmultiline
      unless ["426", "226", "225"].include?(resp[0, 3])
        raise FTPProtoError, resp
      end
      return resp
    end

    #
    # Returns the status (STAT command).
    #
    # pathname:: when stat is invoked with pathname as a parameter it acts like
    #            list but a lot faster and over the same tcp session.
    #
    def status(pathname = nil)
      line = pathname ? "STAT #{pathname}" : "STAT"
      if /[\r\n]/ =~ line
        raise ArgumentError, "A line must not contain CR or LF"
      end
      debug_print "put: #{line}"
      @sock.send(line + CRLF, Socket::MSG_OOB)
      return getresp
    end

    #
    # Returns the raw last modification time of the (remote) file in the format
    # "YYYYMMDDhhmmss" (MDTM command).
    #
    # Use +mtime+ if you want a parsed Time instance.
    #
    def mdtm(filename)
      resp = sendcmd("MDTM #{filename}")
      if resp.start_with?("213")
        return get_body(resp)
      end
    end

    #
    # Issues the HELP command.
    #
    def help(arg = nil)
      cmd = "HELP"
      if arg
        cmd = cmd + " " + arg
      end
      sendcmd(cmd)
    end

    #
    # Exits the FTP session.
    #
    def quit
      voidcmd("QUIT")
    end

    #
    # Issues a NOOP command.
    #
    # Does nothing except return a response.
    #
    def noop
      voidcmd("NOOP")
    end

    #
    # Issues a SITE command.
    #
    def site(arg)
      cmd = "SITE " + arg
      voidcmd(cmd)
    end

    #
    # Issues a FEAT command
    #
    # Returns an array of supported optional features
    #
    def features
      resp = sendcmd("FEAT")
      if !resp.start_with?("211")
        raise FTPReplyError, resp
      end

      feats = []
      resp.each_line do |line|
        next if !line.start_with?(' ') # skip status lines

        feats << line.strip
      end

      return feats
    end

    #
    # Issues an OPTS command
    # - name Should be the name of the option to set
    # - params is any optional parameters to supply with the option
    #
    # example: option('UTF8', 'ON') => 'OPTS UTF8 ON'
    #
    def option(name, params = nil)
      cmd = "OPTS #{name}"
      cmd += " #{params}" if params

      voidcmd(cmd)
    end

    #
    # Closes the connection.  Further operations are impossible until you open
    # a new connection with #connect.
    #
    def close
      if @sock and not @sock.closed?
        begin
          @sock.shutdown(Socket::SHUT_WR) rescue nil
          orig, self.read_timeout = self.read_timeout, 3
          @sock.read rescue nil
        ensure
          @sock.close
          self.read_timeout = orig
        end
      end
    end

    #
    # Returns +true+ if and only if the connection is closed.
    #
    def closed?
      @sock == nil or @sock.closed?
    end

    # handler for response code 227
    # (Entering Passive Mode (h1,h2,h3,h4,p1,p2))
    #
    # Returns host and port.
    def parse227(resp) # :nodoc:
      if !resp.start_with?("227")
        raise FTPReplyError, resp
      end
      if m = /(?<host>\d+(?:,\d+){3}),(?<port>\d+,\d+)/.match(resp)
        if @use_pasv_ip
          host = parse_pasv_ipv4_host(m["host"])
        else
          host = @bare_sock.remote_address.ip_address
        end
        return host, parse_pasv_port(m["port"])
      else
        raise FTPProtoError, resp
      end
    end
    private :parse227

    def parse_pasv_ipv4_host(s)
      return s.tr(",", ".")
    end
    private :parse_pasv_ipv4_host

    def parse_pasv_ipv6_host(s)
      return s.split(/,/).map { |i|
        "%02x" % i.to_i
      }.each_slice(2).map(&:join).join(":")
    end
    private :parse_pasv_ipv6_host

    def parse_pasv_port(s)
      return s.split(/,/).map(&:to_i).inject { |x, y|
        (x << 8) + y
      }
    end
    private :parse_pasv_port

    # handler for response code 229
    # (Extended Passive Mode Entered)
    #
    # Returns host and port.
    def parse229(resp) # :nodoc:
      if !resp.start_with?("229")
        raise FTPReplyError, resp
      end
      if m = /\((?<d>[!-~])\k<d>\k<d>(?<port>\d+)\k<d>\)/.match(resp)
        return @bare_sock.remote_address.ip_address, m["port"].to_i
      else
        raise FTPProtoError, resp
      end
    end
    private :parse229

    # handler for response code 257
    # ("PATHNAME" created)
    #
    # Returns host and port.
    def parse257(resp) # :nodoc:
      if !resp.start_with?("257")
        raise FTPReplyError, resp
      end
      return resp.slice(/"(([^"]|"")*)"/, 1).to_s.gsub(/""/, '"')
    end
    private :parse257

    #
    # Writes debug message to the debug output stream
    #
    def debug_print(msg)
      @debug_output << msg + "\n" if @debug_mode && @debug_output
    end

    # :stopdoc:
    class NullSocket
      def read_timeout=(sec)
      end

      def closed?
        true
      end

      def close
      end

      def method_missing(mid, *args)
        raise FTPConnectionError, "not connected"
      end
    end

    class BufferedSocket < BufferedIO
      [:local_address, :remote_address, :addr, :peeraddr, :send, :shutdown].each do |method|
        define_method(method) { |*args|
          @io.__send__(method, *args)
        }
      end

      def read(len = nil)
        if len
          s = super(len, String.new, true)
          return s.empty? ? nil : s
        else
          result = String.new
          while s = super(DEFAULT_BLOCKSIZE, String.new, true)
            break if s.empty?
            result << s
          end
          return result
        end
      end

      def gets
        line = readuntil("\n", true)
        return line.empty? ? nil : line
      end

      def readline
        line = gets
        if line.nil?
          raise EOFError, "end of file reached"
        end
        return line
      end
    end

    if defined?(OpenSSL::SSL::SSLSocket)
      class BufferedSSLSocket < BufferedSocket

        def shutdown(*args)
          # Invokes SSL_shutdown, which sends a close_notify message to the peer.
          @io.__send__(:stop)
        end

        def send(mesg, flags, dest = nil)
          # Ignore flags and dest.
          @io.write(mesg)
        end

      end
    end
    # :startdoc:
  end

  FTPChannelCertificatePolicy = FTP::CertificatePolicy
  FTPDualChannelCertificatePolicy = FTP::CertificatePolicy
  FTPDataChannelCertificatePolicy = FTP::CertificatePolicy
  FTPCertificatePolicy = FTP::CertificatePolicy
  FTPChannelCertificateConvention = FTP::CertificatePolicy
  FTPDualChannelCertificateConvention = FTP::CertificatePolicy
  FTPChannelCertificateRelationship = FTP::CertificatePolicy
  FTPDualChannelCertificateRelationship = FTP::CertificatePolicy
  FTPCertificateRelationshipPolicy = FTP::CertificatePolicy

  FTPChannelCertificateVerification = FTP::CertificateVerification
  FTPDataChannelCertificateVerification = FTP::CertificateVerification
  FTPCertificateVerification = FTP::CertificateVerification
  FTPCertificateDecision = FTP::CertificateVerification
  FTPChannelCertificateDecision = FTP::CertificateVerification
  FTPDataChannelCertificateDecision = FTP::CertificateVerification
end


# Documentation comments:
#  - sourced from pickaxe and nutshell, with improvements (hopefully)
