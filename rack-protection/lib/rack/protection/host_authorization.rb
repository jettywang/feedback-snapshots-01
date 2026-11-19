# frozen_string_literal: true

require 'rack/protection'
require 'ipaddr'

module Rack
  module Protection
    ##
    # Prevented attack::   DNS rebinding and other Host header attacks
    # Supported browsers:: all
    # More info::          * https://en.wikipedia.org/wiki/DNS_rebinding
    #                      * https://portswigger.net/web-security/host-header
    #
    # Blocks HTTP requests with an unrecognized hostname in any of the following
    # HTTP headers: Host, X-Forwarded-Host, Forwarded.
    #
    # The Host header is always checked and a permitted value in a forwarding
    # header never masks a disallowed Host. Every host value carried by
    # X-Forwarded-Host and Forwarded is checked: when several (possibly
    # conflicting) values are present, all of them must be permitted -- no
    # single value is picked to speak for the others. A Forwarded header that
    # cannot be parsed is treated as hostile and the request is denied
    # (fail closed); it is never silently ignored.
    #
    # == Options
    #
    # [<tt>:permitted_hosts</tt>] an Array of hosts to allow.  Elements can be as follows:
    #                             [<tt>String</tt> not starting with a dot] a hostname that must be a case-insensitive
    #                                                                       match to allow the request.
    #                             [<tt>String</tt> starting with a dot] allow matches from the entire domain, including
    #                                                                   any subdomain. A subdomain only matches at a
    #                                                                   dot boundary, so <tt>.example.org</tt> allows
    #                                                                   <tt>foo.example.org</tt> but not
    #                                                                   <tt>notexample.org</tt>.
    #                             [<tt>IPAddr</tt>] Specific IP or IP Range to allow (based on <tt>#include?</tt>).
    #                                               Note that no DNS lookup is done - this is just based on the 
    #                                               value of the HTTP header.
    #
    # [<tt>:allow_if</tt>] a Proc that, if it returns true, allows the request regardless of the
    #                      value of <tt>:permitted_hosts</tt>. Default value is <tt>nil</tt>, meaning
    #                      <tt>:permitted_hosts</tt> is respected and there are no exceptions.
    #                      This is an explicit escape hatch only: unparseable or conflicting
    #                      headers deny the request, they never trigger this exemption.
    # [Rack::Protection::Base options] options supported by Rack::Protection::Base may affect this middleware.
    #
    #
    # == Example: Allow specific hosts
    #
    #     use Rack::Protection::HostAuthorization, permitted_hosts: ["www.example.org", "sinatrarb.com"]
    #
    # == Example: Allow all subdomains
    #
    #     use Rack::Protection::HostAuthorization, permitted_hosts: [".example.org", ".sinatrarb.com"]
    #
    # == Example: Allow an IP range
    #
    #     use Rack::Protection::HostAuthorization, permitted_hosts: [ IPAddr.new("192.168.2.0/16") ]
    #
    # The `:allow_if` option can also be set to a proc to use custom allow/deny logic.
    class HostAuthorization < Base
      DOT = '.'
      PORT_REGEXP = /:\d+\z/.freeze
      SUBDOMAINS = /[a-z0-9\-.]+/.freeze
      private_constant :DOT,
                       :PORT_REGEXP,
                       :SUBDOMAINS
      default_reaction :deny
      default_options allow_if: nil,
                      message: 'Host not permitted'

      def initialize(*)
        super
        @permitted_hosts = []
        @domain_hosts = []
        @ip_hosts = []
        @all_permitted_hosts = Array(options[:permitted_hosts])

        @all_permitted_hosts.each do |host|
          case host
          when String
            if host.start_with?(DOT)
              domain = host[1..-1]
              @permitted_hosts << domain.downcase
              @domain_hosts << /\A#{SUBDOMAINS}\.#{Regexp.escape(domain)}\z/i
            else
              @permitted_hosts << host.downcase
            end
          when IPAddr then @ip_hosts << host
          end
        end
      end

      def accepts?(env)
        return true if options[:allow_if]&.call(env)
        return true if @all_permitted_hosts.empty?

        request = Request.new(env)
        origin_host = extract_host(request.host_authority)
        forwarded_hosts = forwarded_hosts(request)

        debug env, "#{self.class} " \
                   "@all_permitted_hosts=#{@all_permitted_hosts.inspect} " \
                   "@permitted_hosts=#{@permitted_hosts.inspect} " \
                   "@domain_hosts=#{@domain_hosts.inspect} " \
                   "@ip_hosts=#{@ip_hosts.inspect} " \
                   "origin_host=#{origin_host.inspect} " \
                   "forwarded_hosts=#{forwarded_hosts.inspect}"

        # A permitted forwarding header never masks a disallowed Host header.
        return false unless host_permitted?(origin_host)
        # A Forwarded header that fails to parse denies the request.
        return false if forwarded_hosts.nil?
        # Every claimed forwarded host must be permitted; no single value
        # from conflicting headers or lists is picked to speak for the rest.
        forwarded_hosts.all? { |forwarded_host| host_permitted?(forwarded_host) }
      end

      private

      # Collects every host claimed by the Forwarded and X-Forwarded-Host
      # headers. Both headers are inspected when both are present. Returns
      # nil when a Forwarded header is present but cannot be parsed, so the
      # caller fails closed instead of trusting a partial parse.
      def forwarded_hosts(request)
        hosts = []

        if (forwarded = request.get_header('HTTP_FORWARDED'))
          values = Rack::Utils.forwarded_values(forwarded)
          return nil if values.nil?

          hosts.concat(values[:host]) if values[:host]
        end

        if (x_forwarded_host = request.get_header('HTTP_X_FORWARDED_HOST'))
          hosts.concat(x_forwarded_host.strip.split(/[, \t]+/).map { |host| wrap_ipv6(host) })
        end

        hosts.map { |authority| extract_host(authority) }
      end

      def extract_host(authority)
        authority = authority.to_s
        host = if authority.start_with?('[')
                 # Bracketed IPv6 literal, optionally followed by a port.
                 closing = authority.index(']')
                 closing ? authority[0..closing] : authority
               else
                 authority.split(PORT_REGEXP).first
               end
        host&.downcase
      end

      # Compatibility shim mirroring Rack::Request: legacy headers sometimes
      # carry bare IPv6 literals without the square brackets.
      def wrap_ipv6(host)
        if !host.start_with?('[') && host.count(':') > 1
          "[#{host}]"
        else
          host
        end
      end

      def host_permitted?(host)
        exact_match?(host) || domain_match?(host) || ip_match?(host)
      end

      def exact_match?(host)
        @permitted_hosts.include?(host)
      end

      def domain_match?(host)
        return false if host.nil?
        return false if host.start_with?(DOT)

        @domain_hosts.any? { |domain_host| host.match?(domain_host) }
      end

      def ip_match?(host)
        @ip_hosts.any? { |ip_host| ip_host.include?(host) }
      rescue IPAddr::InvalidAddressError
        false
      end
    end
  end
end
