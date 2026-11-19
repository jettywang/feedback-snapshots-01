# frozen_string_literal: true

require 'rack/protection'
require 'ipaddr'

module Rack
  module Protection
    ##
    # Prevented attack::   IP spoofing
    # Supported browsers:: all
    # More infos::         http://blog.c22.cc/2011/04/22/surveymonkey-ip-spoofing/
    #
    # Detects forwarding headers that are not backed by a trustworthy peer.
    #
    # A forwarding header is only allowed to influence the client address when
    # the immediate peer (the peer described by <tt>REMOTE_ADDR</tt>) is a
    # trusted proxy.  The peer trust decision is made with
    # <tt>:trusted_proxies</tt>.  If that option is not given, Rack's own
    # <tt>Rack::Request.ip_filter</tt> is used, so the middleware follows the
    # same peer semantics as <tt>Rack::Request#ip</tt>.
    #
    # The forwarding chain is interpreted with Rack's rules:
    #
    # * <tt>Forwarded</tt> (its <tt>for</tt> parameter) takes precedence over
    #   <tt>X-Forwarded-For</tt>, subject to
    #   <tt>Rack::Request.forwarded_priority</tt>.
    # * Addresses are ordered from the client to the peer.  When selecting the
    #   client address, addresses that belong to trusted proxies are skipped
    #   from the right, exactly as <tt>Rack::Request#ip</tt> does.
    # * <tt>X-Real-IP</tt> and <tt>Client-IP</tt> are not used by Rack to select
    #   an address.  They are treated as corroborating headers: when a
    #   forwarding chain is present, their addresses must occur in that chain.
    # * When both <tt>Forwarded</tt> and <tt>X-Forwarded-For</tt> are present,
    #   they must name the same original client.
    #
    # A peer that is not a trusted proxy cannot make its forwarding headers
    # trusted by supplying a plausible-looking private address chain; such a
    # request is denied.  A legitimate multi-hop chain is accepted even though
    # it contains addresses of intermediate proxies.
    #
    # == Default trust set
    #
    # When <tt>:trusted_proxies</tt> is omitted, <tt>Rack::Request.ip_filter</tt>
    # is consulted for every hop.  Rack's default filter trusts loopback and
    # private networks, which is convenient for development but means any host
    # that can reach the application from one of those networks may supply
    # forwarding headers.  Deployments that face untrusted clients over a
    # private network should pass an explicit list.
    #
    # == Options
    #
    # [<tt>:trusted_proxies</tt>] addresses of peers that are allowed to supply
    #                             forwarding headers.  Accepts an Array of
    #                             <tt>String</tt>, <tt>IPAddr</tt> or
    #                             <tt>Regexp</tt> entries (strings may be
    #                             CIDR ranges), a single such entry, or a
    #                             <tt>Proc</tt> receiving an address.  When
    #                             omitted, <tt>Rack::Request.ip_filter</tt> is
    #                             used.  The option is per middleware instance;
    #                             it never changes Rack's global configuration.
    # [Rack::Protection::Base options] options supported by Rack::Protection::Base may affect this middleware.
    #
    # == Evidence
    #
    # The adopted client address and the evidence used to derive it are
    # available to downstream middleware and the application:
    #
    #   env['rack.protection.client_ip']    # adopted address, or nil
    #   env['rack.protection.ip_spoofing']  # provenance details (Hash)
    #
    # The provenance hash contains:
    #
    # [<tt>:peer</tt>] immediate <tt>REMOTE_ADDR</tt> peer
    # [<tt>:peer_trusted</tt>] whether the immediate peer is a trusted proxy
    # [<tt>:remote_addr_chain</tt>] addresses parsed from <tt>REMOTE_ADDR</tt>
    # [<tt>:forwarded_header</tt>] raw <tt>Forwarded</tt> header, or nil
    # [<tt>:forwarded_for</tt>] addresses from <tt>Forwarded</tt>
    # [<tt>:x_forwarded_for_header</tt>] raw <tt>X-Forwarded-For</tt> header
    # [<tt>:x_forwarded_for</tt>] addresses from <tt>X-Forwarded-For</tt>
    # [<tt>:x_real_ip_header</tt>] raw <tt>X-Real-IP</tt> header
    # [<tt>:x_real_ip</tt>] addresses from <tt>X-Real-IP</tt>
    # [<tt>:client_ip_header</tt>] raw <tt>Client-IP</tt> header
    # [<tt>:client_ip_assertion</tt>] addresses from <tt>Client-IP</tt>
    # [<tt>:client_ip</tt>] adopted client address
    # [<tt>:client_ip_source</tt>] <tt>:remote_addr</tt>,
    #                             <tt>:forwarded</tt> or
    #                             <tt>:x_forwarded_for</tt>
    # [<tt>:forwarded_source</tt>] header Rack selected for the chain
    # [<tt>:claimed_chain</tt>] chain as claimed by the request, client first
    # [<tt>:adopted_chain</tt>] chain actually trusted, client first
    # [<tt>:chain</tt>] alias of <tt>:adopted_chain</tt>
    # [<tt>:trusted_proxies</tt>] chain addresses skipped as trusted proxies,
    #                             nearest hop first
    # [<tt>:consistent</tt>] whether the headers agree with each other
    # [<tt>:invalid_forwarding</tt>] whether an address header was malformed
    # [<tt>:headers_present</tt>] whether any address header was supplied
    # [<tt>:source_trusted</tt>] whether the adopted address is trustworthy
    # [<tt>:accepted</tt>] whether the request is accepted
    # [<tt>:reason</tt>] machine-readable explanation
    #
    # == Example
    #
    #     use Rack::Protection::IPSpoofing,
    #         trusted_proxies: ['10.0.0.1', IPAddr.new('192.0.2.0/24')]
    #
    class IPSpoofing < Base
      EVIDENCE_KEY = 'rack.protection.ip_spoofing'
      CLIENT_IP_KEY = 'rack.protection.client_ip'

      default_reaction :deny
      default_options trusted_proxies: nil

      def initialize(app, options = {})
        super
        @trusted_proxy_matcher = build_trusted_proxy_matcher(@options[:trusted_proxies])
      end

      def accepts?(env)
        evidence = analyze(env).freeze
        env[EVIDENCE_KEY] = evidence
        env[CLIENT_IP_KEY] = evidence[:client_ip]
        evidence[:accepted]
      end

      # Returns the provenance hash for the request without changing +env+.
      def analyze(env)
        remote_addresses = parse_remote_addresses(env['REMOTE_ADDR'])
        forwarded_for, forwarded_invalid, forwarded_claimed = parse_forwarded_header(env['HTTP_FORWARDED'])
        x_forwarded_for, xff_invalid, xff_claimed = parse_x_forwarded_for(env['HTTP_X_FORWARDED_FOR'])
        x_real_ip, x_real_ip_invalid, x_real_ip_claimed = parse_address_list(env['HTTP_X_REAL_IP'])
        client_ip_header, client_ip_invalid, client_ip_claimed = parse_address_list(env['HTTP_CLIENT_IP'])

        claim_present = claim_present?(forwarded_claimed, xff_claimed, x_real_ip_claimed, client_ip_claimed)
        invalid_forwarding = forwarded_invalid || xff_invalid || x_real_ip_invalid || client_ip_invalid
        consistent = headers_consistent?(forwarded_for, x_forwarded_for, x_real_ip, client_ip_header)
        peer = remote_addresses.last
        peer_trusted = trusted_proxy?(peer)

        forwarded_source, effective_chain = effective_forwarded_chain(forwarded_for, x_forwarded_for)
        forwarding_trusted = claim_present && peer_trusted && !invalid_forwarding && consistent
        selectable_chain = forwarding_trusted ? effective_chain : []

        client_ip, client_ip_source, skipped_proxies =
          select_client(remote_addresses, selectable_chain, forwarded_source)
        client_ip_source ||= :remote_addr

        claimed_chain = build_claimed_chain(effective_chain, x_forwarded_for, remote_addresses)
        adopted_chain = forwarding_trusted ? full_chain(effective_chain, remote_addresses) : remote_addresses

        {
          peer: peer,
          peer_trusted: peer_trusted,
          remote_addr_chain: remote_addresses.freeze,
          forwarded_header: header_value(env['HTTP_FORWARDED']),
          forwarded_for: forwarded_for.freeze,
          x_forwarded_for_header: header_value(env['HTTP_X_FORWARDED_FOR']),
          x_forwarded_for: x_forwarded_for.freeze,
          x_real_ip_header: header_value(env['HTTP_X_REAL_IP']),
          x_real_ip: x_real_ip.freeze,
          client_ip_header: header_value(env['HTTP_CLIENT_IP']),
          client_ip_assertion: client_ip_header.freeze,
          client_ip: client_ip,
          client_ip_source: client_ip_source,
          forwarded_source: forwarded_source,
          claimed_chain: claimed_chain.freeze,
          adopted_chain: adopted_chain.freeze,
          chain: adopted_chain,
          trusted_proxies: skipped_proxies.freeze,
          consistent: consistent,
          invalid_forwarding: invalid_forwarding,
          headers_present: claim_present,
          source_trusted: !claim_present || forwarding_trusted,
          accepted: !claim_present || forwarding_trusted,
          reason: decision_reason(claim_present, peer_trusted, invalid_forwarding,
                                  consistent, effective_chain)
        }
      end

      def evidence(env)
        env[EVIDENCE_KEY] || analyze(env)
      end

      def client_ip(env)
        env[CLIENT_IP_KEY] || evidence(env)[:client_ip]
      end

      # Whether +address+ is in the configured trusted proxy set.
      def trusted_proxy?(address)
        return false if address.nil? || address.to_s.empty?

        @trusted_proxy_matcher.call(address.to_s)
      end

      private

      # A claim is only made by headers that actually describe an address.
      # Forwarded with only proto/host carries no client address and must not
      # turn an otherwise direct request into a spoofing attempt.
      def claim_present?(forwarded_claimed, xff_claimed, x_real_ip_claimed, client_ip_claimed)
        forwarded_claimed || xff_claimed || x_real_ip_claimed || client_ip_claimed
      end

      def decision_reason(claim_present, peer_trusted, invalid, consistent, effective_chain)
        return :no_client_address_claim unless claim_present
        return :untrusted_peer unless peer_trusted
        return :invalid_forwarded_address if invalid
        return :inconsistent_forwarded_headers unless consistent

        effective_chain.empty? ? :corroborating_headers_only : :trusted_forwarded_chain
      end

      # Keeps a malformed REMOTE_ADDR verbatim so trust checks treat it as an
      # untrusted peer rather than silently dropping the peer.
      def parse_remote_addresses(value)
        split_header(value).map do |address|
          normalize_address(address) || address
        end
      end

      def parse_forwarded_header(value)
        return [[], false, false] if value.nil? || value.to_s.strip.empty?

        parsed = Rack::Utils.forwarded_values(value)
        # A Forwarded header may only carry proto/host/by information. That is
        # not an address claim, so it must not invalidate the request.
        return [[], false, false] unless parsed && parsed.key?(:for)

        raw = Array(parsed[:for])
        return [[], true, true] if raw.empty?

        addresses = raw.map { |address| normalize_address(address) }
        [addresses.compact, addresses.any?(&:nil?), true]
      end

      def parse_x_forwarded_for(value)
        parse_address_list(value)
      end

      def parse_address_list(value)
        return [[], false, false] if value.nil? || value.to_s.strip.empty?

        tokens = split_header(value)
        addresses = tokens.map { |address| normalize_address(address) }
        [addresses.compact, addresses.any?(&:nil?), true]
      end

      # Mirrors Rack::Request#split_header.
      def split_header(value)
        value ? value.to_s.strip.split(/[, \t]+/) : []
      end

      # Extracts an IP address from a Forwarded/X-Forwarded-For authority.
      # Ports and IPv6 brackets are removed, and the result is canonicalized.
      def normalize_address(authority)
        host = extract_host(authority.to_s.strip)
        return if host.nil? || host.empty? || host.include?('/')

        IPAddr.new(host).to_s
      rescue ArgumentError
        nil
      end

      def extract_host(authority)
        return if authority.empty?
        return authority unless authority.include?(':') || authority.start_with?('[')

        if authority.start_with?('[')
          closing = authority.index(']')
          return if closing.nil?

          suffix = authority[(closing + 1)..]
          return if suffix && !suffix.empty? && !suffix.match?(/\A:\d+\z/)

          authority[1...closing]
        elsif authority.count(':') == 1
          host, separator, port = authority.rpartition(':')
          return if separator.empty? || !port.match?(/\A\d+\z/)

          host
        else
          authority
        end
      end

      # Two forwarding headers can only be consistent when the client they
      # name is the same. A proxy may rewrite or extend the intermediate hops
      # (for example, an appending proxy versus a replacing one), so comparing
      # every hop would reject legitimate deployments.
      def headers_consistent?(forwarded_for, x_forwarded_for, x_real_ip, client_ip_header)
        if forwarded_for.any? && x_forwarded_for.any? && forwarded_for.first != x_forwarded_for.first
          return false
        end

        declared_chain = forwarded_for.any? ? forwarded_for : x_forwarded_for
        return true if declared_chain.empty?

        (x_real_ip + client_ip_header).all? { |address| declared_chain.include?(address) }
      end

      # Selects the forwarding header Rack would use, following
      # Rack::Request.forwarded_priority.
      def effective_forwarded_chain(forwarded_for, x_forwarded_for)
        priority = if Rack::Request.respond_to?(:forwarded_priority)
                     Rack::Request.forwarded_priority
                   else
                     %i[forwarded x_forwarded]
                   end

        Array(priority).each do |type|
          case type
          when :forwarded
            return [:forwarded, forwarded_for] if forwarded_for.any?
          when :x_forwarded
            return [:x_forwarded_for, x_forwarded_for] if x_forwarded_for.any?
          end
        end

        [nil, []]
      end

      # Mirrors Rack::Request#ip: walk REMOTE_ADDR from the right, skipping
      # trusted proxies, then walk the forwarding chain from the right.
      def select_client(remote_addresses, forwarded_chain, forwarded_source)
        skipped = []

        remote_addresses.reverse_each do |address|
          if trusted_proxy?(address)
            skipped << address
          else
            return [address, :remote_addr, skipped]
          end
        end

        unless forwarded_chain.empty?
          forwarded_chain.reverse_each do |address|
            if trusted_proxy?(address)
              skipped << address
            else
              return [address, forwarded_source, skipped]
            end
          end

          return [forwarded_chain.first, forwarded_source, skipped]
        end

        [remote_addresses.first, :remote_addr, skipped]
      end

      def build_claimed_chain(effective_chain, x_forwarded_for, remote_addresses)
        claimed = effective_chain.any? ? effective_chain : x_forwarded_for
        full_chain(claimed, remote_addresses)
      end

      def header_value(value)
        value.nil? || value.to_s.strip.empty? ? nil : value
      end

      def full_chain(claimed, remote_addresses)
        chain = claimed.dup

        remote_addresses.each do |address|
          chain << address unless chain.last == address
        end

        chain
      end

      def build_trusted_proxy_matcher(value)
        return ->(address) { rack_ip_filter(address) } if value.nil?
        return value if value.respond_to?(:call)

        # Snapshot the list so later mutation of the caller's array cannot
        # change this instance's policy.
        entries = value.is_a?(Array) ? value.dup : [value]
        entries.freeze

        ->(address) { entries.any? { |entry| trusted_proxy_entry?(entry, address) } }
      end

      def rack_ip_filter(address)
        return false unless Rack::Request.respond_to?(:ip_filter)

        Rack::Request.ip_filter.call(address)
      end

      def trusted_proxy_entry?(entry, address)
        case entry
        when IPAddr
          ip_include?(entry, address)
        when Regexp
          entry.match?(address)
        when String
          trusted_proxy_string?(entry, address)
        else
          entry == address
        end
      end

      def trusted_proxy_string?(entry, address)
        return entry == address unless entry.match?(/\A[0-9A-Fa-f:.\/]+\z/)

        return ip_include?(IPAddr.new(entry), address) if entry.include?('/')

        entry == address || IPAddr.new(entry) == IPAddr.new(address)
      rescue ArgumentError
        false
      end

      def ip_include?(range, address)
        range.include?(IPAddr.new(address))
      rescue ArgumentError
        false
      end
    end
  end
end
