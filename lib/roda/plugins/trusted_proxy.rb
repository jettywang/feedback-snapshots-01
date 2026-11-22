# frozen-string-literal: true
require 'ipaddr'

#
class Roda
  module RodaPlugins
    # The trusted_proxy plugin gives +request.ip+ an explicit trusted
    # proxy chain contract.  It is intended for internal applications that
    # run behind one or more known reverse proxies (for example, a load
    # balancer in front of an application proxy) and need both access
    # restrictions and duty logs to agree on the same source address.
    #
    # == The contract
    #
    # The only host the application can observe directly is +REMOTE_ADDR+,
    # the host that opened the TCP connection.  A forwarding header such as
    # <tt>X-Forwarded-For</tt> is attacker-controlled unless every host that
    # could have produced it is trusted.  This plugin therefore only consults
    # the forwarding header when +REMOTE_ADDR+ is itself a trusted proxy:
    #
    # 1. Direct request (+REMOTE_ADDR+ is not inside a trusted proxy range):
    #    the forwarding header is ignored entirely and +request.ip+ is
    #    +REMOTE_ADDR+.  A spoofed header cannot change the reported source.
    # 2. Proxied request (+REMOTE_ADDR+ is trusted): the forwarding header is
    #    read right-to-left, starting at the proxy closest to the application.
    #    Trusted proxy entries are skipped; the first entry that is not a
    #    trusted proxy is returned as the client address.
    # 3. If the chain reaches an entry that cannot be parsed as an IP, the
    #    chain cannot be confirmed.  The plugin fails closed: +request.ip+
    #    falls back to +REMOTE_ADDR+ and +request.forwarded_ip?+ is false.
    #
    # +request.forwarded_ip?+ reports whether +request.ip+ was derived from a
    # chain that every observed hop attested to.  It is false for direct
    # requests and for any chain that cannot be confirmed, so logs never have
    # to present a header value as fact when it is only a guess.
    #
    # == Usage
    #
    # Pass the CIDR ranges of every proxy that is allowed to forward requests:
    #
    #   plugin :trusted_proxy, ['10.0.8.0/24', '10.0.9.0/24']
    #
    # A single range can be passed as a string.  Individual addresses are
    # accepted as /32 (IPv4) or /128 (IPv6) ranges:
    #
    #   plugin :trusted_proxy, '127.0.0.1'
    #
    # The header defaults to <tt>X-Forwarded-For</tt> and can be overridden:
    #
    #   plugin :trusted_proxy, '10.0.0.0/8', header: 'X-Real-IP'
    #
    # == Restricting and logging by source
    #
    # Because +request.ip+ is already validated against the trusted chain,
    # access checks and logging can share it directly:
    #
    #   route do |r|
    #     r.on "admin" do
    #       unless ADMIN_NETWORKS.any? { |net| net.include?(IPAddr.new(r.ip)) }
    #         response.status = 403
    #         next "forbidden"
    #       end
    #
    #       audit_log.record(action: r.path, source: r.ip,
    #         confirmed: r.forwarded_ip?)
    #       # ...
    #     end
    #   end
    module TrustedProxy
      # Parse the configured trusted proxy ranges into IPAddr objects and
      # remember the Rack environment key for the forwarding header.
      def self.configure(app, proxies=nil, opts=(no_positional_opts = true; OPTS),
          header: opts[:header] || 'X-Forwarded-For',
          **kw)
        RodaPlugins.check_keywords("the trusted_proxy plugin", no_positional_opts, opts, kw)

        app.opts[:trusted_proxy_header_env_key] =
          "HTTP_#{header.upcase.tr('-', '_')}".freeze

        if proxies
          app.opts[:trusted_proxy_ranges] =
            Array(proxies).map { |range| IPAddr.new(range) }.freeze
        end
      end

      module ClassMethods
        RodaPlugins.opt_attr_reader(self, :trusted_proxy_ranges)
        RodaPlugins.opt_attr_reader(self, :trusted_proxy_header_env_key)
      end

      module RequestMethods
        # Whether the address returned by #ip was taken from a forwarding
        # header whose entire observed chain is made of trusted proxies.
        # False for direct requests and for any chain that cannot be
        # confirmed, so callers can distinguish an attested source from a
        # fallback rather than treating a header value as fact.
        def forwarded_ip?
          ip
          @trusted_proxy_forwarded
        end

        # Return the source address according to the trusted proxy chain
        # contract described on the TrustedProxy module.  The direct peer is
        # REMOTE_ADDR, never a value derived from a forwarding header; the
        # header is only consulted once that peer is itself trusted.
        def ip
          @ip ||= begin
            ranges = roda_class.trusted_proxy_ranges
            peer = @env['REMOTE_ADDR'].to_s

            @trusted_proxy_forwarded = false

            if ranges && (peer_address = _trusted_proxy_parse(peer)) &&
                trusted_proxy_address?(peer_address, ranges)
              _trusted_proxy_client_ip(peer, ranges)
            else
              peer
            end
          end
        end

        private

        # Parse an address string into an IPAddr, returning nil for values
        # that are not valid IP addresses instead of raising.
        def _trusted_proxy_parse(address)
          return if address.nil? || address.empty?
          IPAddr.new(address)
        rescue IPAddr::InvalidAddressError
          nil
        end

        # Walk the forwarding header right-to-left, skipping trusted proxies,
        # and return the first untrusted entry.  Fails closed to the peer
        # address when the chain is missing, empty, or contains an entry that
        # is not a parseable IP address.
        def _trusted_proxy_client_ip(peer, ranges)
          header = @env[roda_class.trusted_proxy_header_env_key]
          return peer unless header

          entries = header.split(',').map { |entry| _trusted_proxy_strip_entry(entry) }
          return peer if entries.empty?

          entries.reverse_each do |entry|
            address = _trusted_proxy_parse(entry)
            return peer unless address

            unless trusted_proxy_address?(address, ranges)
              @trusted_proxy_forwarded = true
              return address.to_s
            end
          end

          # Every entry is itself a trusted proxy, so there is no client
          # address in the header; the direct peer is the only known source.
          peer
        end

        # Normalize one forwarding header entry: surrounding whitespace, an
        # optional TCP port, and the square brackets around an IPv6 literal.
        def _trusted_proxy_strip_entry(entry)
          entry = entry.strip

          if entry.start_with?('[') && (index = entry.index(']'))
            entry = entry[1, index - 1]
          elsif entry.count(':') == 1 && (index = entry.rindex(':'))
            entry = entry[0, index]
          end

          entry.strip
        end

        # Whether the given address (a parsed IPAddr) is inside one of the
        # configured trusted proxy ranges.
        def trusted_proxy_address?(address, ranges)
          ranges.any? { |range| range.include?(address) }
        end
      end
    end

    register_plugin(:trusted_proxy, TrustedProxy)
  end
end
