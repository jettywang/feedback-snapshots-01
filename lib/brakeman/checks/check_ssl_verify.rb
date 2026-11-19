require 'brakeman/checks/base_check'
require 'brakeman/processors/lib/ssl_verify_tracker'

# Checks for disabled TLS certificate/hostname verification.
#
# A variable can be reassigned to a different object and verification
# settings can be changed through aliases, helpers, and conditional
# branches, and use_ssl=true does not imply that certificate or hostname
# verification is still enabled. This check therefore tracks the actual
# connection object used by each request and only reports conclusions when
# the effective state can be proven. Unknown branches are reported with
# reduced confidence rather than assumed safe.
class Brakeman::CheckSSLVerify < Brakeman::BaseCheck
  Brakeman::Checks.add self

  SSL_VERIFY_NONE = s(:colon2, s(:colon2, s(:const, :OpenSSL), :SSL), :VERIFY_NONE)

  @description = "Checks for OpenSSL::SSL::VERIFY_NONE"

  def run_check
    # Locations (file + line) of verify_mode= / Net::HTTP.start calls whose
    # enclosing method was modeled by the connection tracker. The legacy
    # syntactic checks skip these because the tracker attributes the more
    # accurate, request-level finding instead.
    @modeled_call_locations = Set.new

    check_tracked_connections
    check_open_ssl_verify_none
    check_http_start
  end

  # Follow each connection object through aliases, reassignments, and
  # branches, and attribute warnings to the request that actually sends
  # data over the misconfigured connection (or to Net::HTTP.start when the
  # dangerous options are supplied there).
  def check_tracked_connections
    connection_tracker = Brakeman::SSLVerifyTracker.new tracker

    tracker.each_method do |src, set_name, method_name, file|
      location = {
        :type => :class,
        :class => set_name,
        :method => method_name,
        :file => file
      }

      modeled = connection_tracker.process_source(src, location)

      @modeled_call_locations.merge(connection_tracker.modeled_call_locations)

      modeled.each do |finding|
        warn_about_tracked_finding finding
      end
    end
  end

  def check_open_ssl_verify_none
    tracker.find_call(:method => :verify_mode=).each { |call| process_verify_mode_result(call) }
  end

  def process_verify_mode_result result
    return if modeled_by_tracker? result

    if result[:call].last_arg == SSL_VERIFY_NONE
      warn_about_ssl_verification_bypass result
    end
  end

  def check_http_start
    tracker.find_call(:target => :'Net::HTTP', :method => :start).each { |call| process_http_start_result call }
  end

  def process_http_start_result result
    return if modeled_by_tracker? result

    arg = result[:call].last_arg

    if hash? arg and hash_access(arg, :verify_mode) == SSL_VERIFY_NONE
      warn_about_ssl_verification_bypass result
    end
  end

  def modeled_by_tracker? result
    file = result[:location][:file]
    line = result[:call].original_line || result[:call].line

    @modeled_call_locations.include? [file.to_s, line]
  end

  def warn_about_tracked_finding finding
    result = { :call => finding[:call], :location => finding[:location] }

    return unless original? result

    warn :result => result,
      :warning_type => "SSL Verification Bypass",
      :warning_code => :ssl_verification_bypass,
      :message => finding[:message],
      :confidence => finding[:confidence],
      :cwe_id => [295]
  end

  def warn_about_ssl_verification_bypass result
    return unless original? result

    warn :result => result,
      :warning_type => "SSL Verification Bypass",
      :warning_code => :ssl_verification_bypass,
      :message => "SSL certificate verification was bypassed",
      :confidence => :high,
      :cwe_id => [295]
  end
end
