#!/usr/bin/env ruby
#
# SubjectConfirmationData Address enforcement behind a reverse proxy.
#
# Demonstrates three ways a Ruby login gateway can feed a client address into
# ruby-saml, using a locally signed SAML Response (no network, no IdP):
#
#   1. direct connection      - the socket peer address is used as-is
#   2. trusted proxy          - the proxy is the socket peer and must itself
#                               assert the client address; we read that header
#                               in this caller, not inside the library
#   3. forged forwarding hdr  - an untrusted direct client sends X-Forwarded-For;
#                               the caller discards it, so no confirmed address
#                               exists and an Address-bearing confirmation fails
#
# Only the address the caller explicitly confirms reaches ruby-saml.

$LOAD_PATH.unshift(File.expand_path("../../lib", __FILE__))
require "base64"
require "openssl"
require "time"
require "onelogin/ruby-saml"
require "onelogin/ruby-saml/response"
require "xml_security"

ACS_URL = "https://login.example.com/saml/consume"
AUDIENCE = "https://login.example.com/saml/metadata"
REQUEST_ID = "_request_4f2a"
NOW = Time.utc(2026, 1, 15, 12, 0, 0)

# A tiny, deterministic certificate for the demo IdP.
KEY = OpenSSL::PKey::RSA.new(2048)
CERT = begin
  cert = OpenSSL::X509::Certificate.new
  cert.version = 2
  cert.serial = 1
  cert.subject = OpenSSL::X509::Name.parse("/CN=demo-idp")
  cert.issuer = cert.subject
  cert.public_key = KEY.public_key
  cert.not_before = NOW - 3600
  cert.not_after = NOW + 3600
  cert.sign(KEY, OpenSSL::Digest::SHA256.new)
  cert
end

# Builds a SAML Response with one Bearer SubjectConfirmation per entry of
# +confirmations+ and signs it locally.
def signed_response(confirmations)
  nodes = confirmations.map do |confirmation|
    attributes = {
      "InResponseTo" => REQUEST_ID,
      "Recipient" => ACS_URL,
      "NotOnOrAfter" => (NOW + 300).utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    }
    attributes["Address"] = confirmation[:address] if confirmation.has_key?(:address)

    serialized = attributes.map { |name, value| "#{name}='#{value}'" }.join(" ")
    "<saml:SubjectConfirmation Method='urn:oasis:names:tc:SAML:2.0:cm:bearer'>" \
      "<saml:SubjectConfirmationData #{serialized}/></saml:SubjectConfirmation>"
  end.join

  xml = <<~XML
    <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_response_demo" Version="2.0" IssueInstant="#{NOW.utc.strftime("%Y-%m-%dT%H:%M:%SZ")}" Destination="#{ACS_URL}" InResponseTo="#{REQUEST_ID}">
      <saml:Issuer>https://idp.example.com/metadata</saml:Issuer>
      <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
      <saml:Assertion ID="_assertion_demo" Version="2.0" IssueInstant="#{NOW.utc.strftime("%Y-%m-%dT%H:%M:%SZ")}">
        <saml:Issuer>https://idp.example.com/metadata</saml:Issuer>
        <saml:Subject>
          <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">alice@example.com</saml:NameID>
          #{nodes}
        </saml:Subject>
        <saml:Conditions NotBefore="#{(NOW - 60).utc.strftime("%Y-%m-%dT%H:%M:%SZ")}" NotOnOrAfter="#{(NOW + 300).utc.strftime("%Y-%m-%dT%H:%M:%SZ")}">
          <saml:AudienceRestriction><saml:Audience>#{AUDIENCE}</saml:Audience></saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AuthnStatement AuthnInstant="#{NOW.utc.strftime("%Y-%m-%dT%H:%M:%SZ")}" SessionIndex="_session_demo">
          <saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext>
        </saml:AuthnStatement>
      </saml:Assertion>
    </samlp:Response>
  XML

  document = XMLSecurity::Document.new(xml)
  document.sign_document(KEY, CERT, XMLSecurity::Document::RSA_SHA256, XMLSecurity::Document::SHA256)
  Base64.strict_encode64(document.to_s)
end

def settings
  OneLogin::RubySaml::Settings.new(
    :idp_cert => CERT.to_pem,
    :sp_entity_id => AUDIENCE,
    :assertion_consumer_service_url => ACS_URL
  )
end

# A stand-in for the HTTP layer. +peer_address+ is the real socket peer;
# +headers+ are what the request claims. The caller alone decides whether the
# peer is allowed to speak for the client behind it.
def request_context(peer_address, headers = {}, trusted_proxies = [])
  trusted = trusted_proxies.include?(peer_address)
  client_address = if trusted
    headers["X-Forwarded-For"].to_s.split(",").first.to_s.strip
  else
    peer_address
  end

  {
    :peer_address => peer_address,
    :trusted_proxy => trusted,
    :forwarded_for => headers["X-Forwarded-For"],
    # An untrusted peer cannot confirm a forwarded address; the direct socket
    # peer is still a confirmed address, so it is used instead.
    :confirmed_client_address => client_address.empty? ? peer_address : client_address
  }
end

# Minimal fixed-clock helper so the demo does not depend on a time library.
def with_fixed_time(instant)
  original = Time.method(:now)
  Time.define_singleton_method(:now) { instant }
  begin
    yield
  ensure
    Time.define_singleton_method(:now, original)
  end
end

def check(title, response_xml, context)
  response = OneLogin::RubySaml::Response.new(
    response_xml,
    :settings => settings,
    :matches_request_id => REQUEST_ID,
    :client_address => context[:confirmed_client_address],
    :client_address_source => context[:trusted_proxy] ? :trusted_proxy_header : :socket_peer,
    :subject_confirmation_address_policy => :exact
  )

  valid = nil
  valid = with_fixed_time(NOW) { response.is_valid? }
  report = response.subject_confirmation_report
  accepted = response.accepted_subject_confirmation

  puts "== #{title}"
  puts "   peer=#{context[:peer_address]} trusted_proxy=#{context[:trusted_proxy]} " \
       "X-Forwarded-For=#{context[:forwarded_for].inspect}"
  puts "   confirmed client address=#{report[:client_address].inspect} " \
       "source=#{report[:client_address_source].inspect}"
  puts "   valid=#{valid} (response_valid=#{report[:response_valid]})"
  report[:candidates].each do |candidate|
    puts "   candidate ##{candidate[:index]} address=#{candidate[:address].inspect} " \
         "address_result=#{candidate[:address_result]} failures=#{candidate[:failures].inspect}"
  end
  if accepted
    puts "   accepted confirmation ##{accepted[:index]} (address=#{accepted[:address].inspect})"
  else
    puts "   accepted confirmation: none"
  end
  if report[:accepted_index] && !valid
    puts "   candidate ##{report[:accepted_index]} passed SubjectConfirmation checks, " \
         "but the response was rejected later"
  end
  puts
  valid
end

address = "203.0.113.7"
proxy = "10.0.0.5"

direct = signed_response([{ :address => address }])
no_address = signed_response([{}])
two_candidates = signed_response([{ :address => "198.51.100.99" }, { :address => address }])

results = []
results << check(
  "1. direct connection, matching Address",
  direct,
  request_context(address)
)
results << check(
  "2. trusted proxy supplies the confirmed client address",
  direct,
  request_context(proxy, { "X-Forwarded-For" => "#{address}, 10.0.0.9" }, [proxy])
)
results << check(
  "3a. forged X-Forwarded-For from an untrusted direct peer",
  direct,
  request_context("198.51.100.44", { "X-Forwarded-For" => address })
)
results << check(
  "3b. trusted proxy passes a different address",
  direct,
  request_context(proxy, { "X-Forwarded-For" => "198.51.100.44" }, [proxy])
)
results << check(
  "4. Address omitted by the IdP (exact policy allows it)",
  no_address,
  request_context(address)
)
results << check(
  "5. two candidates, only the second matches",
  two_candidates,
  request_context(address)
)

expected = [true, true, false, false, true, true]
abort "demo expectations failed: #{results.inspect}" unless results == expected
puts "All demo expectations matched."
