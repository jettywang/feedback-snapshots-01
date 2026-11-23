# frozen_string_literal: true

require "spec_helper"
require "webauthn/fake_authenticator"
require "webauthn/fake_client"
require "webauthn/relying_party"

# Application policy under test: a hardware admittance decision may only rely
# on authenticator extension outputs that (a) travel with a successfully
# verified credential and (b) were requested in the options of the very
# operation being completed. Client extension outputs are display-only hints,
# and every decision stays linked to the options that initiated its operation.
class HardwareAdmittanceService
  EXTENSION_ID = "hardwareAdmittance"

  UnknownOperationError = Class.new(StandardError)

  Operation = Struct.new(:purpose, :options, keyword_init: true) do
    def requested_extensions
      (options.extensions || {}).keys.map(&:to_s)
    end

    def requested?(extension_id)
      requested_extensions.include?(extension_id)
    end
  end

  Decision = Struct.new(:operation, :credential, :trusted_outputs, :display_hints, keyword_init: true) do
    def purpose
      operation.purpose
    end

    def options
      operation.options
    end
  end

  attr_reader :decisions

  def initialize(relying_party)
    @relying_party = relying_party
    @pending_operations = {}
    @decisions = []
  end

  def begin_operation(purpose, extensions: {})
    options = relying_party.options_for_authentication(extensions: extensions)
    operation = Operation.new(purpose: purpose, options: options)
    pending_operations[operation.options.challenge] = operation
    operation
  end

  def complete_operation(raw_credential, public_key:, sign_count:)
    credential = WebAuthn::Credential.from_get(raw_credential, relying_party: relying_party)
    operation = pending_operations.delete(challenge_key_for(credential)) || raise(UnknownOperationError)

    credential.verify(
      operation.options.challenge,
      public_key: public_key,
      sign_count: sign_count
    )

    Decision.new(
      operation: operation,
      credential: credential,
      trusted_outputs: trusted_outputs_for(operation, credential),
      display_hints: credential.client_extension_outputs || {}
    ).tap { |decision| decisions << decision }
  end

  private

  attr_reader :relying_party, :pending_operations

  def challenge_key_for(credential)
    relying_party.encoder.encode(credential.response.client_data.challenge)
  end

  def trusted_outputs_for(operation, credential)
    authenticator_outputs = credential.authenticator_extension_outputs || {}

    operation.requested_extensions.each_with_object({}) do |extension_id, trusted|
      trusted[extension_id] = authenticator_outputs[extension_id] if authenticator_outputs.key?(extension_id)
    end
  end
end

RSpec.describe "hardware admittance extension evidence" do
  let(:relying_party) do
    WebAuthn::RelyingParty.new(
      allowed_origins: ["https://admittance.example.test"],
      id: "admittance.example.test",
      name: "Hardware Admittance"
    )
  end
  let(:authenticator) { WebAuthn::FakeAuthenticator.new }
  let(:client) { WebAuthn::FakeClient.new("https://admittance.example.test", authenticator: authenticator) }
  let(:service) { HardwareAdmittanceService.new(relying_party) }

  let(:extension_id) { HardwareAdmittanceService::EXTENSION_ID }
  let(:extension_input) { { extension_id => "prepare-device" } }
  let(:trusted_output) { { extension_id => "device-accepted" } }

  let!(:registered_credential) do
    registration_options = relying_party.options_for_registration(
      user: { id: WebAuthn.generate_user_id, name: "Jane Doe" }
    )
    raw_attestation = client.create(challenge: registration_options.challenge, rp_id: relying_party.id)
    attestation = relying_party.verify_registration(raw_attestation, registration_options.challenge)

    { public_key: attestation.public_key, sign_count: attestation.sign_count }
  end

  def complete(raw_credential)
    service.complete_operation(
      raw_credential,
      public_key: registered_credential[:public_key],
      sign_count: registered_credential[:sign_count]
    )
  end

  def client_hint_only_result(challenge)
    client.get(challenge: challenge, rp_id: relying_party.id).tap do |result|
      result["clientExtensionResults"] = trusted_output.dup
    end
  end

  context "with two concurrent operations of different purpose on the same client" do
    it "binds trusted output to the operation that requested it, whatever the return order" do
      # Requests go out in this order: display flow first, admittance flow second.
      display_operation = service.begin_operation("ui-preview")
      admittance_operation = service.begin_operation("hardware-admittance", extensions: extension_input)

      expect(display_operation.options.extensions).to eq({})
      expect(admittance_operation.options.extensions).to eq(extension_input)
      expect(admittance_operation.options.challenge).not_to eq(display_operation.options.challenge)

      # The client returns in the opposite order: first a result carrying
      # trusted authenticator output, then a valid result with only client hints.
      admittance_result = client.get(
        challenge: admittance_operation.options.challenge,
        rp_id: relying_party.id,
        extensions: trusted_output
      )
      display_result = client_hint_only_result(display_operation.options.challenge)

      admittance_decision = complete(admittance_result)
      display_decision = complete(display_result)

      # Three-way cross-check for the admittance flow: the generated options,
      # the verified authenticator data and the application decision all agree.
      expect(admittance_decision.purpose).to eq("hardware-admittance")
      expect(admittance_decision.options).to equal(admittance_operation.options)
      expect(admittance_decision.credential.authenticator_extension_outputs).to eq(trusted_output)
      expect(admittance_decision.trusted_outputs).to eq(trusted_output)
      expect(admittance_decision.display_hints).to eq(trusted_output)

      # The display flow only gets display hints; nothing is trusted even
      # though the client used the very same extension identifier.
      expect(display_decision.purpose).to eq("ui-preview")
      expect(display_decision.options).to equal(display_operation.options)
      expect(display_decision.credential.authenticator_extension_outputs).to be_nil
      expect(display_decision.trusted_outputs).to eq({})
      expect(display_decision.display_hints).to eq(trusted_output)
    end
  end

  it "does not trust authenticator output that the operation never requested" do
    operation = service.begin_operation("ui-preview")

    # The authenticator passes basic verification while returning extension
    # output that this operation never asked for.
    unsolicited_result = client.get(
      challenge: operation.options.challenge,
      rp_id: relying_party.id,
      extensions: trusted_output
    )

    decision = complete(unsolicited_result)

    expect(operation.requested?(extension_id)).to be(false)
    expect(decision.credential.authenticator_extension_outputs).to eq(trusted_output)
    expect(decision.trusted_outputs).to eq({})
    expect(decision.display_hints).to eq(trusted_output)
  end

  it "never carries a previous success into a new operation" do
    first_operation = service.begin_operation("hardware-admittance", extensions: extension_input)
    first_result = client.get(
      challenge: first_operation.options.challenge,
      rp_id: relying_party.id,
      extensions: trusted_output
    )
    first_decision = complete(first_result)
    expect(first_decision.trusted_outputs).to eq(trusted_output)

    # Same purpose, same client, fresh options — but the authenticator
    # returns no extension output this time.
    second_operation = service.begin_operation("hardware-admittance", extensions: extension_input)
    second_result = client.get(challenge: second_operation.options.challenge, rp_id: relying_party.id)
    second_decision = complete(second_result)

    expect(second_decision.trusted_outputs).to eq({})
    expect(second_decision.options).to equal(second_operation.options)
    expect(second_decision.options.challenge).not_to eq(first_decision.options.challenge)

    # The earlier success stays associated with its own initiating options.
    expect(service.decisions).to eq([first_decision, second_decision])
    expect(first_decision.options).to equal(first_operation.options)
    expect(first_decision.trusted_outputs).to eq(trusted_output)
  end

  it "rejects results that do not match any operation it initiated" do
    service.begin_operation("hardware-admittance", extensions: extension_input)

    foreign_options = relying_party.options_for_authentication(extensions: extension_input)
    foreign_result = client.get(
      challenge: foreign_options.challenge,
      rp_id: relying_party.id,
      extensions: trusted_output
    )

    expect { complete(foreign_result) }.to raise_error(HardwareAdmittanceService::UnknownOperationError)
    expect(service.decisions).to be_empty
  end
end
