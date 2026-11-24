# frozen_string_literal: true

require "json"
require "dry/schema/messages/i18n"
require "dry/schema/extensions/hints"

RSpec.describe Dry::Schema, "shareable messages" do
  FIXTURE_PATH = File.expand_path("../fixtures/shareable_messages.yml", __dir__)

  let(:private_sample) { "PRIVATE-SAMPLE-8421" }
  let(:email_sample) { "EMAIL-SAMPLE-314" }
  let(:expected_vault) { "VAULT-EXPECTED-42" }

  let(:schema) do
    Dry::Schema.define do
      config.messages.backend = :i18n
      config.messages.load_paths = [FIXTURE_PATH]

      required(:account).hash do
        required(:contacts).array(:hash) do
          required(:email).filled(eql?: "partner@example.test")
          required(:vault_code).filled(eql?: "VAULT-EXPECTED-42")
        end
      end
    end
  end

  let(:result) do
    schema.(
      account: {
        contacts: [
          {email: email_sample, vault_code: private_sample},
          {email: "", vault_code: ""}
        ]
      }
    )
  end

  let(:allowed_fields) { ["account.contacts.*.email"] }

  before do
    I18n.load_path = [FIXTURE_PATH]
    I18n.reload!
  end

  let(:shared_records) do
    result.shareable_messages_for(:en, :ja, allow_fields: allowed_fields)
  end

  def internal_text(locale)
    [
      result.errors(locale: locale).map(&:text),
      result.hints(locale: locale).hints.map(&:text)
    ].flatten.join("\n")
  end

  it "compares identical redacted output with different full internal messages" do
    expect(internal_text(:en)).to include("EN expected", private_sample, email_sample)
    expect(internal_text(:ja)).to include("JA expected", private_sample, email_sample)
    expect(internal_text(:en)).not_to eq(internal_text(:ja))

    expect(shared_records[:ja]).to eq(shared_records[:en])

    expect(shared_records[:en].map { |record|
      record.values_at(:path, :category, :code, :origin)
    }).to eq(
      [
        [
          %i[account contacts] + [0, :email],
          :eql?,
          "equality_mismatch",
          "error"
        ],
        [
          %i[account contacts] + [1, :email],
          :filled?,
          "required",
          "error"
        ],
        [
          %i[account contacts] + [1, :email],
          :eql?,
          "equality_hint",
          "hint"
        ]
      ]
    )
  end

  it "preserves hint attribution independently from errors" do
    hint = result.hints(locale: :ja).hints.find do |message|
      message.path == %i[account contacts] + [1, :email] && message.predicate == :eql?
    end

    expect(hint).to be_a(Dry::Schema::Hint)

    origins = result
      .shareable_messages(locale: :ja, allow_fields: allowed_fields)
      .group_by { |message| message.path }

    expect(origins[%i[account contacts] + [1, :email]].map(&:origin)).to eq(%w[error hint])
    expect(result.shareable_errors(locale: :ja, allow_fields: allowed_fields))
      .to all(be_error)
    expect(result.shareable_hints(locale: :ja, allow_fields: allowed_fields).map(&:origin))
      .to eq(%w[hint])
  end

  it "keeps original array indexes and supports exact field locations" do
    records = result.shareable_messages(
      locale: :en,
      allow_fields: ["/account/contacts/0/email"]
    ).records

    expect(records.map { |record| record[:path] }).to all(start_with(%i[account contacts] + [0]))
    expect(records.size).to eq(1)
  end

  it "omits private field locations and all sample/template/argument content" do
    payload = JSON.generate(shared_records)

    expect(payload).not_to include(private_sample)
    expect(payload).not_to include(email_sample)
    expect(payload).not_to include(expected_vault)
    expect(payload).not_to include("partner@example.test")
    expect(payload).not_to include("sample was")
    expect(payload).not_to include("vault_code")
  end

  it "does not expose rendered text when adapting an existing message" do
    message = Dry::Schema::Message.new(
      text: "template leaked #{private_sample}",
      path: %i[account vault_code],
      predicate: :format?,
      args: [private_sample],
      input: private_sample,
      meta: {code: "format_invalid", sensitive_meta: private_sample}
    )

    shared = message.to_shareable_h

    expect(shared).to include(
      path: %i[account vault_code],
      category: :format?,
      code: "format_invalid",
      origin: "error"
    )
    expect(shared[:text]).to be_nil
    expect(JSON.generate(shared)).not_to include(private_sample)
  end

  it "can rewrite field locations without exposing source message data" do
    representation = result.shareable_messages(
      locale: :en,
      allow_fields: allowed_fields,
      field_map: {"account.contacts" => "recipients"}
    )

    expect(representation.records.map { |record| record[:path] }.uniq).to include(
      %i[recipients] + [0, :email],
      %i[recipients] + [1, :email]
    )
  end
end
