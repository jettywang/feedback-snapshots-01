# frozen_string_literal: true

class CreateAuthenticationsAndUserProviders < ActiveRecord::Migration::Current
  def self.up
    create_table :authentications do |t|
      t.integer :user_id, null: false
      t.string :provider, :uid, null: false
      # Timestamp set when a provider notifies us that the external account is suspended.
      # The record is kept for auditing; a non-null value blocks this external login.
      t.datetime :disabled_at

      t.timestamps null: false
    end

    create_table :user_providers do |t|
      t.integer :user_id, null: false
      t.string :provider, :uid, null: false
      t.datetime :disabled_at

      t.timestamps null: false
    end
  end

  def self.down
    drop_table :authentications
    drop_table :user_providers
  end
end
