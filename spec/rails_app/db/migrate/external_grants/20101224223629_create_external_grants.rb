# frozen_string_literal: true

class CreateExternalGrants < ActiveRecord::Migration::Current
  def self.up
    create_table :external_grants do |t|
      t.integer :user_id, null: false
      t.string :provider, :purpose, null: false
      t.string :scope
      t.string :status, null: false, default: 'unconfirmed'

      t.timestamps null: false
    end
  end

  def self.down
    drop_table :external_grants
  end
end
