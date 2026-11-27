# frozen_string_literal: true

class CreateSorceryRecentAuthentications < ActiveRecord::Migration::Current
  def self.up
    create_table :sorcery_recent_authentications do |t|
      t.integer  :user_id,          null: false
      t.string   :session_id,       null: false
      t.string   :operation,        null: false
      t.datetime :authenticated_at, null: false
      t.datetime :expires_at,       null: false
      t.datetime :revoked_at,       default: nil

      t.timestamps null: false
    end

    add_index :sorcery_recent_authentications, %i[user_id session_id operation],
              name: 'index_sorcery_recent_authentications_lookup'
    add_index :sorcery_recent_authentications, :expires_at
  end

  def self.down
    drop_table :sorcery_recent_authentications
  end
end
