class SorceryRecentAuthentication < <%= migration_class_name %>
  def change
    create_table :sorcery_recent_authentications do |t|
      t.integer  :user_id,          null: false
      t.string   :session_id,       null: false
      t.string   :operation,        null: false
      t.datetime :authenticated_at, null: false
      t.datetime :expires_at,       null: false
      t.datetime :revoked_at,       default: nil

      t.timestamps null: false
    end

    add_index :sorcery_recent_authentications, [:user_id, :session_id, :operation], name: 'index_sorcery_recent_authentications_lookup'
    add_index :sorcery_recent_authentications, :expires_at
  end
end
