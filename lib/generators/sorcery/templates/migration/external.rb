class SorceryExternal < <%= migration_class_name %>
  def change
    create_table :authentications do |t|
      t.integer :<%= tableized_model_class.singularize %>_id, null: false
      t.string :provider, :uid, null: false
      # Set when a provider confirms the external account is suspended.
      # The record is retained for auditing; a non-null value blocks this login.
      t.datetime :disabled_at

      t.timestamps              null: false
    end

    add_index :authentications, [:provider, :uid]
  end
end
