# frozen_string_literal: true

module Sorcery
  # Default record used by Sorcery::RecentAuthenticationStore::ActiveRecordStore.
  # Applications using a different persistence layer can point
  # `config.recent_authentication_store` at their own store instead.
  class RecentAuthenticationRecord < ActiveRecord::Base
    self.table_name = 'sorcery_recent_authentications'
  end
end
