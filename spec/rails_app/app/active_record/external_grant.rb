# frozen_string_literal: true

class ExternalGrant < ActiveRecord::Base
  belongs_to :user
end
