class SearchBase < ApplicationRecord
  def self.ransackable_attributes(auth_object = nil)
    [:id, :name]
  end

  def self.ransackable_associations(auth_object = nil)
    []
  end
end

class FiniteChild < SearchBase
  def self.ransackable_attributes(auth_object = nil)
    [:title, :body]
  end
end

class ConditionalFiniteChild < SearchBase
  def self.ransackable_attributes(auth_object = nil)
    if auth_object&.admin?
      [:title]
    else
      [:title, :body]
    end
  end
end

class BroadParent < ApplicationRecord
  def self.ransackable_attributes(auth_object = nil)
    [:id]
  end

  def self.ransackable_associations(auth_object = nil)
    reflect_on_all_associations.map(&:name)
  end
end

class NarrowChild < BroadParent
  def self.ransackable_attributes(auth_object = nil)
    [:title]
  end
end

class FallbackAllowList < ApplicationRecord
  def self.ransackable_attributes(auth_object = nil)
    column_names
  end

  def self.ransackable_associations(auth_object = nil)
    []
  end
end

class DynamicAllowList < ApplicationRecord
  def self.ransackable_attributes(auth_object = nil)
    allowed_attributes_for(auth_object)
  end

  def self.ransackable_associations(auth_object = nil)
    []
  end
end

class ConcatenatedAllowList < ApplicationRecord
  def self.ransackable_attributes(auth_object = nil)
    [:title] + [params[:column]]
  end

  def self.ransackable_associations(auth_object = nil)
    []
  end
end

class AllAssociations < ApplicationRecord
  def self.ransackable_attributes(auth_object = nil)
    [:title]
  end

  def self.ransackable_associations(auth_object = nil)
    reflect_on_all_associations.map(&:name)
  end
end

class ConditionalFallback < ApplicationRecord
  def self.ransackable_attributes(auth_object = nil)
    if auth_object&.admin?
      [:title]
    else
      column_names
    end
  end

  def self.ransackable_associations(auth_object = nil)
    []
  end
end
