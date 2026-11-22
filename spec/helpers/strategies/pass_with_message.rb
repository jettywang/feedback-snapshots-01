# encoding: utf-8
# frozen_string_literal: true
Warden::Strategies.add(:pass_with_message) do
  def authenticate!
    request.env['warden.spec.strategies'] ||= []
    request.env['warden.spec.strategies'] << :pass_with_message
    success!("Valid User", "The Success Strategy Has Accepted You") unless scope == :failz
  end
end

# Performs an ordinary login that explicitly declares level 1.
Warden::Strategies.add(:level_one) do
  def authenticate!
    request.env['warden.spec.strategies'] ||= []
    request.env['warden.spec.strategies'] << :level_one
    success!("Level One User", nil, :level => 1)
  end
end

# Performs a step-up verification declaring level 2.
Warden::Strategies.add(:level_two) do
  authentication_level 2

  def authenticate!
    request.env['warden.spec.strategies'] ||= []
    request.env['warden.spec.strategies'] << :level_two
    success!("Level Two User")
  end
end

# Succeeds, but only verifies level 1, so it cannot satisfy a level 2 action.
Warden::Strategies.add(:weak_step_up) do
  authentication_level 1

  def authenticate!
    request.env['warden.spec.strategies'] ||= []
    request.env['warden.spec.strategies'] << :weak_step_up
    success!("Weak User")
  end
end

# Fails the step-up attempt outright.
Warden::Strategies.add(:failed_step_up) do
  authentication_level 2

  def authenticate!
    request.env['warden.spec.strategies'] ||= []
    request.env['warden.spec.strategies'] << :failed_step_up
    fail!("Second factor rejected")
  end
end
