class UsersController < ApplicationController
  protect_from_forgery with: :exception

  def show
    @user = User.find(params[:id])
  end

  def helpers
    @user = User.find(params[:id])
  end

  def edge
  end

  def dynamic
  end

  def conditional
  end

  def unknown
  end
end
