class GreetingsController < ApplicationController
  def show
    @name = params[:name]
  end
end
