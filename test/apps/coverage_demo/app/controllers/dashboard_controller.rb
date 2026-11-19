class DashboardController < ApplicationController
  def run
    # Dangerous call: user input passed straight to a system command
    system(params[:command])
  end
end
