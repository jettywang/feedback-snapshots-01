class HomeController < ApplicationController
  def index
    # Signed and encrypted cookie reads are the entry points where
    # the configured serializer deserializes cookie data
    user_id = cookies.signed[:user_id]
    token = cookies.encrypted[:token]

    if user_id and token
      head :ok
    else
      head :unauthorized
    end
  end
end
