# frozen_string_literal: true

require 'sorcery/providers/base'
require 'sorcery/protocols/oauth2'

module Sorcery
  module Providers
    class TwitterOauth2 < Base
      include Protocols::Oauth2

      attr_accessor :user_info_path

      def initialize
        super
        @site = 'https://api.twitter.com'
        @user_info_path = '/2/users/me'
      end

      def login_url(params, session)
        authorize_url(params: params, session: session)
      end

      def process_callback(params, session)
        get_access_token({ code: params[:code] }, {})
      end

      def get_user_hash(access_token)
        response = access_token.get(user_info_path)
        auth_hash(access_token).tap do |h|
          h[:user_info] = JSON.parse(response.body)
          h[:uid] = h[:user_info]['id'].to_s
        end
      end
    end
  end
end
