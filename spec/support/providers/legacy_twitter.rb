# frozen_string_literal: true

require 'sorcery/providers/base'
require 'sorcery/protocols/oauth'

module Sorcery
  module Providers
    class LegacyTwitter < Base
      include Protocols::Oauth

      attr_accessor :user_info_path

      def initialize
        super
        @site = 'https://api.twitter.com'
        @user_info_path = '/1.1/account/verify_credentials.json'
      end

      def get_consumer
        ::OAuth::Consumer.new(key, secret, site: site, authorize_path: '/oauth/authenticate')
      end

      def get_user_hash(access_token)
        response = access_token.get(user_info_path)
        auth_hash(access_token).tap do |h|
          h[:user_info] = JSON.parse(response.body)
          h[:uid] = h[:user_info]['id_str'].to_s
        end
      end

      def login_url(_params, session)
        request_token = get_request_token
        session[:request_token] = request_token.token
        session[:request_token_secret] = request_token.secret
        authorize_url(request_token: request_token.token, request_token_secret: request_token.secret)
      end

      def process_callback(params, session)
        args = {
          oauth_verifier: params[:oauth_verifier],
          request_token: session[:request_token],
          request_token_secret: session[:request_token_secret]
        }
        get_access_token(args)
      end
    end
  end
end
