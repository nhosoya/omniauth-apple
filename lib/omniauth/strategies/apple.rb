# frozen_string_literal: true

require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class Apple < OmniAuth::Strategies::OAuth2
      attr_reader :id_info

      option :name, 'apple'
      option :client_options,
             site: 'https://appleid.apple.com',
             authorize_url: '/auth/authorize',
             token_url: '/auth/token'

      uid { id_info['sub'] }

      info do
        {
          sub: id_info['sub'],
          extra: {
            raw_info: id_info
          }
        }
      end

      def client
        ::OAuth2::Client.new(options.client_id, client_secret, deep_symbolize(options.client_options))
      end

      def callback_url
        options[:redirect_uri] || (full_host + script_name + callback_path)
      end

      def build_access_token
        _access_token = super
        @id_info = ::JWT.decode(_access_token.params['id_token'], nil, false)
        log(:info, @id_info)
        _access_token
      end

      private

      def client_secret
        payload = {
          iss: options[:team_id],
          aud: 'https://appleid.apple.com',
          sub: options.client_id,
          iat: Time.now.to_i,
          exp: Time.now.to_i + 60
        }
        headers = { kid: options[:key_id] }

        ::JWT.encode(payload, private_key, 'ES256', headers)
      end

      def private_key
        OpenSSL::PKey::EC.new(options[:pem])
      end
    end
  end
end
