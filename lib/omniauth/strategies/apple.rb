# frozen_string_literal: true

require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class Apple < OmniAuth::Strategies::OAuth2
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

      private

      def id_info
        log(:info, "id_token: #{access_token.params['id_token']}")
        @id_info ||= ::JWT.decode(access_token.params['id_token'], nil, false)[0] # payload after decoding
        log(:info, "id_info: #{@id_info}")
      end

      def client_secret
        payload = {
          iss: options[:team_id],
          aud: 'https://appleid.apple.com',
          sub: options.client_id,
          iat: Time.now.to_i,
          exp: Time.now.to_i + 60
        }
        headers = { alg: 'ES256', kid: options[:key_id] }

        ::JWT.encode(payload, private_key, 'ES256', headers)
      end

      def private_key
        OpenSSL::PKey::EC.new(options[:pem])
      end
    end
  end
end
