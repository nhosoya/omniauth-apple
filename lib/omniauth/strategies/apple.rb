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
          email: user_info.dig('email'),
          first_name: user_info.dig('name', 'firstName'),
          last_name: user_info.dig('name', 'lastName'),
          extra: {
            raw_info: id_info.merge(user_info)
          }
        }
      end

      def client
        ::OAuth2::Client.new(options.client_id, client_secret, deep_symbolize(options.client_options))
      end

      def callback_url
        options[:redirect_uri] || (full_host + script_name + callback_path)
      end

      def callback_phase
        log(:info, "request_params: #{request.params}")

        if request.params['id_token'] && request.params['user']
          # Apple-specific callback --> request initiated via Apple JS
          env['omniauth.auth'] = auth_hash
          call_app!
        elsif request.params['code']
          super # regular OAuth2 code flow --> request initiated via OmniAuth
        else
          fail!(:invalid_callback_parameters)
        end
      end

      private

      def id_info
        id_token = request.params['id_token'] || access_token.params['id_token']
        log(:info, "id_token: #{id_token}")
        @id_info ||= ::JWT.decode(id_token, nil, false)[0] # payload after decoding
      end

      def user_info
        info = request.params['user'].presence || access_token.params['user'].presence || '{}'
        log(:info, "user_info: #{info}")
        @user_info ||= info.present? ? JSON.parse(info) : {}
      end

      def client_secret
        payload = {
          iss: options.team_id,
          aud: 'https://appleid.apple.com',
          sub: options.client_id,
          iat: Time.now.to_i,
          exp: Time.now.to_i + 300
        }
        headers = { kid: options.key_id }

        ::JWT.encode(payload, private_key, 'ES256', headers)
      end

      def private_key
        ::OpenSSL::PKey::EC.new(options.pem)
      end
    end
  end
end
