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
        if request.params['error']
          fail!(request.params['error'])
        elsif !options.provider_ignores_state && (request.params['state'].to_s.empty? || request.params['state'] != session.delete('omniauth.state'))
          fail!(:csrf_detected)
        else # success
          unless request.params['id_token'].present? && request.params['user'].present?
            self.access_token = build_access_token
            self.access_token = access_token.refresh! if access_token.expired?
          end
          super
        end
      rescue ::Timeout::Error, ::Errno::ETIMEDOUT => e
        fail!(:timeout, e)
      rescue ::SocketError => e
        fail!(:failed_to_connect, e)
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
        @user_info ||= JSON.parse(info) if info.present?
      end

      def client_secret
        payload = {
          iss: options.team_id,
          aud: 'https://appleid.apple.com',
          sub: options.client_id,
          iat: Time.now.to_i,
          exp: Time.now.to_i + 60
        }
        headers = { alg: 'ES256', kid: options.key_id }

        ::JWT.encode(payload, private_key, 'ES256', headers)
      end

      def private_key
        OpenSSL::PKey::EC.new(options.pem)
      end
    end
  end
end
