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
      option :authorize_params,
             response_mode: 'form_post'
      option :authorized_client_ids, []
      
      uid { id_info['sub'] }

      info do
        {
          sub: id_info['sub'],
          email: email,
          first_name: first_name,
          last_name: last_name
        }
      end

      extra do
        {
          raw_info: id_info.merge(user_info)
        }
      end

      def client
        ::OAuth2::Client.new(client_id, client_secret, deep_symbolize(options.client_options))
      end

      def callback_url
        options[:redirect_uri] || (full_host + script_name + callback_path)
      end

      def request_phase
        redirect client.auth_code.authorize_url({:redirect_uri => callback_url}.merge(authorize_params)).gsub(/\+/, '%20')
      end

      private

      def id_info
        if request.params&.key?('id_token') || access_token&.params&.key?('id_token')
          id_token = request.params['id_token'] || access_token.params['id_token']
          log(:info, "id_token: #{id_token}")
          @id_info ||= ::JWT.decode(id_token, nil, false)[0] # payload after decoding
        end
      end

      def client_id
        unless id_info.nil?
          return id_info['aud'] if options.authorized_client_ids.include? id_info['aud']
        end

        options.client_id
      end

      def user_info
        return {} unless request.params['user'].present?

        log(:info, "user_info: #{request.params['user']}")
        @user_info ||= JSON.parse(request.params['user'])
      end

      def email
        user_info['email'] || id_info['email']
      end

      def first_name
        user_info.dig('name', 'firstName')
      end

      def last_name
        user_info.dig('name', 'lastName')
      end

      def client_secret
        payload = {
          iss: options.team_id,
          aud: 'https://appleid.apple.com',
          sub: client_id,
          iat: Time.now.to_i,
          exp: Time.now.to_i + 60
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
