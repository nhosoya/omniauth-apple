require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class Apple < OmniAuth::Strategies::OAuth2

      attr_reader :id_token
      args %i[client_id team_id key_id pem]

      option :name, 'apple'
      option :client_options, {
        site: 'https://appleid.apple.com',
        authorize_url: '/auth/authorize',
        token_url: '/auth/token',
      }

      uid { id_token['sub'] }

      info do
        { sub: id_token['sub'] }
      end

      def client
        ::OAuth2::Client.new(options.client_id, client_secret, deep_symbolize(options.client_options))
      end

      def callback_url
        full_host + script_name + callback_path
      end

      def build_access_token
        _access_token = super
        @id_token = ::JSON::JWT.decode(_access_token.params['id_token'], :skip_verification)
        _access_token
      end

      private

      def client_secret
        jwt = ::JSON::JWT.new(
          iss: options.team_id,
          aud: 'https://appleid.apple.com',
          sub: options.client_id,
          iat: Time.current,
          exp: 1.minutes.after
        )
        jwt.kid = options.key_id
        jwt.sign(private_key).to_s
      end

      def private_key
        ::OpenSSL::PKey::EC.new(options.pem)
      end
    end
  end
end
