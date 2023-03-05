# frozen_string_literal: true

require 'omniauth-oauth2'
require 'json/jwt'

module OmniAuth
  module Strategies
    class Apple < OmniAuth::Strategies::OAuth2
      ISSUER = 'https://appleid.apple.com'

      option :name, 'apple'

      option :client_options,
             site: ISSUER,
             authorize_url: '/auth/authorize',
             token_url: '/auth/token',
             auth_scheme: :request_body
      option :authorize_params,
             response_mode: 'form_post',
             scope: 'email name'
      option :authorized_client_ids, []

      uid { id_info[:sub] }

      # Documentation on parameters
      # https://developer.apple.com/documentation/sign_in_with_apple/sign_in_with_apple_rest_api/authenticating_users_with_sign_in_with_apple
      info do
        prune!(
          sub: id_info[:sub],
          email: email,
          first_name: first_name,
          last_name: last_name,
          name: (first_name || last_name) ? [first_name, last_name].join(' ') : email,
          email_verified: email_verified,
          is_private_email: is_private_email
        )
      end

      extra do
        id_token_str = request.params['id_token'] || access_token&.params&.dig('id_token')
        prune!(raw_info: {id_info: id_info, user_info: user_info, id_token: id_token_str})
      end

      def client
        ::OAuth2::Client.new(client_id, client_secret, deep_symbolize(options.client_options))
      end

      def email_verified
        value = id_info[:email_verified]
        value == true || value == "true"
      end

      def is_private_email
        value = id_info[:is_private_email]
        value == true || value == "true"
      end

      def authorize_params
        super.merge(nonce: new_nonce)
      end

      def callback_url
        options[:redirect_uri] || (full_host + callback_path)
      end

      private

      def new_nonce
        session['omniauth.nonce'] = SecureRandom.urlsafe_base64(16)
      end

      def id_info
        @id_info ||= if request.params&.key?('id_token') || access_token&.params&.key?('id_token')
                       id_token_str = request.params['id_token'] || access_token.params['id_token']
                       id_token = JSON::JWT.decode(id_token_str, :skip_verification)
                       verify_id_token! id_token
                       id_token
                     end
      end

      def verify_id_token!(id_token)
        jwk = fetch_jwk! id_token.kid
        verify_signature! id_token, jwk
        verify_claims! id_token
      end

      def fetch_jwk!(kid)
        JSON::JWK::Set::Fetcher.fetch File.join(ISSUER, 'auth/keys'), kid: kid
      rescue => e
        raise CallbackError.new(:jwks_fetching_failed, e)
      end

      def verify_signature!(id_token, jwk)
        id_token.verify! jwk
      rescue => e
        raise CallbackError.new(:id_token_signature_invalid, e)
      end

      def verify_claims!(id_token)
        verify_iss!(id_token)
        verify_aud!(id_token)
        verify_iat!(id_token)
        verify_exp!(id_token)
      end

      def verify_iss!(id_token)
        invalid_claim! :iss unless id_token[:iss] == ISSUER
      end

      def verify_aud!(id_token)
        invalid_claim! :aud unless [options.client_id].concat(options.authorized_client_ids).include?(id_token[:aud])
      end

      def verify_iat!(id_token)
        invalid_claim! :iat unless id_token[:iat] <= Time.now.to_i
      end

      def verify_exp!(id_token)
        invalid_claim! :exp unless id_token[:exp] >= Time.now.to_i
      end

      def invalid_claim!(claim)
        raise CallbackError.new(:id_token_claims_invalid, "#{claim} invalid")
      end

      def client_id
        @client_id ||= if id_info.nil?
                         options.client_id
                       else
                         id_info[:aud] if options.authorized_client_ids.include? id_info[:aud]
                       end
      end

      def user_info
        user = request.params['user']
        return {} if user.nil?

        @user_info ||= JSON.parse(user)
      end

      def email
        id_info[:email]
      end

      def first_name
        user_info.dig('name', 'firstName')
      end

      def last_name
        user_info.dig('name', 'lastName')
      end

      def prune!(hash)
        hash.delete_if do |_, v|
          prune!(v) if v.is_a?(Hash)
          v.nil? || (v.respond_to?(:empty?) && v.empty?)
        end
      end

      def client_secret
        jwt = JSON::JWT.new(
          iss: options.team_id,
          aud: ISSUER,
          sub: client_id,
          iat: Time.now,
          exp: Time.now + 60
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
