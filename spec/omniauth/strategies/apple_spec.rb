# frozen_string_literal: true

require 'spec_helper'

describe OmniAuth::Strategies::Apple do
  let(:request) { double('Request', params: {}, cookies: {}, env: {}) }
  let(:app) do
    lambda do
      [200, {}, ['Hello.']]
    end
  end

  let(:options) {{
      team_id: 'my-team-id',
      key_id: 'my-key-id',
      pem: ::OpenSSL::PKey::EC.generate('prime256v1').to_pem,
  }}

  let(:apple_key) { OpenSSL::PKey::RSA.generate(1024) }
  let(:auth_keys) do
    {
        keys: [
            {
                kty: "RSA",
                kid: "1",
                use: "sig",
                alg: "RS256",
                n: Base64.urlsafe_encode64(apple_key.n.to_s(2)),
                e: Base64.urlsafe_encode64(apple_key.e.to_s(2)),
            }
        ]
    }
  end
  let(:kid)  do
    '1'
  end
  let(:valid_id_token_payload) do
    {
      iss: 'https://appleid.apple.com',
      sub: 'sub-1',
      aud: 'appid',
      exp: Time.now + 3600,
      iat: Time.now,
      nonce_supported: true,
      email: 'something@privatrerelay.appleid.com',
      email_verified: true,
    }
  end
  let(:id_token_payload) do
    valid_id_token_payload
  end
  let(:id_token) do
    jwt = JSON::JWT.new(id_token_payload)
    jwt.kid = kid
    jwt.sign(apple_key).to_s
  end
  let(:access_token) { OAuth2::AccessToken.from_hash(subject.client, 'id_token' => id_token) }
  let(:strategy) do
    OmniAuth::Strategies::Apple.new(app, 'appid', 'secret', options ).tap do |strategy|
      allow(strategy).to receive(:request) do
        request
      end
    end
  end
  subject { strategy }

  before do
    OmniAuth.config.test_mode = true
    stub_request(:get, 'https://appleid.apple.com/auth/keys').to_return(
      body: auth_keys.to_json,
      headers: {
       'Content-Type': 'application/json'
      }
    )
  end

  after do
    OmniAuth.config.test_mode = false
    WebMock.reset!
  end

  describe '#client_options' do
    it 'has correct site' do
      expect(subject.client.site).to eq('https://appleid.apple.com')
    end

    it 'has correct authorize_url' do
      expect(subject.client.options[:authorize_url]).to eq('/auth/authorize')
    end

    it 'has correct token_url' do
      expect(subject.client.options[:token_url]).to eq('/auth/token')
    end

    it 'has correct auth_scheme' do
      expect(subject.client.options[:auth_scheme]).to eq(:request_body)
    end

    describe 'overrides' do
      context 'as strings' do
        it 'should allow overriding the site' do
          options.merge!({ client_options: {'site' => 'https://example.com'} })
          expect(subject.client.site).to eq('https://example.com')
        end

        it 'should allow overriding the authorize_url' do
          options.merge!({ client_options: { 'authorize_url' => 'https://example.com' } })
          expect(subject.client.options[:authorize_url]).to eq('https://example.com')
        end

        it 'should allow overriding the token_url' do
          options.merge!({ client_options: { 'token_url' => 'https://example.com' } })
          expect(subject.client.options[:token_url]).to eq('https://example.com')
        end
      end

      context 'as symbols' do
        it 'should allow overriding the site' do
          options.merge!({ client_options: { site: 'https://example.com' } })
          expect(subject.client.site).to eq('https://example.com')
        end

        it 'should allow overriding the authorize_url' do
          options.merge!({ client_options: { authorize_url: 'https://example.com' } })
          expect(subject.client.options[:authorize_url]).to eq('https://example.com')
        end

        it 'should allow overriding the token_url' do
          options.merge!({ client_options: { token_url: 'https://example.com' } })
          expect(subject.client.options[:token_url]).to eq('https://example.com')
        end
      end
    end
  end

  describe '#authorize_options' do
    %i[scope].each do |k|
      it "should support '#{k}'" do
        options.merge!({ k => 'http://someval' })
        expect(subject.authorize_params[k.to_s]).to eq('http://someval')
      end
    end

    describe 'redirect_uri' do
      it 'should default to nil' do
        expect(subject.authorize_params['redirect_uri']).to eq(nil)
      end
    end

    describe 'scope' do
      it "should set default scope to 'email name'" do
        expect(subject.authorize_params['scope']).to eq('email name')
      end

      it 'should support space delimited scopes' do
        options.merge!(scope: 'one two')
        expect(subject.authorize_params['scope']).to eq('one two')
      end

    end

    describe 'state' do
      it 'should set the omniauth.state' do
        expect(subject.authorize_params['state']).to match /\h+/
      end
    end

    describe 'overrides' do
      it 'should include top-level options that are marked as :authorize_options' do
        options.merge!(authorize_options: %i[scope foo request_visible_actions], scope: 'http://bar', foo: 'baz', hd: 'wow', request_visible_actions: 'something')
        expect(subject.authorize_params['scope']).to eq('http://bar')
        expect(subject.authorize_params['foo']).to eq('baz')
        expect(subject.authorize_params['hd']).to eq(nil)
        expect(subject.authorize_params['request_visible_actions']).to eq('something')
      end
    end
  end

  describe '#authorize_params' do
    it 'should include any authorize params passed in the :authorize_params option' do
      options.merge!(authorize_params: { request_visible_actions: 'something', foo: 'bar', baz: 'zip' }, bad: 'not_included')
      expect(subject.authorize_params['request_visible_actions']).to eq('something')
      expect(subject.authorize_params['foo']).to eq('bar')
      expect(subject.authorize_params['baz']).to eq('zip')
      expect(subject.authorize_params['bad']).to eq(nil)
    end
  end

  describe '#token_params' do
    it 'should include any token params passed in the :token_params option' do
      options.merge!(token_params: { foo: 'bar', baz: 'zip' })
      expect(subject.token_params['foo']).to eq('bar')
      expect(subject.token_params['baz']).to eq('zip')
    end
  end

  describe '#token_options' do
    it 'should include top-level options that are marked as :token_options' do
      options.merge!(token_options: %i[scope foo], scope: 'bar', foo: 'baz', bad: 'not_included')
      expect(subject.token_params['scope']).to eq('bar')
      expect(subject.token_params['foo']).to eq('baz')
      expect(subject.token_params['bad']).to eq(nil)
    end
  end

  describe '#callback_url' do
    let(:base_url) { 'https://example.com' }

    it 'has the correct default callback path' do
      allow(subject).to receive(:full_host) { base_url }
      allow(subject).to receive(:script_name) { '' }
      expect(subject.send(:callback_url)).to eq(base_url + '/auth/apple/callback')
    end

    it 'should set the callback path with script_name if present' do
      allow(subject).to receive(:full_host) { base_url }
      allow(subject).to receive(:script_name) { '/v1' }
      expect(subject.send(:callback_url)).to eq(base_url + '/v1/auth/apple/callback')
    end
  end

  describe '#callback_path' do
    it 'has the correct default callback path' do
      subject.authorize_params # initializes env, session (for test_mode) and populates 'nonce', 'state'
      expect(subject.callback_path).to eq('/auth/apple/callback')
    end

    it 'should set the callback_path parameter if present' do
      options.merge!(callback_path: '/auth/foo/callback')
      subject.authorize_params # initializes env, session (for test_mode) and populates 'nonce', 'state'
      expect(subject.callback_path).to eq('/auth/foo/callback')
    end
  end

  describe '#info' do
    let(:user_info_payload) do
      {
        name: {
          firstName: 'first',
          lastName: 'last',
        },
        email: 'something@privatrerelay.appleid.com',
      }
    end
    before(:each) do
      subject.authorize_params # initializes session / populates 'nonce', 'state', etc
      id_token_payload['nonce'] = subject.session['omniauth.nonce']
      request.params.merge!('id_token' => id_token, 'user' => user_info_payload.to_json)
    end

    it 'should return sub' do
      expect(subject.info[:sub]).to eq 'sub-1'
    end

    it 'should return email' do
      expect(subject.info[:email]).to eq('something@privatrerelay.appleid.com')
    end

    it 'should return first_name' do
      expect(subject.info[:first_name]).to eq 'first'
    end

    it 'should return last_name' do
      expect(subject.info[:last_name]).to eq 'last'
    end

    it 'should return name' do
      # https://github.com/omniauth/omniauth/wiki/Auth-Hash-Schema
      # schema lists 'name' as required property
      expect(subject.info[:name]).to eq 'first last'
    end

    context 'with a spoofed email in the user payload' do
      before do
        request.params['user'] = {
          name: {
            firstName: 'first',
            lastName: 'last'
          },
          email: "spoofed@example.com"
        }.to_json
      end

      it 'should return the true email' do
        expect(subject.info[:email]).to eq('something@privatrerelay.appleid.com')
      end
    end
  end

  describe '#extra' do
    before(:each) do
      strategy.authorize_params # initializes session / populates 'nonce', 'state', etc
      id_token_payload[:nonce] ||= strategy.session['omniauth.nonce']
    end

    describe 'extra[:raw_info]' do
      subject { strategy.extra[:raw_info] }

      context 'when the id_token is given' do
        before(:each) do
          request.params.merge!('id_token' => id_token)
        end

        context 'when valid' do
          it { is_expected.to include(id_token: id_token) }
          it { is_expected.to include(id_info: id_token_payload) }
          it do
            expect(strategy).not_to receive(:fail!)
            subject
          end
        end

        context 'when signature invalid' do
          let(:id_token) do
            jwt = JSON::JWT.new(id_token_payload)
            jwt.kid = kid
            jwt.to_s
          end

          it do
            expect { subject }.to raise_error(
              OmniAuth::Strategies::OAuth2::CallbackError, /id_token_signature_invalid/
            )
          end
        end

        context 'when claims invalid' do
          let(:id_token_payload) do
            valid_id_token_payload.merge(invalid_claims)
          end

          shared_examples :invalid_at do |claim|
            it do
              expect { subject }.to raise_error(
                OmniAuth::Strategies::OAuth2::CallbackError, "id_token_claims_invalid | #{claim} invalid"
              )
            end
          end

          context 'on iss' do
            let(:invalid_claims) do
              { iss: 'https://invalid.example.com' }
            end
            it_behaves_like :invalid_at, :iss
          end

          context 'on aud' do
            let(:invalid_claims) do
              { aud: 'invalid_client' }
            end
            it_behaves_like :invalid_at, :aud
          end

          context 'on iat' do
            let(:invalid_claims) do
              { iat: Time.now + 30 }
            end
            it_behaves_like :invalid_at, :iat
          end

          context 'on exp' do
            let(:invalid_claims) do
              { exp: Time.now - 30 }
            end
            it_behaves_like :invalid_at, :exp
          end
        end
      end

      context 'otherwise' do
        it { is_expected.to be_nil }
      end
    end
  end

  describe 'network errors' do
    before do
      subject.authorize_params # initializes session / populates 'nonce', 'state', etc
      id_token_payload['nonce'] = subject.session['omniauth.nonce']
      request.params.merge!('id_token' => id_token)
    end

    context 'when JWKS fetching failed' do
      before do
        stub_request(:get, 'https://appleid.apple.com/auth/keys').to_return(
          status: 502,
          body: "<html><head><title>502 Bad Gateway..."
        )
      end

      it do
        expect { subject.info }.to raise_error(
          OmniAuth::Strategies::OAuth2::CallbackError, /jwks_fetching_failed/
        )
      end
    end

    context 'when JWKS format is invalid' do
      before do
        stub_request(:get, 'https://appleid.apple.com/auth/keys').to_return(
          body: 'invalid',
          headers: {
            'Content-Type': 'application/json'
          }
        )
      end

      it do
        expect { subject.info }.to raise_error(
          OmniAuth::Strategies::OAuth2::CallbackError, /jwks_fetching_failed/
        )
      end
    end
  end
end
