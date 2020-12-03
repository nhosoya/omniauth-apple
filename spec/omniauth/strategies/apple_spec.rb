# frozen_string_literal: true

require 'spec_helper'
require 'json'
require 'omniauth-apple'

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
  let(:id_token_header)  do
    { kid: '1' }
  end
  let(:id_token_payload) do
    {
        'iss' => 'https://appleid.apple.com',
        'sub' => 'sub-1',
        'aud' => 'appid',
        'exp' => Time.now.to_i + 3600,
        'iat' => Time.now.to_i,
        'nonce_supported' => true,
        'email' => 'something@privatrerelay.appleid.com',
        'email_verified' => true,
    }
  end
  let(:id_token) { JWT.encode(id_token_payload, apple_key, 'RS256', id_token_header) }
  let(:access_token) { OAuth2::AccessToken.from_hash(subject.client, 'id_token' => id_token) }

  subject do
    OmniAuth::Strategies::Apple.new(app, 'appid', 'secret', options ).tap do |strategy|
      allow(strategy).to receive(:request) do
        request
      end
    end
  end

  before do
    OmniAuth.config.test_mode = true
    stub_request(:get, 'https://appleid.apple.com/auth/keys').to_return(body: auth_keys.to_json)
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

  describe '#callback_path' do
    it 'has the correct default callback path' do
      expect(subject.callback_path).to eq('/auth/apple/callback')
    end

    it 'should set the callback_path parameter if present' do
      options.merge!(callback_path: '/auth/foo/callback')
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

    context 'fails nonce' do
      before(:each) do
        expect(subject).to receive(:fail!).with(:nonce_mismatch, instance_of(OmniAuth::Strategies::OAuth2::CallbackError))
      end
      it 'when differs from session' do
        subject.session['omniauth.nonce'] = 'abc'
        subject.info
      end
      it 'when missing from session' do
        subject.session.delete('omniauth.nonce')
        subject.info
      end
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
      subject.authorize_params # initializes session / populates 'nonce', 'state', etc
      id_token_payload['nonce'] = subject.session['omniauth.nonce']
    end

    describe 'id_token' do
      context 'issued by valid issuer' do
        before(:each) do
          request.params.merge!('id_token' => id_token)
        end
        context 'when the id_token is passed into the access token' do
          it 'should include id_token when set on the access_token' do
            expect(subject.extra[:raw_info]).to include(id_token: id_token)
          end

          it 'should include id_info when id_token is set on the access_token' do
            expect(subject.extra[:raw_info]).to include(id_info: id_token_payload)
          end
        end
      end

      context 'issued by invalid issuer' do
        it 'raises JWT::InvalidIssuerError' do
          id_token_payload['iss'] = 'https://appleid.badguy.com'
          request.params.merge!('id_token' => id_token)
          expect { subject.extra }.to raise_error(JWT::InvalidIssuerError)
        end
      end

      context 'when the id_token is missing' do
        it 'should not include id_token' do
          allow(subject).to receive(:access_token).and_return(nil)
          expect(subject.extra).not_to have_key(:raw_info)
        end

        it 'should not include id_info' do
          allow(subject).to receive(:access_token).and_return(nil)
          expect(subject.extra).not_to have_key(:raw_info)
        end
      end
    end

 end

end
