require 'spec_helper'

RSpec.describe OmniAuth::Strategies::Apple do
  let(:access_token) { instance_double('AccessToken', options: {}) }
  let(:parsed_response) { instance_double('ParsedResponse') }
  let(:response) { instance_double('Response', parsed: parsed_response) }

  subject do
    OmniAuth::Strategies::Apple.new({})
  end

  before do
    allow(subject).to receive(:access_token).and_return(access_token)
  end

  context '#options.client_options' do
    it do
      expect(subject.options.client_options.site).to eq('https://appleid.apple.com')
    end

    it do
      expect(subject.options.client_options.authorize_url).to eq('/auth/authorize')
    end

    it do
      expect(subject.options.client_options.token_url).to eq('/auth/token')
    end
  end

  describe '#callback_url' do
    it 'is a combination of host, script name, and callback path' do
      allow(subject).to receive(:full_host).and_return('https://example.com')
      allow(subject).to receive(:script_name).and_return('/sub_uri')

      expect(subject.callback_url).to eq('https://example.com/sub_uri/auth/apple/callback')
    end
  end
end
