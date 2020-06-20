# frozen_string_literal: true

require 'spec_helper'
require_relative '../../../lib/omniauth/apple/version'

describe OmniAuth::Apple do
  it 'has VERSION' do
    expect(OmniAuth::Apple::VERSION).to be_a String
  end

  it 'is correct' do
    expect(Gem::Version.correct?(OmniAuth::Apple::VERSION)).to be true
  end
end
