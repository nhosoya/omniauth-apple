# frozen_string_literal: true

require File.join('bundler', 'setup')
require 'rspec'
require 'simplecov'
SimpleCov.start('test_frameworks')

require 'omniauth-apple'
OmniAuth.config.logger = Logger.new(nil)

require 'webmock/rspec'
WebMock.disable_net_connect!
