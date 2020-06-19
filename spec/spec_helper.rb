# frozen_string_literal: true

require File.join('bundler', 'setup')
require 'rspec'
require 'simplecov'
SimpleCov.start('test_frameworks')

require 'webmock/rspec'
WebMock.disable_net_connect!
