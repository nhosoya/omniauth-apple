# OmniAuth::Apple

OmniAuth strategy for [Sign In with Apple](https://developer.apple.com/sign-in-with-apple/).

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'omniauth-apple', github: 'nhosoya/omniauth-apple', branch: 'master'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install omniauth-apple

## Usage

```ruby
Rails.application.config.middleware.use OmniAuth::Builder do
  provider :apple, ENV['CLIENT_ID'], ENV['TEAM_ID'], ENV['KEY_ID'], ENV['PRIVATE_KEY'],
           {
             scope: 'email name',
           }
end
```

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/nhosoya/omniauth-apple.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
