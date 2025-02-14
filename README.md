![build](https://github.com/nhosoya/omniauth-apple/workflows/RSpec/badge.svg?branch=master&event=push)

# OmniAuth Apple Strategy

OmniAuth strategy for [Sign In with Apple](https://developer.apple.com/sign-in-with-apple/).

## Installation

Add this line to your application's Gemfile:
```ruby
gem 'omniauth-apple', '~> 1.3.0'
```

Then execute
```bash
bundle install
```

Or install it yourself globally with
```bash
gem install omniauth-apple
```

## Usage
Using Devise ? Skip to <a href="#use-with-devise">Use with Devise</a>

Here's an example for adding the middleware to a Rails app in `config/initializers/omniauth.rb`
```ruby
Rails.application.config.middleware.use OmniAuth::Builder do
  provider :apple, ENV['APPLE_CLIENT_ID'], '', {
    key_id: ENV['APPLE_KEY_ID'],
    pem: ENV['APPLE_PRIVATE_KEY'],
    scope: 'email name',
    team_id: ENV['APPLE_TEAM_ID']
  }
end
```

You can find more confiduration options in the <a href="#configuration">Configuration</a> section.

NOTE: Any change made to the middleware's configuration will required you to reset your server before taking action.

### Use with Devise
When using `omniauth-apple` with Devise you must omit the `config/initializers/omniauth.rb` file.
Instead you can add the middleware's configuration in `config/initializers/devise.rb`
```ruby
# config/initializers/devise.rb
config.omniauth :apple, 'APPLE_CLIENT_ID', '', {
  key_id: ENV['APPLE_KEY_ID'],
  pem: ENV['APPLE_PRIVATE_KEY'],
  scope: 'email name',
  team_id: ENV['APPLE_TEAM_ID']
}
```

Make sure to your Omniauthable model includes the new provider. Generally that model is your `User` model.

You should also create a class method to register and find users from a omniauth provider's callback in your model.
```ruby
# app/models.user.rb
def User < ApplicationRecord
  devise :omniauthable, omniauth_providers: %i[apple]

  class << self
    def from_omniauth(access_token)
      user = find_or_initialize_by(email: access_token.info['email'])
      user.update!(name: access_token.info['name'], password: Devise.friendly_token[0, 20]) unless user.persisted?
      user
    end
  end
end
```

If you want to override Devise's omniauth callback management then update your routes with a custom controller inheriting from Devise's `Devise::OmniauthCallbacksController`
```ruby
# config/routes.rb
devise_for :users, controllers: { omniauth_callbacks: 'users/omniauth_callbacks' }
```
```ruby
# app/controllers/users/omniauth_callbacks_controller.rb
class Users::OmniauthCallbacksController < Devise::OmniauthCallbacksController
  def apple
    # User.from_omniauth needs to be implemented in your `User` model
    @user = User.from_omniauth(request.env['omniauth.auth'])

    if @user.persisted?
      # handle success
    else
      # handle error
    end
  end
end
```

More info can be found in Devise's [wiki](https://github.com/heartcombo/devise/wiki/OmniAuth:-Overview)

### Use with Hybrid application
When working with a Rails API and a separated client-side application you will want to handle omniauth authentication differently from a fullstack Rails application.

Usually the flow is as followed:
1. The client (web browser or ios device for example) authenticate the user directly via AppleJS' API or the native IOS API. During this process a popup might appear prompting the user for their credentials or the user might be redirected to a Apple sign in page.
2. On successful authentication Apple returns a one-time use authorization `code` as well as a identification `id_token`.
3. Using an HTTP request those params are POSTed to the Rails API's apple omniauth callback route, usually that would be `https://your.api.domain/users/auth/apple/callback`.
4. The `omniauth-apple` gem will validate the token and code via a server-side request to Apple. If both are valid then Apple will return a `access_token` which can be used to find an existing user or create a new one if this is the first time such process is run for that user.
5. Your Rails server can then respond to the client's HTTP request with the user's data.

The `omniauth-apple` gem supports this mode if you provide an additional configuration option.
```ruby
Rails.application.config.middleware.use OmniAuth::Builder do
  provider :apple, ENV['APPLE_CLIENT_ID'], '', {
    key_id: ENV['APPLE_KEY_ID'],
    pem: ENV['APPLE_PRIVATE_KEY'],
    scope: 'email name',
    team_id: ENV['APPLE_TEAM_ID'],

    # Add this to your existing configuration
    provider_ignores_state: true,
  }
end
```

Make sure that the `ENV['APPLE_CLIENT_ID']` you use in your configuration is the same as the one used in your client-side application.

#### Multi-platform client-side applications
If you use your Rails API with multiple different client-side applications on different platforms (for example you might have a web app and a IOS app) then you might have to use different `APPLE_CLIENT_ID` for these apps.

When this is the case you can register additional client ids for your middleware by using the `authorized_client_ids` option.
```ruby
Rails.application.config.middleware.use OmniAuth::Builder do
  provider :apple, ENV['APPLE_CLIENT_ID'], '', {
    key_id: ENV['APPLE_KEY_ID'],
    pem: ENV['APPLE_PRIVATE_KEY'],
    scope: 'email name',
    provider_ignores_state: true,
    team_id: ENV['APPLE_TEAM_ID'],

    # Add this to your existing configuration
    authorized_client_ids: [ENV['OTHER_APPLE_CLIENT_ID']]
  }
end
```

#### AppleJS example
*Example inspired from https://developer.apple.com/documentation/sign_in_with_apple/configuring-your-webpage-for-sign-in-with-apple*

Include Apple's CDN in your html by adding this script tag at the end of your `<body>`
```html
<script type="text/javascript" src="https://appleid.cdn-apple.com/appleauth/static/jsapi/appleid/1/en_US/appleid.auth.js"></script>
```

Then in your application authenticate the user with the following method
```js
const handleAppleSignIn = async () => {
  AppleID.auth.init({
    clientID: '<APPLE_CLIENT_ID>' // In web application this will be a Apple Service ID, not your App's Bundle ID
    redirectURI: '<YOUR_REDIRECT_URI>' // In popup mode this won't do anything but still needs to be present. You can use the current page's URL
    scope: 'email name',
    state: 'apple' // Use this if your `redirectURI` handle multiple different omniauth providers. When redirecting to that page the `state` will be included in the query params and will help you identity which provider is redirecting to your application.
    usePopup: true
  })

  try {
    const { authorization: { code, id_token, state } } = await AppleID.auth.signIn()

    // The same `redirect_uri` needs to be sent to your API you will end up with a redirect_uri_mismatch error.
    const params = new URLSearchParams({ code, id_token, redirect_uri: '<YOUR_REDIRECT_URI>' })

    // `omniauth-apple` does not support sending data in the request's body so your params need to be appended to the URL.
    const apiURL = `https://your.api.domain/users/auth/apple/callback?${params.toString()}`

    const user = await fetch(url, {
      headers: { 'Content-type': 'application/json' },
      method: 'POST'
    })
  } catch (error) {
    // handle error: { error: string }
  }
}
```

#### IOS Example
*See: https://developer.apple.com/documentation/AuthenticationServices/implementing-user-authentication-with-sign-in-with-apple*

Note that for IOS devices the `APPLE_CLIENT_ID` you need to use is your app's Bundle ID, not a Service ID.

## Configuration
In order to configure `omniauth-apple` properly you will need to have an active Apple App.
If that is not the case then start by logging into your [Apple Developer Account](https://idmsa.apple.com/IDMSWebAuth/signin?appIdKey=891bd3417a7776362562d2197f89480a8547b108fd934911bcbea0110d07f757&path=%2Faccount%2F&rv=1) (if you don't have one, you can [create one here](https://appleid.apple.com/account?appId=632&returnUrl=https%3A%2F%2Fdeveloper.apple.com%2Faccount%2F)).

Then you can create an App ID by going to your [Identifiers](https://developer.apple.com/account/resources/identifiers/list), click on the [+](https://developer.apple.com/account/resources/identifiers/add/bundleId) button, select **App IDs** and **continue**, select **App** and **continue**, enter a **description** and a **Bundle ID**, scroll down and check the **Sign in with Apple** capability then save your App.


### CLIENT_ID
The `CLIENT_ID` will depend on the platform you make your authentication request from.

|Platform|Description|
|--|--|
|IOS|The `CLIENT_ID` for requests made from a IOS native device is your Apple App's Bundle ID.<br><br>To find your App's Bundle ID access your [Identifiers](https://developer.apple.com/account/resources/identifiers/list) and select your **App ID**. You will find your **Bundle ID** in the App ID's configuration which should look something like `domain.custom.your`|
|Web|The `CLIENT_ID` for requests made from a web browser or server is a Apple **Service ID**'s' **Identifier**.<br><br>To create a Service ID go to your [Identifiers](https://developer.apple.com/account/resources/identifiers/list), click on the [+](https://developer.apple.com/account/resources/identifiers/add/bundleId) button, select **Service IDs** and **continue**, enter a **description** and a **Identifier** (for example `domain.custom.your.signin`) and **continue**, enable **Sign in with Apple** then configure it by providing your **Primary App ID** (that will usually the **App ID** you already created) as well as the **domain** and **redirect_uri** used when you make the authorization request.<br>Finally save your Service ID and copy the **Identifier**|

### CLIENT_SECRET
`omniauth-apple` does not use a `CLIENT_SECRET`. You can leave this option as `''`

### Options

|Key|Description|Required|
|---|-----------|--|
|authorized_client_ids|A list of authorized client_ids in addition to your `APPLE_CLIENT_ID`|false|
|key_id|The **Key ID** of a encryption key you generated.<br><br>To create a new encryption key access your [Keys](https://developer.apple.com/account/resources/authkeys/list), click on the [+](https://developer.apple.com/account/resources/authkeys/add) button, enter a **Key Name** and a **Key Usage Description**, enable **Sign Iin with Apple** and configure it with your **Primary App ID** (that will usually the **App ID** you already created) then save the Key.<br><br>The **Key ID** will be found in your Key Details|true|
|pem|The encryption key of the **Key ID** you generated.<br><br>Once your **Key ID** has been created you can **Download** the key and open the file in your IDE. The `pem` is the content of that file **with an extra newline at the end**<br><br>**DO NOT COMMIT THIS ENCRYPTION KEY**|true|
|provider_ignores_state|Necessary when skipping to the callback phase directly (which is the case for hybrid configuration)|Only with <a href="#use-with-hybrid-application">Hybrid Applications</a>|
|scope|The amount of user information requested from Apple.|true|
|team_id|The **App ID Prefix** of the **App ID** you created earlier.<br><br>Access your [Identifiers](https://developer.apple.com/account/resources/identifiers/list), select your **App ID** then copy the **App ID Prefix** found in the App ID's Configuration|true|

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/nhosoya/omniauth-apple.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
