# openid-connect-ruby

This is a literal, not so idiomatic ruby port of Michael Jett's excellent [OpenID Connect](https://github.com/jumbojett/OpenID-Connect-PHP) library for PHP.

## Requirements
- [curb](https://github.com/taf2/curb)

## Installation
```
gem install openid_connect_client
```

## Usage
It's done in two steps: first, in your login controller you'll request authorization and redirect the user to the OpenID Connect provider. If your app gets authorized, then the provider will redirect the user back to your callback url where you'll be able to ask the provider for the user data.

See `example.rb`

### In the login controller
```ruby
# 1. Client setup
oidc = OpenIDConnectClient::Client.new('https://provider.com/openid', 'CLIENT_ID', 'SECRET')
oidc.redirect_url = "http://yourweb.com/callback"
oidc.scopes = "openid email profile address"

# 2. Request authorization
oidc.authorize()

# 3. Save state in session
session[:state] = oidc.state

# 4. Redirect user to OpenID Connect provider
redirect_to(oidc.auth_endpoint)
```

### In the callback controller
```ruby
# 1. Get client
oidc = OpenIDConnectClient::Client.new('https://provider.com/openid', 'CLIENT_ID', 'SECRET')

# 2. Restore state
oidc.state = session[:state]

# 3. Pass the authorization parameters sent by the provider
oidc.params = request.parameters

# 4. Authenticate your app against the provider
oidc.authenticate()

# 5. Fetch the user's details
given_name = oidc.get('given_name')
email = oidc.get('email')
address = oidc.get('address')
```