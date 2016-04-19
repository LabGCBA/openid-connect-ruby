# openid-connect-ruby

A literal, not so idiomatic ruby port of Michael Jett's excellent [OpenID Connect](https://github.com/jumbojett/OpenID-Connect-PHP) library for PHP.

## Requirements
- Curb

## Usage
See `example.rb`
```
oidc = OpenIDConnectClient::Client.new('https://provider.com/openid', 'CLIENT_ID', 'SECRET')
oidc.redirect_url = "http://yourweb.com/callback"
oidc.scopes = "openid email profile address phone"

oidc.authorize()
        
session[:state] = oidc.state
redirect_to(oidc.auth_endpoint)
```

### On the callback
```
oidc = OpenIDConnectClient::Client.new('https://provider.com/openid', 'CLIENT_ID', 'SECRET')
oidc.redirect_url = "http://yourweb.com/callback"
oidc.scopes = "openid email profile address phone"

oidc.authenticate()
        
email = oidc.get('email')
given_name = oidc.get('given_name')
address = oidc.get('address')
```