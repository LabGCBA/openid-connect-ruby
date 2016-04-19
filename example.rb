require 'nyny'
require 'erb'
require 'openid_connect_client'

TEMPLATE = DATA.read.freeze
  
class App < NYNY::App  
    use Rack::Session::Cookie, :secret => 'your_secret'
    
    get '/' do
        oidc = get_client()
        oidc.authorize()
        
        session[:state] = oidc.state
        redirect_to(oidc.auth_endpoint)
    end
    
    get '/callback' do
        oidc = get_client(params)
        oidc.authenticate()
        
        email = oidc.get('email')
        given_name = oidc.get('given_name')
        address = oidc.get('address')
        
        ERB.new(TEMPLATE).result(binding)
    end
    
    helpers do
        def get_client(params = nil)
            oidc = OpenIDConnectClient::Client.new('PROVIDER_ENDPOINT', 'CLIENT_ID', 'SECRET')
            oidc.redirect_url = 'http://localhost:9292/callback'
            oidc.scopes = 'openid email profile address phone'
            
            oidc.state = session[:state]
            oidc.params = params if params
            
            oidc
        end
    end
end

App.run!

__END__
<html>
<head>
    <title>OpenID Connect Client Example</title>
    <style>
        body {
            font-family: Helvetica, Arial, sans-serif;
        }
    </style>
</head>
<body>
    <div>
        Hi <%= given_name %><br>
        Your email is <%= email %><br>
        Your address is <%= address[:street_address] %><br>
        Your postal code is <%= address[:postal_code] %>
    </div>
</body>
</html>