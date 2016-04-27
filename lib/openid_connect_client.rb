module OpenIDConnectClient
  class OpenIDConnectClientException < Exception  
  end

  class Client
      require 'securerandom'
      require 'digest/md5'
      require 'cgi'
      require 'base64'
      require 'openssl'
      require 'curb'
      

      private #==============================================================================================================================
          
          #
          # Gets anything that we need configuration wise including endpoints, and other values
          #
          # @return void
          # @throws OpenIDConnectClientException
          #
          def get_provider_config()
            
              well_known_config_response = fetch_url(@well_known_config_url).body_str
              
              unless well_known_config_response
                  raise OpenIDConnectClientException, "Unable to get provider configuration data. Make sure your provider has a well known configuration available."
              end
              
              values = JSON[well_known_config_response]
              
              values.each do |key, value|
                  @state[key.to_sym] = value
              end
          end

          # 
          # @param param
          # @throws OpenIDConnectClientException
          # @return string
          #
          def get_provider_config_value(param)
              # If the configuration value is not available, attempt to fetch it from a well known config endpoint
              # This is also known as auto "discovery"          
              if @state[param].nil?
                  well_known_config_response = fetch_url(@well_known_config_url).body_str
                  
                  unless well_known_config_response
                      raise OpenIDConnectClientException, "Unable to get provider configuration data. Make sure your provider has a well known configuration available."
                  end
                  
                  value = JSON[well_known_config_response][param.to_s] 
                  
                  unless value
                      raise OpenIDConnectClientException, "The provider #{param} has not been set. Make sure your provider has a well known configuration available."
                  end
                  
                  @state[param] = value
              end
              
              @state[param]
          end
          
          #
          # @param array keys
          # @param array header
          # @throws OpenIDConnectClientException
          # @return object
          #
          def get_key_for_header(keys, header)
              keys.each do |key|
                  if !(key["alg"] and header["kid"]) and key["kty"] == 'RSA' or (key["alg"] == header["alg"] and key["kid"] == header["kid"])
                      return key
                  end
              end
              
              if header["kid"]
                  raise OpenIDConnectClientException, "Unable to find a key for (algorithm, kid): #{header["alg"]}, #{header["kid"]}."
              else
                  raise OpenIDConnectClientException, "Unable to find a key for RSA."
              end
          end
          
          #
          # @param jwt string encoded JWT
          # @throws OpenIDConnectClientException
          # @return bool
          #
          def verify_JWT_signature(jwt)
              parts = jwt.split(".")
              signature = decode_64(parts.pop())
              
              decoded_header = decode_64(parts[0])
              header = JSON[decoded_header]
              
              payload = parts.join(".")
              
              fetched_jwks = fetch_url(get_provider_config_value(:jwks_uri)).body_str
              jwks = JSON[fetched_jwks]
              
              unless not jwks.nil?
                  raise OpenIDConnectClientException, "Error decoding JSON from jwks_uri."
              end
              
              verified = false
              
              case header["alg"]
                  when 'RS256', 'RS384', 'RS512'
                      hashtype = "sha" + header["alg"][0,2]
                      verified = verify_RSA_JWT_signature(hashtype, get_key_for_header(jwks["keys"], header), payload, signature)
              else
                  raise OpenIDConnectClientException, "No support for signature type: #{header["alg"]}."
              end
              
              verified
          end
          
          #
          # @param string hashtype
          # @param object key
          # @throws OpenIDConnectClientException
          #
          def verify_RSA_JWT_signature(hashtype, key, payload, signature)
              unless key["n"] and key["e"]
                  raise OpenIDConnectClientException, "Malformed key object."
              end
                          
            digest = case hashtype
                when 'md2' then OpenSSL::Digest::MD2.new
                when 'md5' then OpenSSL::Digest::MD5.new
                when 'sha1' then OpenSSL::Digest::SHA1.new
                when 'sha256' then OpenSSL::Digest::SHA256.new
                when 'sha384' then OpenSSL::Digest::SHA384.new
                when 'sha512' then OpenSSL::Digest::SHA512.new
                else OpenSSL::Digest::SHA256.new
            end
            
            key = get_rsa_key(url_safe_base64(key["n"]), url_safe_base64(key["e"]))
            key.public_key.verify(digest, signature, payload)
          end
          
          #
          # @param object claims
          # @return bool
          #
          def verify_JWT_claims(claims)
              if claims["nonce"]
                  return (claims["iss"] == @provider_url and ((claims["aud"] == @client_id) or (claims["aud"].include? @client_id)) and (claims["nonce"] == @state["openid_connect_nonce"]))
              else
                  return (claims["iss"] == @provider_url and ((claims["aud"] == @client_id) or (claims["aud"].include? @client_id)))
              end
          end
          
          #
          # @param jwt string encoded JWT
          # @param int section the section we would like to decode
          # @return object
          #
          def decode_JWT(jwt, section = 0)
              parts = jwt.split(".")
              url_decoded = decode_64(parts[section])
              
              JSON[url_decoded]
          end
          

          # Utility methods ==================================================================================================================
          
          #
          # @param string json
          # @return bool
          #
          def is_valid_url?(url)
              begin
                  URI.parse(url)
                  return url
              rescue URI::InvalidURIError
                  return false
              end
          end
          
          #
          # @param string json
          # @return bool
          #
          def is_json?(json)
              begin
                  JSON.parse(json)
                  return true
              rescue JSON::ParserError => e
                  return false
              end
          end
          
          #
          # @param object object
          # @return string
          #
          def http_build_query(object)
            h = hashify(object)
            result = ""
            separator = '&'
            h.keys.sort.each do |key|
                result << (CGI.escape(key) + '=' + CGI.escape(h[key]) + separator)
            end
            
            result = result.sub(/#{separator}$/, '') # Remove the trailing k-v separator
            return result
          end
          
          #
          # @param object object
          # @param string parent_key
          #
          def hashify(object, parent_key = '')
            unless object.is_a?(Hash) or object.is_a?(Array) or parent_key.length > 0
                raise ArgumentError.new('This is made for serializing Hashes and Arrays only.') 
            end

            result = {}
            
            case object
                when String, Symbol, Numeric
                      result[parent_key] = object.to_s
                when Hash
                      # Recursively call hashify, building closure-like state by
                      # appending the current location in the tree as new "parent_key"
                      # values.
                      hashes = object.map do |key, value|
                          if parent_key =~ /^[0-9]+/ or parent_key.length == 0
                              new_parent_key = key.to_s
                          else
                              new_parent_key = parent_key + '[' + key.to_s + ']'
                          end
                          
                          hashify(value, new_parent_key)
                      end
                      
                      hash = hashes.reduce { |memo, hash| memo.merge hash }
                      result.merge! hash
                when Enumerable
                      # _Very_ similar to above, but iterating with "each_with_index"
                      hashes = {}
                      object.each_with_index do |value, index|
                          
                          if parent_key.length == 0
                              new_parent_key = index.to_s
                          else
                              new_parent_key = parent_key + '[' + index.to_s + ']'
                          end
                          
                          hashes.merge! hashify(value, new_parent_key)
                      end
                      
                      result.merge! hashes
                  else
                      raise Exception.new("This should only be serializing Strings, Symbols, or Numerics.")
            end

              return result
          end
          
          #
          # @param string str
          # @return string
          #
          def decode_64(str)
              Base64.decode64(url_safe_base64(str))
          end
          
          # 
          # Per RFC4648, "base64 encoding with URL-safe and filename-safe alphabet".  This just replaces characters 62 and 63. 
          # None of the reference implementations seem to restore the padding if necessary, but we'll do it anyway.
          # 
          # @param string str
          # @return string
          #
          def url_safe_base64(str)
              # add '=' padding
              str = case str.length % 4
                  when 2 then str + '=='
                  when 3 then str + '='
                  else str
              end
              
              str.tr('-_', '+/')
          end
          
          #
          # @param string xml_string
          # @return object
          #
          def get_rsa_key(modulus, exponent)
            #d = XML::Parser.string(xml_string).parse
            m = Base64.decode64(modulus).unpack('H*')
            e = Base64.decode64(exponent).unpack('H*')

            pub_key = OpenSSL::PKey::RSA.new
            
            #modules
            pub_key.n = OpenSSL::BN.new(m[0].hex.to_s)
            
            #exponent
            pub_key.e = OpenSSL::BN.new(e[0].hex.to_s)
            
            #return Public Key
            pub_key
          end 

          #
          # Used for arbitrary value generation for nonces and state
          #
          # @return string
          #
          def random_string()
              SecureRandom.urlsafe_base64
          end
          
          #
          # @param url
          # @param null post_body string If this is set the post type will be POST
          # @param array headers Extra headers to be send with the request. Format as 'NameHeader: ValueHeader'
          # @throws OpenIDConnectClientException
          # @return mixed
          #
          def fetch_url(url, post_body = nil, headers = Array.new)
              curb = Curl::Easy.new(url) do |curl| 
                  headers.each do |key, value|
                      curl.headers[key] = value
                  end
                  
                  if post_body          
                      if is_json?(post_body)
                          content_type = "application/json"
                      else
                          content_type = "application/x-www-form-urlencoded"
                      end
                      
                      curl.headers["Content-Type"] = content_type
                      curl.post_body = post_body
                      
                  else
                      curl.http(:GET)
                  end

                  curl.timeout = 60
                  curl.proxy_url = @proxy_url if self.instance_variable_defined? :@proxy_url
                  curl.verbose = true
                  
                  if self.instance_variable_defined? :@cert_path
                      curl.ssl_verify_peer = true
                      curl.ssl_verify_host = true
                      curl.cert = @cert_path
                  else
                      curl.ssl_verify_peer = false
                  end
              end
              
              curb.post_body = post_body if post_body
              result = curb.perform
                              
              if result
                  return curb
              else
                  return false
              end
          end
          
      
      public #==============================================================================================================================
      
          attr_reader :access_token, :refresh_token, :auth_endpoint
          attr_writer :http_proxy, :cert_path, :params
          attr_accessor :client_name, :client_id, :client_secret, :well_known_config_url, :state, :provider_config
          
          #
          # @param provider_url string optional
          # @param client_id string optional
          # @param client_secret string optional
          #
          def initialize(provider_url = nil, client_id = nil, client_secret = nil)
              @scopes = Hash.new
              @state = Hash.new
              @state = Hash.new
              @auth_params = Hash.new
              @user_info = Hash.new
              @params = Hash.new
              @response = Hash.new
              
              @client_id = client_id
              @client_secret = client_secret
              @provider_url = provider_url
              
              substitute = "/"
              
              if self.instance_variable_defined? :@provider_url
                  @well_known_config_url = provider_url.gsub(/[#{substitute}]+$/, '') + "/.well-known/openid-configuration/"
              end
          end
          
          # 
          # Builds the user authentication url.
          #
          # @return void
          # 
          def authorize()           
              get_provider_config()
              
              auth_endpoint = get_provider_config_value(:authorization_endpoint)
              response_type = "code"
              
              # Generate and store a nonce in the session
              # The nonce is an arbitrary value
              nonce = random_string()
              @state["openid_connect_nonce"] = nonce
              
              # State essentially acts as a session key for OIDC
              state = random_string()
              @state["openid_connect_state"] = state
              
              @auth_params = @auth_params.merge({
                  response_type: response_type,
                  redirect_uri: @redirect_url,
                  client_id: @client_id,
                  nonce: nonce,
                  state: state,
                  scope: 'openid'
              })
              
              # If the client has been registered with additional scopes
              if @scopes.length > 0
                  @auth_params[:scope] = @scopes.join(' ')
                  auth_endpoint += '?' + http_build_query(@auth_params)
                  @auth_endpoint = auth_endpoint
              end
          end
          
          # 
          # Gets the access token needed to request user info.
          #
          # @return bool
          # @throws OpenIDConnectClientException
          # 
          def authenticate()
              # Do a preemptive check to see if the provider has raised an error from a previous redirect
              unless @response[:error].nil?
                  raise OpenIDConnectClientException, "Error: #{@response[:error]} Description: #{@response[:error_description]}"
              end
              
              # If we have an authorization code then proceed to request a token
              if not @params["code"].nil? || @params["code"].empty?
                  code = @params["code"]
                  token_endpoint = get_provider_config_value(:token_endpoint)
                  grant_type = "authorization_code"
                  
                  tokemoduluss = {
                      grant_type: grant_type,
                      code: code,
                      redirect_uri: @redirect_url,
                      client_id: @client_id,
                      client_secret: @client_secret
                  }
                  
                  # Convert token params to string format
                  tokemoduluss = http_build_query(tokemoduluss)
                  
                  token_data = fetch_url(token_endpoint, tokemoduluss).body_str
                  
                  unless token_data
                      raise OpenIDConnectClientException, "Unable to get token data from the provider."
                  end
                  
                  token_json = JSON[token_data]
                  
                  # Throw an error if the server returns one
                  if token_json["error"]
                      raise OpenIDConnectClientException, token_json["error_description"]
                  end
                  
                  # Do an OpenID Connect session check
                  unless @params["state"] == @state["openid_connect_state"]
                      raise OpenIDConnectClientException, "Unable to determine state."
                  end
              
                  unless token_json["id_token"]
                      raise OpenIDConnectClientException, "User did not authorize openid scope."
                  end
                  
                  # Verify the signature
                  unless verify_JWT_signature(token_json["id_token"])
                      raise OpenIDConnectClientException, "Unable to verify signature."
                  end
                  
                  claims = decode_JWT(token_json["id_token"], 1)
                  
                  # If this is a valid claim
                  unless verify_JWT_claims(claims)
                      raise OpenIDConnectClientException, "Unable to verify JWT claims."
                  end
                  
                  # Save the access token
                  @access_token = token_json["access_token"]
                  
                  # Save the refresh token, if we got one
                  if token_json["refresh_token"]
                      @refresh_token = token_json["refresh_token"]
                  end
                  
                  # Success!
                  return true
              end
          end
          
          #
          # @param attribute
          #
          #
          # Attribute           Type          Description
          # user_id            string         REQUIRED Identifier for the End-User at the Issuer.
          # name               string         End-User's full name in displayable form including all name parts, ordered according to End-User's locale and preferences.
          # given_name         string         Given name or first name of the End-User.
          # family_name        string         Surname or last name of the End-User.
          # middle_name        string         Middle name of the End-User.
          # nickname           string         Casual name of the End-User that may or may not be the same as the given_name. For instance, a nickname value of Mike might be returned alongside a given_name value of Michael.
          # profile            string         URL of End-User's profile page.
          # picture            string         URL of the End-User's profile picture.
          # website            string         URL of End-User's web page or blog.
          # email              string         The End-User's preferred e-mail address.
          # verified           boolean        True if the End-User's e-mail address has been verified; otherwise false.
          # gender             string         The End-User's gender: Values defined by this specification are female and male. Other values MAY be used when neither of the defined values are applicable.
          # birthday           string         The End-User's birthday, represented as a date string in MM/DD/YYYY format. The year MAY be 0000, indicating that it is omitted.
          # zoneinfo           string         String from zoneinfo [zoneinfo] time zone database. For example, Europe/Paris or America/Los_Angeles.
          # locale             string         The End-User's locale, represented as a BCP47 [RFC5646] language tag. This is typically an ISO 639-1 Alpha-2 [ISO639‑1] language code in lowercase and an ISO 3166-1 Alpha-2 [ISO3166‑1] country code in uppercase, separated by a dash. For example, en-US or fr-CA. As a compatibility note, some implementations have used an underscore as the separator rather than a dash, for example, en_US; Implementations MAY choose to accept this locale syntax as well.
          # phone_number       string         The End-User's preferred telephone number. E.164 [E.164] is RECOMMENDED as the format of this Claim. For example, +1 (425) 555-1212 or +56 (2) 687 2400.
          # address            JSON object    The End-User's preferred address. The value of the address member is a JSON [RFC4627] structure containing some or all of the members defined in Section 2.4.2.1.
          # updated_time       string         Time the End-User's information was last updated, represented as a RFC 3339 [RFC3339] datetime. For example, 2011-01-03T23:58:42+0000.
          #
          # @return mixed
          # @throws OpenIDConnectClientException
          #
          def get(attribute)
              if @user_info.include? attribute
                  return @user_info["#{attribute}"]
              end
              
              user_info_endpoint = get_provider_config_value(:userinfo_endpoint)
              schema = "openid"
              user_info_endpoint += "?schema=#{schema}"
              headers = {"Authorization" => "Bearer #{@access_token}"}
              user_data = fetch_url(user_info_endpoint, nil, headers).body_str
              
              if user_data.nil? || user_data.empty?
                  raise OpenIDConnectClientException, "Unable to get #{attribute} from the provider."
              end
              
              user_json = JSON[user_data]
              @user_info = user_json
              
              if @user_info.include? attribute
                  return @user_info["#{attribute}"]
              end
              
              return nil
          end
          
          #
          # Dynamic registration
          # 
          # @return void
          # @throws OpenIDConnectClientException
          #
          def register()
              registration_endpoint = get_provider_config_value(:registration_endpoint)
              
              send_object = {
                  redirect_uris: [@redirect_url],
                  client_name: @client_name
              }
              
              @response = fetch_url(registration_endpoint, JSON[send_object])
              json_response = JSON[response]
              
              if not json_response
                  raise OpenIDConnectClientException, "Error registering: JSON response received from the server was invalid."
              elsif json_response[:error_description]
                  raise OpenIDConnectClientException, json_response[:error_description]
              end
              
              if json_response[:client_id]
                  @client_secret = json_response[:client_id]
              else
                  raise OpenIDConnectClientException, "Error registering: Please contact the OpenID Connect provider and obtain a Client ID and Secret directly from them."
              end
          end
          
          
          # Getters/Setters ==================================================================================================================
          
          #
          # @param hash hash
          # @return hash
          #
          def add_auth_param(hash)
              @auth_params = @auth_params.merge(hash)
          end
          
          #
          # @param hash hash
          # @return hash
          #
          def add_provider_config_param(hash)
              @state = @state.merge(hash)
          end
          
          #
          # @param scopes - example: openid, given_name, etc...
          #
          def scopes=(scopes)         
              @scopes = scopes.split(' ') if scopes
          end
          
          #
          # @param hash state
          # @return hash
          #
          def state=(state)
              @state = @state.merge(state) if state
          end
          
          #
          # @return string
          # @throws OpenIDConnectClientException
          #
          def provider_url()
              # If the provider URL has been set then return it.
              unless self.instance_variable_defined? :@provider_url
                  raise OpenIDConnectClientException, "The provider URL has not been set."
              end

              @provider_url
          end
          
          #
          # @param provider_url
          # @return string
          # @throws OpenIDConnectClientException
          #
          def provider_url=(url)
              unless is_valid_url?(url)
                  raise OpenIDConnectClientException, "Invalid URL."
              end

              @state[:issuer] = url
          end
          
          #
          # Gets the URL of the current page we are on, encodes, and returns it
          #
          # @return string
          # @throws OpenIDConnectClientException
          #
          def redirect_url()
              # If the redirect URL has been set then return it.
              unless self.instance_variable_defined? :@redirect_url
                  raise OpenIDConnectClientException, "The redirect URL has not been set."
              end

              @redirect_url
          end
          
          #
          # @param url Sets redirect URL for auth flow
          # @return string
          # @throws OpenIDConnectClientException
          #
          def redirect_url=(url)
              unless is_valid_url?(url)
                  raise OpenIDConnectClientException, "Invalid URL."
              end

              @redirect_url = url
          end
  end
end
