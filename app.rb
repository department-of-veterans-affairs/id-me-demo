require 'sinatra'
require 'json'
require 'ruby-saml'

enable :sessions
set :session_secret, 'secret!'
set :server, 'thin'

SAML_SETTINGS = OneLogin::RubySaml::Settings.new
SAML_SETTINGS.assertion_consumer_service_url = "http://localhost:4567/auth/saml/callback"
SAML_SETTINGS.certificate                    = File.read('certs/greg-localhost.crt')
SAML_SETTINGS.private_key                    = File.read('certs/greg-localhost.key')
SAML_SETTINGS.authn_context                  = "authentication"

# Use the .us for the "production" version; use .localhost for running locally with ID.me
#SAML_SETTINGS.issuer                         = "saml-rp.adhocteam.us"
SAML_SETTINGS.issuer                         = "saml-rp.adhocteam.localhost"


parser = OneLogin::RubySaml::IdpMetadataParser.new
parser.parse_remote("https://api.idmelabs.com/saml/metadata", true, {settings: SAML_SETTINGS})

puts SAML_SETTINGS.inspect

before '/api/*' do
  content_type 'application/json'
end

get '/' do
  redirect to('/index.html')
end

# API call to return information related to the current session.
get '/api/session' do
  if session["user"]
    user_hash = {"user": session["user"]}
    user_json = user_hash.to_json
    [200, user_json]
  else
    404
  end
end

get '/api/profile' do
  if session['user']
    attributes = session['user'][:attributes]
    profile = {first_name: attributes['fname'], last_name: attributes['lname'], zip: attributes['zip'], email: attributes['email'], uid: attributes['uuid']}
    [200, {profile: profile}.to_json]
  else
    401
  end
end

# API call to destroy the current session
delete '/api/session' do
  session.clear if session
  [200, {}.to_json]
end

# Link to redirect the user to our identity provider. This would generate a SAML Authentication Request and then redirect the user to it, which would transfer control to the Identity Provider (or Broker).
get '/sign_in' do
  saml_auth_request = OneLogin::RubySaml::Authrequest.new
  redirect to(saml_auth_request.create(SAML_SETTINGS))
end

# Callback that is called by identity provider with SAML assertion containing the user information; would normally be a post with the assertion. Here, we're just establishing a session as a random user.
get '/auth/saml/callback' do
  saml_response = OneLogin::RubySaml::Response.new(params[:SAMLResponse], settings: SAML_SETTINGS)
  if saml_response.is_valid?(true)
    session[:user] = { name: saml_response.name_id, attributes: saml_response.attributes.all.to_h }
  else
    puts "INVALID REPSONSE"
    puts saml_response.errors.inspect
  end
  redirect to('/')
end