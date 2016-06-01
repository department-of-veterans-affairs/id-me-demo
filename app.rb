require 'sinatra'
require 'json'
require 'ruby-saml'

enable :sessions
set :session_secret, 'secret!'

SAML_SETTINGS = OneLogin::RubySaml::Settings.new
SAML_SETTINGS.idp_sso_target_url             = "https://app.onelogin.com/trust/saml2/http-post/sso/362804"
SAML_SETTINGS.idp_cert_fingerprint           = "D4:A1:E4:25:AE:E1:0E:03:46:C5:42:3D:4C:56:BA:A3:A6:CB:AB:9E"
SAML_SETTINGS.name_identifier_format         = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
SAML_SETTINGS.idp_slo_target_url             = "https://app.onelogin.com/trust/saml2/http-redirect/slo/362804"

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
    profile = {first_name: "Joe", last_name: "User", city: "Springfield", state: "OR", phone_number: "1234567890"}
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
post '/auth/saml/callback' do
  saml_response = OneLogin::RubySaml::Response.new(params[:SAMLResponse])
  saml_response.settings = SAML_SETTINGS
  if saml_response.is_valid?
    session[:user] = { name: saml_response.name_id }
  end
  redirect to('/')
end