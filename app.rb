#!/usr/bin/env ruby

# dev hint: shotgun login.rb

require 'rubygems'
require 'sinatra'
require 'oauth2'
require 'net/https'
require 'uri'
require 'json'
require 'ims/lti'
require 'oauth/request_proxy/rack_request'
require 'openssl'
require 'coffee-script'

# Canvas OAuth Application Client ID 
OAUTH_CLIENT_ID = 1234

# Canvas OAuth Client Secret
OAUTH_CLIENT_SECRET = 'secret here'

# A secret key that this app will use to generate another secret
# key for an account based on the consumer key. Make sure this is long
# and random and you keep it secret and stuff.
APP_SECRET = nil
if APP_SECRET.nil?
  raise "You need to choose an APP_SECRET!" +
    "May I suggest: #{(0...40).map { (65 + rand(25)).chr }.join}"
end

# Provide the name of your LTI tool here... You can include a port if
# you need to.
TOOL_DOMAIN = "ltitool.example.com"

# Set to true if your tool needs SSL
TOOL_SSL = false

# Set to true if you want to hit Canvas with SSL (you probably do)
CANVAS_SSL = true


configure do
  set :public_folder, Proc.new { File.join(root, "static") }
  # This is necessary in order for the LTI tool to work within a Canvas
  # iframe.
  set :protection, :except => :frame_options
  enable :sessions
end

helpers do
  def oauth_client
    domain = session[:canvas_domain]
    OAuth2::Client.new(OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET,
      :site => domain,
      :authorize_url => "http://#{domain}/login/oauth2/auth",
      :token_url => "http://#{domain}/login/oauth2/token")
  end

  def secret_for_consumer_key(key)
    OpenSSL::HMAC.hexdigest(
      OpenSSL::Digest::Digest.new('sha1'), APP_SECRET, key)
  end

  def warning_alert(string)
    "<div class='alert'>#{string}</div>"
  end

  def fail_alert(string)
    "<div class='alert alert-error'>#{string}</div>"
  end
end

get '/' do
  erb :index
end

post '/login' do
  session[:canvas_domain] = params[:canvas_domain]

  redirect to oauth_client.auth_code.authorize_url(
    :redirect_uri => "http#{"s" if TOOL_SSL}://#{TOOL_DOMAIN}/oauth_callback")
end

get '/oauth_callback' do
  token = oauth_client.auth_code.get_token(params[:code],
    :redirect_uri => "http#{"s" if TOOL_SSL}://#{TOOL_DOMAIN}/oauth_callback")

  session[:canvas_token] = token.token
  redirect to '/setup'
end

get '/setup' do
  erb :setup
end

post '/setup_tool' do
  http = Net::HTTP.new(session[:canvas_domain], CANVAS_SSL ? 443 : 80)
  http.use_ssl = CANVAS_SSL

  # Verify that tool doesn't exist
  request = Net::HTTP::Get.new("/api/v1/accounts/self/external_tools")
  request["Authorization"] = "Bearer #{session[:canvas_token]}"
  response = http.request(request)
  if response.code == 401
    halt erb fail_alert("Could not fetch list of LTI tools - are you an admin?")
  end

  tools = JSON.parse(response.body)
  if tools.select {|tool| tool["domain"] == TOOL_DOMAIN }.length > 0
    halt erb fail_alert("Tool is already configured.")
  end

  # Create tool

  # We're going to go an easy way and create a random consumer key to identify
  # this authentication to the LTI tool. In this case, we're putting the
  # canvas domain in the consumer key in case we want to know what domain the
  # user originally authenticated to when they return via the LTI entrance point.

  # A more robust method would be to create a random consumer key, and store
  # metadata about it in a database or something.
  consumer_key = "#{session[:canvas_domain]}:#{(0...20).map { (65 + rand(25)).chr }.join}"

  # Because we're not using a database to persist a secret, we'll create one
  # based on the consumer_key and our APP_SECRET using HMAC. This means we
  # don't need to store any state but we can authenticate future requests.

  # Again, a more robust method would be to create a random secret and store
  # it somewhere safe.
  consumer_secret = secret_for_consumer_key(consumer_key)

  request = Net::HTTP::Post.new("/api/v1/accounts/self/external_tools")
  request["Authorization"] = "Bearer #{session[:canvas_token]}"
  request.set_form_data({
    "name" => "LTI Tool",
    "privacy_level" => "public",
    "consumer_key" => consumer_key,
    "shared_secret" => consumer_secret,
    "description" => "A magical self-configuring LTI Tool for Canvas.",
    "account_navigation[url]" => "http#{"s" if TOOL_SSL}://#{TOOL_DOMAIN}/enter",
    "account_navigation[text]" => "LTI Tool",
    "domain" => TOOL_DOMAIN
    })
  response = http.request(request)
  if !response.kind_of?(Net::HTTPSuccess)
    halt erb fail_tool("Error creating tool in Canvas.")
  end

  erb :setup_done
end

# LTI Tool entry point
post '/enter' do
  provider = IMS::LTI::ToolProvider.new(
    params[:oauth_consumer_key],
    secret_for_consumer_key(params[:oauth_consumer_key]),
    params)

  if !provider.valid_request?(request)
    halt erb fail_alert("Invalid request.")
  end

  # Admin check. You can take this out, or check for another role, or whatever
  roles = params[:roles].split ',' 
  if !roles.include?('urn:lti:instrole:ims/lis/Administrator')
    halt erb fail_alert("You are not an administrator.")
  end

  # Do your magic LTI stuff here!
  erb :entry
end
