# frozen_string_literal: true

require "oauth2"

# A Client is configured once with its credentials and site; the authorize and
# token endpoints default to the gem's /oauth/authorize and /oauth/token paths.
client = OAuth2::Client.new("client-id", "s3cr3t", site: "https://example.com")
puts client.authorize_url # => https://example.com/oauth/authorize

# The auth_code grant builds a redirect URL; keys are sorted and every value is
# percent-encoded (space -> %20), byte-faithful to the gem.
puts client.auth_code.authorize_url(redirect_uri: "https://app/cb", scope: "read write", state: "xyz")

# get_token builds the token Request the host round-trips; here is its POST body.
req = client.auth_code.get_token("the-code", redirect_uri: "https://app/cb")
puts "#{req.method} #{req.url}"
puts req.body # => code=the-code&grant_type=authorization_code&redirect_uri=...

# Other grants build their own request bodies.
puts client.client_credentials.get_token.body     # => grant_type=client_credentials
puts client.password.get_token("bob", "pw").body  # => grant_type=password&password=pw&username=bob

# Parse a token endpoint Response (as returned by the host) into an AccessToken.
resp = OAuth2::Response.new(200, { "Content-Type" => "application/json" },
                            '{"access_token":"tok","refresh_token":"r","token_type":"bearer"}')
token = client.get_token(resp)
puts "#{token.token} (#{token.token_type})" # => tok (bearer)
puts token.refresh.body                      # => grant_type=refresh_token&refresh_token=r

# PKCE code_challenge for the S256 method (RFC 7636).
puts OAuth2::PKCE.code_challenge("verifier", :S256)

# An error token response raises OAuth2::Error.
begin
  client.get_token(OAuth2::Response.new(400, { "Content-Type" => "application/json" },
                                        '{"error":"invalid_grant"}'))
rescue OAuth2::Error => e
  puts "rejected: #{e.class}"
end
