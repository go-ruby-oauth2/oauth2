# Examples

Runnable pure-Ruby usage of the `OAuth2` client, verified under the [rbgo](https://github.com/go-embedded-ruby) interpreter.

```sh
rbgo examples/oauth2_usage.rb
```

| File | Shows |
| --- | --- |
| `oauth2_usage.rb` | `OAuth2::Client.new` with `site:`, `authorize_url`/`token_url` defaults, `auth_code.authorize_url` (sorted, percent-encoded params), `get_token` request building for the auth_code / client_credentials / password grants, parsing an `OAuth2::Response` into an `AccessToken` and building its `refresh` request, `OAuth2::PKCE.code_challenge` (S256), and an error response raising `OAuth2::Error` |
