# Srp

[![Hex.pm](https://img.shields.io/hexpm/v/srp.svg)](https://hex.pm/packages/srp)
[![Docs](https://img.shields.io/badge/hex-docs-green.svg)](https://hexdocs.pm/srp)
[![Build Status](https://travis-ci.com/thiamsantos/srp-elixir.svg?branch=master)](https://travis-ci.com/thiamsantos/srp-elixir)
[![Coverage Status](https://coveralls.io/repos/github/thiamsantos/srp-elixir/badge.svg?branch=master)](https://coveralls.io/github/thiamsantos/srp-elixir?branch=master)

> Secure Remote Password Protocol implementation in elixir.

SRP provides an implementation of the Secure Remote Password Protocol presented on
[The SRP Authentication and Key Exchange System](https://tools.ietf.org/html/rfc2945),
[Using the Secure Remote Password (SRP) Protocol for TLS Authentication](https://tools.ietf.org/html/rfc5054)
and [The Secure Remote Password Protocol](http://srp.stanford.edu/ndss.html).

The protocol provides a way to do zero-knowledge authentication between client and servers.
By using the SRP protocol you can:
- authenticate without ever sending a password over the network.
- authenticate without the risk of anyone learning any of your secrets – even
  if they intercept your communication.
- authenticate both the identity of the client and the server to guarantee
  that a client isn’t communicating with an impostor server.

## Installation

The package can be installed by adding `srp` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:srp, "~> 0.1.0"}
  ]
end
```

## Usage

Checkout the full [documentation](https://hexdocs.pm/srp) for a complete usage.

### Signing up

After the user provides his username and password, the client must generate
a password verifier. Then it must send to the server:

- The username for future identification.
- The password verifier that will be used in the future to verify the client credentials.
- The salt used in the process.

```elixir
username = "alice"
password = "password123"

identity = SRP.Identity.new(username, password)
%SRP.IdentityVerifier{username: username, salt: salt, password_verifier: password_verifier} =
  SRP.generate_verifier(identity)

# Send to the server -> username + salt + password_verifier
# Server stores the information
```

### Logging in

Authenticating a user on the server involves multiple steps.

1. The client sends to the server the username.
2. The server finds the password verifier and salt for that username.
Then it generates a ephemeral key pair and sends back to the client the salt and the public key.

```elixir
# Find the record for the given username
# Load from the database the password_verifier, and the salt
key_pair = SRP.server_key_pair(password_verifier)

# Send back to the client -> key_pair.public + salt
```

If the username does not exist the server can send a fake value.
It is important to not reveal if an username is registered on the system or not.
An attacker could use the login to find the registered usernames
and try a dictionary attack specify for those users.

3. The client generates a key pair and a client proof of identity.
Then the client sends to the server the proof and the client's public key.

```elixir
# receives from the server the server_public_key and the salt.

identity = SRP.Identity.new(username, password)
key_pair = SRP.client_key_pair()
proof = SRP.client_proof(identity, salt, key_pair, server_public_key)

# Send to the server -> proof + server_public_key
```

4. Server verify client proof then build its own proof of identity.
Then sends back the server's proof.

```elixir
valid? = SRP.valid_client_proof?(client_proof, password_verifier, server_key_wpair, client_public_key)

if valid? do
  # Send back to client the server's proof -> server_proof
else
  # Send back unauthorized
end
```

5. The client receives the server's proof and validates it.
This step can be skipped if you don't feel the need to verify the server's identity.

```elixir
identity = SRP.Identity.new(username, password)
valid? = SRP.valid_server_proof?(server_proof, identity, salt, client_key_pair, server_public_key)
```

From now on is to safe to create a new session between the client and server.

## License

[Apache License, Version 2.0](LICENSE.md) © [Thiago Santos](https://github.com/thiamsantos)
