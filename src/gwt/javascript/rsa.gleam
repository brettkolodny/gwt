@target(javascript)
import gleam/bit_array
@target(javascript)
import gleam/javascript/promise.{type Promise}
@target(javascript)
import gleam/option
@target(javascript)
import gleam/result
@target(javascript)
import gwt

@target(javascript)
pub type Algorithm {
  RS256
  RS384
  RS512
}

@target(javascript)
pub type Public

@target(javascript)
pub type Private

@target(javascript)
type CryptoKey

@target(javascript)
pub opaque type Key(scope) {
  Key(crypto_key: CryptoKey, alg: Algorithm)
}

@target(javascript)
pub fn to_signed_string(
  jwt: gwt.JwtBuilder,
  key: Key(Private),
) -> Promise(String) {
  let alg_string = case key.alg {
    RS256 -> "RS256"
    RS384 -> "RS384"
    RS512 -> "RS512"
  }

  let header_string = gwt.get_header_string(jwt, alg_string)
  let payload_string = gwt.get_payload_string(jwt)
  let jwt_body = header_string <> "." <> payload_string

  use jwt_signature <- promise.await(
    jwt_body
    |> sign(key.crypto_key),
  )
  let encoded_signature = bit_array.base64_url_encode(jwt_signature, False)

  promise.resolve(jwt_body <> "." <> encoded_signature)
}

@target(javascript)
pub fn from_signed_string(
  jwt_string: String,
  key: Key(Public),
) -> Promise(Result(gwt.Jwt(gwt.Verified), gwt.JwtDecodeError)) {
  use #(encoded_header, encoded_payload, maybe_signature) <- promise.try_await(
    gwt.string_parts(jwt_string) |> promise.resolve(),
  )

  use header <- promise.try_await(
    gwt.part_to_dict(encoded_header, gwt.InvalidHeader)
    |> promise.resolve(),
  )
  use payload <- promise.try_await(
    gwt.part_to_dict(encoded_payload, gwt.InvalidPayload)
    |> promise.resolve(),
  )
  use signature <- promise.try_await(
    option.to_result(maybe_signature, gwt.MissingSignature)
    |> promise.resolve(),
  )

  use _ <- promise.try_await(
    gwt.ensure_valid_expiration(payload) |> promise.resolve,
  )
  use _ <- promise.try_await(
    gwt.ensure_valid_not_before(payload) |> promise.resolve,
  )

  let body = encoded_header <> "." <> encoded_payload

  use signature <- promise.try_await(
    signature
    |> bit_array.base64_url_decode()
    |> result.replace_error(gwt.InvalidSignature)
    |> promise.resolve(),
  )

  use valid <- promise.await(verify(signature, key.crypto_key, body))
  case valid {
    True -> Ok(gwt.dangerously_set_jwt_from_header_and_payload(header, payload))
    False -> Error(gwt.InvalidSignature)
  }
  |> promise.resolve()
}

@target(javascript)
fn algorithm_to_string(alg: Algorithm) -> String {
  case alg {
    RS256 -> "SHA-256"
    RS384 -> "SHA-384"
    RS512 -> "SHA-512"
  }
}

@target(javascript)
pub fn pem_to_rsa_private_key(
  pem: String,
  alg: Algorithm,
) -> Promise(Result(Key(Private), Nil)) {
  use crypto_key <- promise.try_await(pem_to_rsa_private_key_(
    pem,
    algorithm_to_string(alg),
  ))

  promise.resolve(Ok(Key(crypto_key:, alg:)))
}

@target(javascript)
pub fn pem_to_rsa_public_key(
  pem: String,
  alg: Algorithm,
) -> Promise(Result(Key(Public), Nil)) {
  use crypto_key <- promise.try_await(pem_to_rsa_public_key_(
    pem,
    algorithm_to_string(alg),
  ))

  promise.resolve(Ok(Key(crypto_key:, alg:)))
}

@target(javascript)
@external(javascript, "./rsa_ffi.mjs", "importPrivateKey")
fn pem_to_rsa_private_key_(
  pem: String,
  digest: String,
) -> Promise(Result(CryptoKey, Nil))

@target(javascript)
@external(javascript, "./rsa_ffi.mjs", "importPublicKey")
fn pem_to_rsa_public_key_(
  pem: String,
  digest: String,
) -> Promise(Result(CryptoKey, Nil))

@target(javascript)
@external(javascript, "./rsa_ffi.mjs", "sign")
fn sign(msg: String, key: CryptoKey) -> Promise(BitArray)

@target(javascript)
@external(javascript, "./rsa_ffi.mjs", "verify")
fn verify(signature: BitArray, key: CryptoKey, data: String) -> Promise(Bool)
