@target(erlang)
import gleam/bit_array
@target(erlang)
import gleam/crypto
@target(erlang)
import gleam/option
@target(erlang)
import gleam/result
@target(erlang)
import gwt

@target(erlang)
pub type Public

@target(erlang)
pub type Private

@target(erlang)
pub type Key(scope)

@target(erlang)
pub type Algorithm {
  RS256
  RS384
  RS512
}

@target(erlang)
pub fn to_signed_string(
  jwt: gwt.JwtBuilder,
  alg: Algorithm,
  key: Key(Private),
) -> String {
  let #(alg_string, digest) = case alg {
    RS256 -> #("RS256", crypto.Sha256)
    RS384 -> #("RS384", crypto.Sha384)
    RS512 -> #("RS512", crypto.Sha512)
  }

  let header_string = gwt.get_header_string(jwt, alg_string)
  let payload_string = gwt.get_payload_string(jwt)
  let jwt_body = header_string <> "." <> payload_string

  let jwt_signature =
    jwt_body
    |> bit_array.from_string()
    |> sign(digest, key)
    |> bit_array.base64_url_encode(False)

  jwt_body <> "." <> jwt_signature
}

@target(erlang)
pub fn from_signed_string(
  jwt_string: String,
  key: Key(Public),
) -> Result(gwt.Jwt(gwt.Verified), gwt.JwtDecodeError) {
  use #(encoded_header, encoded_payload, maybe_signature) <- result.try(
    gwt.string_parts(jwt_string),
  )

  use header <- result.try(gwt.part_to_dict(encoded_header, gwt.InvalidHeader))
  use payload <- result.try(gwt.part_to_dict(
    encoded_payload,
    gwt.InvalidPayload,
  ))
  use signature <- result.try(option.to_result(
    maybe_signature,
    gwt.MissingSignature,
  ))

  use _ <- result.try(gwt.ensure_valid_expiration(payload))
  use _ <- result.try(gwt.ensure_valid_not_before(payload))
  use alg_string <- result.try(gwt.ensure_valid_alg(header))

  let digest = case alg_string {
    "RS256" -> Ok(crypto.Sha256)
    "RS384" -> Ok(crypto.Sha384)
    "RS512" -> Ok(crypto.Sha512)
    _ -> Error(gwt.UnexpectedAlgorithm)
  }
  use digest <- result.try(digest)

  let body = bit_array.from_string(encoded_header <> "." <> encoded_payload)
  use signature <- result.try(
    signature
    |> bit_array.base64_url_decode()
    |> result.replace_error(gwt.InvalidSignature),
  )
  case verify(body, digest, signature, key) {
    True -> Ok(gwt.dangerously_set_jwt_from_header_and_payload(header, payload))
    False -> Error(gwt.InvalidSignature)
  }
}

@target(erlang)
@external(erlang, "rsa_ffi", "extract_public_key_from_pem")
pub fn pem_to_rsa_public_key(pem: String) -> Result(Key(Public), Nil)

@target(erlang)
@external(erlang, "rsa_ffi", "extract_private_key_from_pem")
pub fn pem_to_rsa_private_key(pem: String) -> Result(Key(Private), Nil)

@target(erlang)
@external(erlang, "public_key", "sign")
fn sign(
  msg: BitArray,
  digest: crypto.HashAlgorithm,
  key: Key(Private),
) -> BitArray

@target(erlang)
@external(erlang, "public_key", "verify")
fn verify(
  msg: BitArray,
  digest: crypto.HashAlgorithm,
  signature: BitArray,
  key: Key(Public),
) -> Bool
