import gleam/bit_array
import gleam/crypto
import gleam/option
import gleam/result
import gleam/string
import gwt

/// Available [JSON Web Algorithms](https://datatracker.ietf.org/doc/html/rfc7518#section-3.2) used for encoding and decdoing signatures in [from_signed_string](#from_signed_string) and [to_signed_string](#to_signed_string).
///
/// If JWT calls for a different algorithm than the ones listed here [from_signed_string](#from_signed_string) will fail
/// with the [JwtDecodeError](#JwtDecodeError) `UnsupportedSigningAlgorithm`.
///
pub type Algorithm {
  HS256
  HS384
  HS512
}

/// Encode a [Jwt](#Jwt) to a signed String using the given [Algorithm](#Algorithm) and secret.
///
/// ```gleam
/// import gwt
///
/// fn example() {
///   gwt.new()
///   |> gwt.set_issuer("gleam")
///   |> gwt.to_signed_string(gwt.HS256, "lucy")
/// }
/// ```
///
pub fn to_signed_string(
  jwt: gwt.JwtBuilder,
  alg: Algorithm,
  secret: String,
) -> String {
  case alg {
    HS256 | HS384 | HS512 -> {
      let #(alg_string, hash_alg) = case alg {
        HS256 -> #("HS256", crypto.Sha256)
        HS384 -> #("HS384", crypto.Sha384)
        HS512 -> #("HS512", crypto.Sha512)
      }

      let header_string = gwt.get_header_string(jwt, alg_string)
      let payload_string = gwt.get_payload_string(jwt)
      let jwt_body = header_string <> "." <> payload_string

      let jwt_signature =
        jwt_body
        |> bit_array.from_string()
        |> crypto.hmac(hash_alg, bit_array.from_string(secret))
        |> bit_array.base64_url_encode(False)

      jwt_body <> "." <> jwt_signature
    }
  }
}

/// Decode a signed JWT string into a verified [Jwt](#Jwt).
///
/// Returns `Ok(JwtBuilder)` if it is a valid JWT and the JWT's signature is successfully verified,
/// and `Error(JwtDecodeError)` otherwise.
///
/// At the moment this library only supports `HS256`, `HS384`, and `HS512` hashing algorithms.
/// if a JWT's alg claim calls for any other this function will return `Error(UnsupportedSigningAlgorithm)`.
///
/// ```gleam
/// import gwt.{type Jwt, type Verified, type JwtDecodeError}
///
/// fn example(jwt_string: String) -> Result(Jwt(Verified), JwtDecodeError) {
///   gwt.from_signed_string(jwt_string, "some secret")
/// }
/// ```
///
pub fn from_signed_string(
  jwt_string: String,
  secret: String,
) -> Result(gwt.Jwt(gwt.Verified), gwt.JwtDecodeError) {
  use #(header, payload, signature) <- result.try(gwt.parts(jwt_string))
  use signature <- result.try(option.to_result(signature, gwt.MissingSignature))

  use _ <- result.try(gwt.ensure_valid_expiration(payload))
  use _ <- result.try(gwt.ensure_valid_not_before(payload))
  use alg <- result.try(gwt.ensure_valid_alg(header))

  let assert [encoded_header, encoded_payload, ..] =
    string.split(jwt_string, ".")
  case alg {
    "HS256" | "HS384" | "HS512" -> {
      let alg = case alg {
        "HS256" -> HS256
        "HS384" -> HS384
        "HS512" -> HS512
        _ -> panic as "Should not be reachable"
      }

      let sig =
        get_signature(encoded_header <> "." <> encoded_payload, alg, secret)
      case
        crypto.secure_compare(
          bit_array.from_string(sig),
          bit_array.from_string(signature),
        )
      {
        True -> {
          Ok(gwt.dangerously_set_jwt_from_header_and_payload(header, payload))
        }
        False -> Error(gwt.InvalidSignature)
      }
    }
    _ -> Error(gwt.UnsupportedSigningAlgorithm)
  }
}

// UTILS -----------------------------------------------------------------------

fn get_signature(data: String, algorithm: Algorithm, secret: String) -> String {
  case algorithm {
    HS256 | HS384 | HS512 -> {
      let hash_alg = case algorithm {
        HS256 -> crypto.Sha256
        HS384 -> crypto.Sha384
        HS512 -> crypto.Sha512
      }

      data
      |> bit_array.from_string()
      |> crypto.hmac(hash_alg, bit_array.from_string(secret))
      |> bit_array.base64_url_encode(False)
    }
  }
}
