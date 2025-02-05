// IMPORTS ---------------------------------------------------------------------

import birl
import gleam/bit_array
import gleam/crypto
import gleam/dict.{type Dict}
import gleam/dynamic
import gleam/dynamic/decode.{type DecodeError, type Decoder, type Dynamic}
import gleam/json.{type Json}
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string

// TYPES -----------------------------------------------------------------------

/// A phantom type representing a Jwt successfully decoded from a signed string.
///
pub type Verified

/// A phantom type representing an unverified Jwt.
///
pub type Unverified

/// The intermediate representation of a JWT before being encoded to a `String`.
///
pub opaque type JwtBuilder {
  JwtBuilder(header: Dict(String, Json), payload: Dict(String, Json))
}

/// A decoded JWT that can be read. The phantom type `status` indicated if it's
/// signature was verified or not.
///
pub opaque type Jwt(status) {
  Jwt(header: Dict(String, Dynamic), payload: Dict(String, Dynamic))
}

/// Errors that can occur when attempting to decode a JWT from a String or read
/// from a successfully decoded JWT string.
///
pub type JwtDecodeError {
  MissingHeader
  ///
  MissingPayload
  ///
  MissingSignature
  ///
  InvalidHeader
  ///
  InvalidPayload
  ///
  InvalidSignature
  ///
  InvalidExpiration
  ///
  TokenExpired
  ///
  TokenNotValidYet
  ///
  InvalidNotBefore
  ///
  NoAlg
  ///
  InvalidAlg
  ///
  UnsupportedSigningAlgorithm
  ///
  MissingClaim
  ///
  InvalidClaim(List(DecodeError))
}

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

// CONSTRUCTORS ----------------------------------------------------------------

/// Creates a JwtBuilder with an empty payload and a header that only
/// contains the cliams `"typ": "JWT"`, and `"alg": "none"`.
///
/// ```gleam
/// import gwt.{type Jwt, type Unverified}
///
/// fn example() -> JwtBuilder {
///   gwt.new()
/// }
/// ```
///
pub fn new() -> JwtBuilder {
  let header =
    dict.new()
    |> dict.insert("typ", json.string("JWT"))
    |> dict.insert("alg", json.string("none"))
  let payload = dict.new()

  JwtBuilder(header, payload)
}

/// Decode a JWT string into an unverified [Jwt](#Jwt).
///
/// Returns `Ok(JwtBuilder)` if it is a valid JWT, and `Error(JwtDecodeError)` otherwise.
///
/// ```gleam
/// import gwt.{type Jwt, type Unverified, type JwtDecodeError}
///
/// fn example(jwt_string: String) -> Result(JwtBuilder, JwtDecodeError) {
///   gwt.from_string(jwt_string)
/// }
/// ```
///
pub fn from_string(
  jwt_string: String,
) -> Result(Jwt(Unverified), JwtDecodeError) {
  use #(header, payload, _) <- result.try(parts(jwt_string))
  Ok(Jwt(header, payload))
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
) -> Result(Jwt(Verified), JwtDecodeError) {
  use #(header, payload, signature) <- result.try(parts(jwt_string))
  use signature <- result.try(option.to_result(signature, MissingSignature))

  use _ <- result.try(ensure_valid_expiration(payload))
  use _ <- result.try(ensure_valid_not_before(payload))
  use alg <- result.try(ensure_valid_alg(header))

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
      case sig == signature {
        True -> {
          Ok(Jwt(header: header, payload: payload))
        }
        False -> Error(InvalidSignature)
      }
    }
    _ -> Error(UnsupportedSigningAlgorithm)
  }
}

// PAYLOAD ---------------------------------------------------------------------

/// Retrieve the iss from the JWT's payload.
///
/// Returns `Error(Nil)` if the iss is not present or if it is invalid.
///
/// If you know the iss claim is not of type `String` you can use [get_payload_claim](#get_payload_claim)
/// to retrieve and decode it manually.
///
/// ```gleam
/// import gwt
///
/// fn example()  {
///   let jwt_with_iss =
///     gwt.new()
///     |> jwt.set_issuer("gleam")
///
///   let assert Ok(issuer) = gwt.get_issuer(jwt_with_iss)
///
///   let jwt_without_iss = gwt.new()
///
///   let assert Error(MissingClaim) = gwt.get_issuer(jwt_without_iss)
/// }
/// ```
///
pub fn get_issuer(from jwt: Jwt(status)) -> Result(String, JwtDecodeError) {
  get_payload_claim(jwt, "iss", decode.string)
}

/// Retrieve the sub from the JWT's payload.
///
/// Returns `Error(Nil)` if the sub is not present or if it is invalid.
///
/// If you know the sub claim is not of type `String` you can use [get_payload_claim](#get_payload_claim)
/// to retrieve and decode it manually.
///
/// ```gleam
/// import gwt
///
/// fn example()  {
///   let jwt_with_sub =
///     gwt.new()
///     |> jwt.set_subject("gleam")
///
///   let assert Ok(subject) = gwt.get_issuer(jwt_with_sub)
///
///   let jwt_without_sub = gwt.new()
///
///   let assert Error(MissingClaim) = gwt.get_subject(jwt_without_sub)
/// }
/// ```
///
pub fn get_subject(from jwt: Jwt(status)) -> Result(String, JwtDecodeError) {
  get_payload_claim(jwt, "sub", decode.string)
}

/// Retrieve the aud from the JWT's payload.
///
/// Returns `Error(Nil)` if the sub is not present or if it is invalid.
///
/// If you know the aud claim is not of type `String` you can use [get_payload_claim](#get_payload_claim)
/// to retrieve and decode it manually.
///
/// ```gleam
/// import gwt
///
/// fn example()  {
///   let jwt_with_aud =
///     gwt.new()
///     |> jwt.set_audience("gleam")
///
///   let assert Ok(audience) = gwt.get_audience(jwt_with_aud)
///
///   let jwt_without_aud = gwt.new()
///
///   let assert Error(MissingClaim) = gwt.get_audience(jwt_without_aud)
/// }
/// ```
///
pub fn get_audience(from jwt: Jwt(status)) -> Result(String, JwtDecodeError) {
  get_payload_claim(jwt, "aud", decode.string)
}

/// Retrieve the jti from the JWT's payload.
///
/// Returns `Error(Nil)` if the jti is not present or if it is invalid.
///
/// If you know the jti claim is not of type `String` you can use [get_payload_claim](#get_payload_claim)
/// to retrieve and decode it manually.
///
/// ```gleam
/// import gwt
///
/// fn example()  {
///   let jwt_with_jti =
///     gwt.new()
///     |> jwt.set_jwt_id("gleam")
///
///   let assert Ok(jwt_id) = gwt.get_jwt_id(jwt_with_jti)
///
///   let jwt_without_jti = gwt.new()
///
///   let assert Error(MissingClaim) = gwt.get_jwt_id(jwt_without_jti)
/// }
/// ```
///
pub fn get_jwt_id(from jwt: Jwt(status)) -> Result(String, JwtDecodeError) {
  get_payload_claim(jwt, "jti", decode.string)
}

/// Retrieve the iat from the JWT's payload.
///
/// Returns `Error(Nil)` if the iat is not present or if it is invalid.
///
/// If you know the iat claim is not of type `String` you can use [get_payload_claim](#get_payload_claim)
/// to retrieve and decode it manually.
///
/// ```gleam
/// import gwt
///
/// fn example()  {
///   let jwt_with_iat =
///     gwt.new()
///     |> jwt.set_issued_at("gleam")
///
///   let assert Ok(issued_at) = gwt.get_issued_at(jwt_with_iat)
///
///   let jwt_without_iat = gwt.new()
///
///   let assert Error(MissingClaim) = gwt.get_issued_at(jwt_without_iat)
/// }
/// ```
///
pub fn get_issued_at(from jwt: Jwt(status)) -> Result(Int, JwtDecodeError) {
  get_payload_claim(jwt, "iat", decode.int)
}

/// Retrieve the nbf from the JWT's payload.
///
/// Returns `Error(Nil)` if the nbf is not present or if it is invalid.
///
/// If you know the nbf claim is not of type `String` you can use [get_payload_claim](#get_payload_claim)
/// to retrieve and decode it manually.
///
/// ```gleam
/// import gwt
///
/// fn example()  {
///   let jwt_with_sub =
///     gwt.new()
///     |> jwt.set_not_before("gleam")
///
///   let assert Ok(not_before) = gwt.get_not_before(jwt_with_nbf)
///
///   let jwt_without_nbf = gwt.new()
///
///   let assert Error(MissingClaim) = gwt.get_not_before(jwt_without_nbf)
/// }
/// ```
///
pub fn get_not_before(from jwt: Jwt(status)) -> Result(Int, JwtDecodeError) {
  get_payload_claim(jwt, "nbf", decode.int)
}

/// Retrieve the exp from the JWT's payload.
///
/// Returns `Error(Nil)` if the exp is not present or if it is invalid.
///
/// If you know the exp claim is not of type `String` you can use [get_payload_claim](#get_payload_claim)
/// to retrieve and decode it manually.
///
/// ```gleam
/// import gwt
///
/// fn example()  {
///   let jwt_with_exp =
///     gwt.new()
///     |> jwt.set_not_before("gleam")
///
///   let assert Ok(expiration) = gwt.get_not_before(jwt_with_exp)
///
///   let jwt_without_exp = gwt.new()
///
///   let assert Error(MissingClaim) = gwt.get_not_before(jwt_without_exp)
/// }
/// ```
///
pub fn get_expiration(from jwt: Jwt(status)) -> Result(Int, JwtDecodeError) {
  get_payload_claim(jwt, "exp", decode.int)
}

/// Retrieve and decode a claim from a JWT's payload.
///
/// Returns `Error` if the claim is not present or if it is invalid based on the passed in decoder.
///
/// ```gleam
/// import gwt
/// import gleam/json
/// import gleam/dynamic/decode
///
/// fn example() {
///   let jwt_with_custom_claim =
///     gwt.new()
///     |> gwt.set_payload_claim("gleam", json.string("lucy"))
///
///   let assert Ok("lucy") =
///     gwt.get_payload_claim(jwt_with_custom_claim, "gleam", decode.string)
///
///   let assert Error(MissingClaim) =
///     gwt.get_payload_claim(jwt_with_custom_claim, "gleam", decode.int)
/// }
/// ```
///
pub fn get_payload_claim(
  from jwt: Jwt(status),
  claim claim: String,
  decoder decoder: Decoder(a),
) -> Result(a, JwtDecodeError) {
  use claim_value <- result.try(
    jwt.payload
    |> dict.get(claim)
    |> result.replace_error(MissingClaim),
  )

  decode.run(claim_value, decoder)
  |> result.map_error(fn(e) { InvalidClaim(e) })
}

/// Set the iss claim of a payload.
///
/// ```gleam
/// import gwt
///
/// fn example() {
///   gwt.new()
///   |> gwt.set_issuer("gleam")
/// }
/// ```
///
pub fn set_issuer(jwt: JwtBuilder, to iss: String) -> JwtBuilder {
  let new_payload = dict.insert(jwt.payload, "iss", json.string(iss))

  JwtBuilder(jwt.header, payload: new_payload)
}

/// Set the sub claim of a payload.
///
/// ```gleam
/// import gwt
///
/// fn example() {
///   gwt.new()
///   |> gwt.set_subject("gleam")
/// }
/// ```
///
pub fn set_subject(jwt: JwtBuilder, to sub: String) -> JwtBuilder {
  let payload = dict.insert(jwt.payload, "sub", json.string(sub))

  JwtBuilder(jwt.header, payload:)
}

/// Set the aud claim of a payload.
///
/// ```gleam
/// import gwt
///
/// fn example() {
///   gwt.new()
///   |> gwt.set_audience("gleam")
/// }
/// ```
///
pub fn set_audience(jwt: JwtBuilder, to aud: String) -> JwtBuilder {
  let payload = dict.insert(jwt.payload, "aud", json.string(aud))

  JwtBuilder(jwt.header, payload:)
}

/// Set the exp claim of a payload.
///
/// ```gleam
/// import gwt
/// import birl
///
/// fn example() {
///   let five_minutes = birl.to_unix(birl.now()) + 300
///
///   gwt.new()
///   |> gwt.set_expiration(five_minutes)
/// }
/// ```
///
pub fn set_expiration(jwt: JwtBuilder, to exp: Int) -> JwtBuilder {
  let payload = dict.insert(jwt.payload, "exp", json.int(exp))

  JwtBuilder(jwt.header, payload:)
}

/// Set the nbf claim of a payload.
///
/// ```gleam
/// import gwt
/// import birl
///
/// fn example() {
///   let five_minutes = birl.to_unix(birl.now()) + 300
///
///   gwt.new()
///   |> gwt.set_not_before(five_minutes)
/// }
/// ```
///
pub fn set_not_before(jwt: JwtBuilder, to nbf: Int) -> JwtBuilder {
  let payload = dict.insert(jwt.payload, "nbf", json.int(nbf))

  JwtBuilder(jwt.header, payload:)
}

/// Set the iat claim of a payload.
///
/// ```gleam
/// import gwt
/// import birl
///
/// fn example() {
///   gwt.new()
///   |> gwt.set_issued_at(birl.to_unix(birl.now()))
/// }
/// ```
///
pub fn set_issued_at(jwt: JwtBuilder, to iat: Int) -> JwtBuilder {
  let payload = dict.insert(jwt.payload, "iat", json.int(iat))

  JwtBuilder(jwt.header, payload:)
}

/// Set the jti claim of a payload.
///
/// ```gleam
/// import gwt
/// import birl
///
/// fn example() {
///   gwt.new()
///   |> gwt.set_jwt_id("gleam")
/// }
/// ```
///
pub fn set_jwt_id(jwt: JwtBuilder, to jti: String) -> JwtBuilder {
  let payload = dict.insert(jwt.payload, "jti", json.string(jti))

  JwtBuilder(jwt.header, payload:)
}

/// Set a custom payload claim to a given JSON value.
///
/// ```gleam
/// import gleam/json
/// import gwt
///
/// fn example() {
///   gwt.new()
///   |> gwt.set_payload_claim("gleam", json.string("lucy"))
/// }
/// ```
///
pub fn set_payload_claim(
  jwt: JwtBuilder,
  set claim: String,
  to value: Json,
) -> JwtBuilder {
  let payload = dict.insert(jwt.payload, claim, value)

  JwtBuilder(jwt.header, payload:)
}

// HEADER ----------------------------------------------------------------------

/// Set a custom header claim to a given JSON value.
///
/// ```gleam
/// import gleam/json
/// import gwt
///
/// fn example() {
///   gwt.new()
///   |> gwt.set_header_claim("gleam", json.string("lucy"))
/// }
/// ```
///
pub fn set_header_claim(
  jwt: JwtBuilder,
  set claim: String,
  to value: Json,
) -> JwtBuilder {
  let header = dict.insert(jwt.header, claim, value)

  JwtBuilder(jwt.payload, header:)
}

/// Retrieve and decode a claim from a JWT's header.
///
/// Returns `Error` if the claim is not present or if it is invalid based on the passed in decoder.
///
/// ```gleam
/// import gwt
/// import gleam/json
/// import gleam/dynamic
///
/// fn example() {
///   let jwt_with_custom_claim =
///     gwt.new()
///     |> gwt.set_header_claim("gleam", json.string("lucy"))
///
///   let assert Ok("lucy") =
///     gwt.get_header_claim(jwt_with_custom_claim, "gleam", dynamic.string)
///
///   let assert Error(MissingClaim) =
///     gwt.get_header_claim(jwt_with_custom_claim, "gleam", dynamic.int)
/// }
/// ```
///
pub fn get_header_claim(
  from jwt: Jwt(status),
  claim claim: String,
  decoder decoder: fn(Dynamic) -> Result(a, List(DecodeError)),
) -> Result(a, Nil) {
  use claim_value <- result.try(
    jwt.header
    |> dict.get(claim),
  )

  claim_value
  |> decoder()
  |> result.replace_error(Nil)
}

// ENCODER ---------------------------------------------------------------------

/// Encode a [Jwt](#Jwt) to a String without a signature
///
/// ```gleam
/// import gwt
///
/// fn example() {
///   gwt.new()
///   |> gwt.set_issuer("gleam")
///   |> gwt.to_string()
/// }
/// ```
///
pub fn to_string(jwt: JwtBuilder) -> String {
  let JwtBuilder(header, payload) = jwt

  let header_string =
    header
    |> dict_to_json_object()
    |> json.to_string()
    |> bit_array.from_string()
    |> bit_array.base64_url_encode(False)

  let payload_string =
    payload
    |> dict_to_json_object()
    |> json.to_string()
    |> bit_array.from_string()
    |> bit_array.base64_url_encode(False)

  header_string <> "." <> payload_string
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
  jwt: JwtBuilder,
  alg: Algorithm,
  secret: String,
) -> String {
  let JwtBuilder(header:, payload:) = jwt

  case alg {
    HS256 | HS384 | HS512 -> {
      let #(alg_string, hash_alg) = case alg {
        HS256 -> #("HS256", crypto.Sha256)
        HS384 -> #("HS384", crypto.Sha384)
        HS512 -> #("HS512", crypto.Sha512)
      }

      let header = dict.insert(header, "alg", json.string(alg_string))

      let header_string =
        header
        |> dict_to_json_object()
        |> json.to_string()
        |> bit_array.from_string()
        |> bit_array.base64_url_encode(False)

      let payload_string =
        payload
        |> dict_to_json_object()
        |> json.to_string()
        |> bit_array.from_string()
        |> bit_array.base64_url_encode(False)

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

// UTILITIES -------------------------------------------------------------------

fn dict_to_json_object(d: Dict(String, Json)) -> Json {
  let key_value_list = {
    use acc, key, value <- dict.fold(d, [])
    [#(key, value), ..acc]
  }

  json.object(key_value_list)
}

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

fn parts(
  jwt_string: String,
) -> Result(
  #(Dict(String, Dynamic), Dict(String, Dynamic), Option(String)),
  JwtDecodeError,
) {
  let parts = string.split(jwt_string, ".")

  use encoded_header <- result.try(
    list.first(parts) |> result.replace_error(MissingHeader),
  )
  let parts = list.drop(parts, 1)
  use header_string <- result.try(
    encoded_header
    |> bit_array.base64_url_decode()
    |> result.try(bit_array.to_string)
    |> result.replace_error(InvalidHeader),
  )
  use header <- result.try(
    json.parse(header_string, decode.dict(decode.string, decode.dynamic))
    |> result.replace_error(InvalidHeader),
  )

  use encoded_payload <- result.try(
    list.first(parts) |> result.replace_error(MissingPayload),
  )
  let parts = list.drop(parts, 1)
  use payload_string <- result.try(
    encoded_payload
    |> bit_array.base64_url_decode()
    |> result.try(bit_array.to_string)
    |> result.replace_error(InvalidPayload),
  )
  use payload <- result.try(
    json.parse(payload_string, decode.dict(decode.string, decode.dynamic))
    |> result.replace_error(InvalidPayload),
  )

  let signature =
    parts
    |> list.first()
    |> option.from_result()

  Ok(#(header, payload, signature))
}

fn ensure_valid_expiration(
  payload: Dict(String, Dynamic),
) -> Result(Nil, JwtDecodeError) {
  let exp = {
    use exp <- result.try(
      dict.get(payload, "exp")
      |> result.or(Ok(dynamic.from(-1)))
      |> result.replace_error(InvalidHeader),
    )
    decode.run(exp, decode.int)
    |> result.replace_error(InvalidHeader)
  }
  use exp <- result.try(exp)
  let exp = case exp {
    -1 -> None
    v -> Some(v)
  }

  case exp {
    None -> Ok(Nil)
    Some(v) -> {
      let now =
        birl.now()
        |> birl.to_unix()
      case now < v {
        True -> Ok(Nil)
        False -> Error(TokenExpired)
      }
    }
  }
}

fn ensure_valid_not_before(
  payload: Dict(String, Dynamic),
) -> Result(Nil, JwtDecodeError) {
  let nbf = {
    use nbf <- result.try(
      dict.get(payload, "nbf")
      |> result.or(Ok(dynamic.from(-1)))
      |> result.replace_error(InvalidHeader),
    )
    decode.run(nbf, decode.int)
    |> result.replace_error(InvalidHeader)
  }
  use nbf <- result.try(nbf)
  let nbf = case nbf {
    -1 -> None
    v -> Some(v)
  }

  case nbf {
    None -> Ok(Nil)
    Some(v) -> {
      let now =
        birl.now()
        |> birl.to_unix()
      case now > v {
        True -> Ok(Nil)
        False -> Error(TokenNotValidYet)
      }
    }
  }
}

fn ensure_valid_alg(
  header: Dict(String, Dynamic),
) -> Result(String, JwtDecodeError) {
  use alg <- result.try(
    dict.get(header, "alg")
    |> result.replace_error(NoAlg),
  )

  alg
  |> decode.run(decode.string)
  |> result.replace_error(InvalidAlg)
}
