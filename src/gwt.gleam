// IMPORTS ---------------------------------------------------------------------

import gleam/bit_array
import gleam/crypto
import gleam/dict.{type Dict}
import gleam/dynamic.{type DecodeError, type Dynamic}
import gleam/json.{type Json}
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import birl

// TYPES -----------------------------------------------------------------------

type Header =
  Dict(String, Dynamic)

type Payload =
  Dict(String, Dynamic)

/// A phantom type representing a Jwt successfully decoded from a signed string.
///
pub type Verified

/// A phantom type representing an unverified Jwt.
///
pub type Unverified

///
pub opaque type Jwt(status) {
  Jwt(header: Header, payload: Payload)
}

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

/// Creates an [Unverified](#Unverified) Jwt with an empty payload and a header that only 
/// contains the cliams `"typ": "JWT"`, and `"alg": "none"`.
///
/// ```gleam
/// import gwt.{type Jwt, type Unverified}
/// 
/// fn example() -> Jwt(Unverified) {
///   gwt.new()
/// }
/// ```
///
pub fn new() -> Jwt(Unverified) {
  let header =
    dict.new()
    |> dict.insert("typ", dynamic.from("JWT"))
    |> dict.insert("alg", dynamic.from("none"))
  let payload = dict.new()

  Jwt(header, payload)
}

/// Decode a JWT string into an unverified [Jwt](#Jwt).
/// 
/// Returns `Ok(Jwt(Unverified))` if it is a valid JWT, and `Error(JwtDecodeError)` otherwise.
///
/// ```gleam
/// import gwt.{type Jwt, type Unverified, type JwtDecodeError}
/// 
/// fn example(jwt_string: String) -> Result(Jwt(Unverified), JwtDecodeError) {
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
/// Returns `Ok(Jwt(Unverified))` if it is a valid JWT and the JWT's signature is successfully verified,
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
  get_payload_claim(jwt, "iss", dynamic.string)
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
  get_payload_claim(jwt, "sub", dynamic.string)
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
  get_payload_claim(jwt, "aud", dynamic.string)
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
  get_payload_claim(jwt, "jti", dynamic.string)
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
  get_payload_claim(jwt, "iat", dynamic.int)
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
  get_payload_claim(jwt, "nbf", dynamic.int)
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
  get_payload_claim(jwt, "exp", dynamic.int)
}

/// Retrieve and decode a claim from a JWT's payload.
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
///     |> gwt.set_payload_claim("gleam", json.string("lucy"))
/// 
///   let assert Ok("lucy") =
///     gwt.get_payload_claim(jwt_with_custom_claim, "gleam", dynamic.string)
/// 
///   let assert Error(MissingClaim) =
///     gwt.get_payload_claim(jwt_with_custom_claim, "gleam", dynamic.int)
/// }
/// ```
///
pub fn get_payload_claim(
  from jwt: Jwt(status),
  claim claim: String,
  decoder decoder: fn(Dynamic) -> Result(a, List(dynamic.DecodeError)),
) -> Result(a, JwtDecodeError) {
  use claim_value <- result.try(
    jwt.payload
    |> dict.get(claim)
    |> result.replace_error(MissingClaim),
  )

  claim_value
  |> decoder()
  |> result.map_error(fn(e) { InvalidClaim(e) })
}

/// Set the iss claim of a payload, and changing the JWT to unverified.
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
pub fn set_issuer(jwt: Jwt(status), to iss: String) -> Jwt(Unverified) {
  let new_payload = dict.insert(jwt.payload, "iss", dynamic.from(iss))

  Jwt(jwt.header, payload: new_payload)
}

/// Set the sub claim of a payload, and changing the JWT to unverified.
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
pub fn set_subject(jwt: Jwt(status), to sub: String) -> Jwt(Unverified) {
  let new_payload = dict.insert(jwt.payload, "sub", dynamic.from(sub))

  Jwt(jwt.header, payload: new_payload)
}

/// Set the aud claim of a payload, and changing the JWT to unverified.
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
pub fn set_audience(jwt: Jwt(status), to aud: String) -> Jwt(Unverified) {
  let new_payload = dict.insert(jwt.payload, "aud", dynamic.from(aud))

  Jwt(jwt.header, payload: new_payload)
}

/// Set the exp claim of a payload, and changing the JWT to unverified.
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
pub fn set_expiration(jwt: Jwt(status), to exp: Int) -> Jwt(Unverified) {
  let new_payload = dict.insert(jwt.payload, "exp", dynamic.from(exp))

  Jwt(jwt.header, payload: new_payload)
}

/// Set the nbf claim of a payload, and changing the JWT to unverified.
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
pub fn set_not_before(jwt: Jwt(status), to nbf: Int) -> Jwt(Unverified) {
  let new_payload = dict.insert(jwt.payload, "nbf", dynamic.from(nbf))

  Jwt(jwt.header, payload: new_payload)
}

/// Set the nbf claim of a payload, and changing the JWT to unverified.
///
/// ```gleam
/// import gwt
/// import birl
/// 
/// fn example() {
///   gwt.new()
///   |> gwt.set_not_before(birl.to_unix(birl.now()))
/// }
/// ``` 
///
pub fn set_issued_at(jwt: Jwt(status), to iat: Int) -> Jwt(Unverified) {
  let new_payload = dict.insert(jwt.payload, "iat", dynamic.from(iat))

  Jwt(jwt.header, payload: new_payload)
}

/// Set the jti claim of a payload, and changing the JWT to unverified.
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
pub fn set_jwt_id(jwt: Jwt(status), to jti: String) -> Jwt(Unverified) {
  let new_payload = dict.insert(jwt.payload, "jti", dynamic.from(jti))

  Jwt(jwt.header, payload: new_payload)
}

/// Set a custom payload claim to a given JSON value, and changing the JWT to unverified.
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
  jwt: Jwt(status),
  set claim: String,
  to value: Json,
) -> Jwt(Unverified) {
  let new_payload = dict.insert(jwt.payload, claim, dynamic.from(value))

  Jwt(jwt.header, payload: new_payload)
}

// HEADER ----------------------------------------------------------------------

/// Set a custom header claim to a given JSON value, and changing the JWT to unverified.
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
  jwt: Jwt(status),
  set claim: String,
  to value: Json,
) -> Jwt(Unverified) {
  let new_header = dict.insert(jwt.header, claim, dynamic.from(value))

  Jwt(jwt.payload, header: new_header)
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
  decoder decoder: fn(Dynamic) -> Result(a, List(dynamic.DecodeError)),
) -> Result(a, Nil) {
  use claim_value <- result.try(
    jwt.header
    |> dict.get(claim),
  )

  claim_value
  |> decoder()
  |> result.nil_error()
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
pub fn to_string(jwt: Jwt(status)) -> String {
  let Jwt(header, payload) = jwt

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
  jwt: Jwt(status),
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

      let header_with_alg =
        dict.insert(jwt.header, "alg", dynamic.from(alg_string))
      let jwt_body =
        Jwt(..jwt, header: header_with_alg)
        |> to_string()

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

fn dict_to_json_object(d: Dict(String, Dynamic)) -> Json {
  let key_value_list = {
    use acc, key, value <- dict.fold(d, [])
    let json_value = case dynamic.classify(value) {
      "String" -> {
        let assert Ok(json_string) = dynamic.string(value)
        json.string(json_string)
      }
      "Float" -> {
        let assert Ok(json_float) = dynamic.float(value)
        json.float(json_float)
      }
      "Int" -> {
        let assert Ok(json_int) = dynamic.int(value)
        json.int(json_int)
      }
      "Bool" -> {
        let assert Ok(json_bool) = dynamic.bool(value)
        json.bool(json_bool)
      }
      "Map" | "Dict" -> {
        let decoder = dynamic.dict(dynamic.string, dynamic.dynamic)
        let assert Ok(d) = decoder(value)
        dict_to_json_object(d)
      }
      _ -> panic as "Unsupported JSON data type"
    }
    [#(key, json_value), ..acc]
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
) -> Result(#(Header, Payload, Option(String)), JwtDecodeError) {
  let jwt_parts = string.split(jwt_string, ".")

  let signature =
    list.at(jwt_parts, 2)
    |> option.from_result()

  use encoded_payload <- result.try(
    list.at(jwt_parts, 1)
    |> result.replace_error(MissingPayload),
  )

  use encoded_header <- result.try(
    list.at(jwt_parts, 0)
    |> result.replace_error(MissingHeader),
  )
  use header_data <- result.try(
    encoded_header
    |> bit_array.base64_url_decode()
    |> result.replace_error(InvalidHeader),
  )
  use header_string <- result.try(
    header_data
    |> bit_array.to_string()
    |> result.replace_error(InvalidHeader),
  )

  use header <- result.try(
    json.decode(header_string, dynamic.dict(dynamic.string, dynamic.dynamic))
    |> result.replace_error(InvalidHeader),
  )

  use payload_data <- result.try(
    encoded_payload
    |> bit_array.base64_url_decode()
    |> result.replace_error(InvalidHeader),
  )
  use payload_string <- result.try(
    payload_data
    |> bit_array.to_string()
    |> result.replace_error(InvalidHeader),
  )

  use payload <- result.try(
    json.decode(payload_string, dynamic.dict(dynamic.string, dynamic.dynamic))
    |> result.replace_error(InvalidHeader),
  )

  Ok(#(header, payload, signature))
}

fn ensure_valid_expiration(payload: Payload) -> Result(Nil, JwtDecodeError) {
  let exp = {
    use exp <- result.try(
      dict.get(payload, "exp")
      |> result.or(Ok(dynamic.from(-1)))
      |> result.replace_error(InvalidHeader),
    )
    dynamic.int(exp)
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

fn ensure_valid_not_before(payload: Payload) -> Result(Nil, JwtDecodeError) {
  let nbf = {
    use nbf <- result.try(
      dict.get(payload, "nbf")
      |> result.or(Ok(dynamic.from(-1)))
      |> result.replace_error(InvalidHeader),
    )
    dynamic.int(nbf)
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

fn ensure_valid_alg(header: Header) -> Result(String, JwtDecodeError) {
  use alg <- result.try(
    dict.get(header, "alg")
    |> result.replace_error(NoAlg),
  )

  alg
  |> dynamic.string()
  |> result.replace_error(InvalidAlg)
}
