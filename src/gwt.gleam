// IMPORTS ---------------------------------------------------------------------

import gleam/bit_array
import gleam/dict.{type Dict}
import gleam/dynamic.{type Dynamic}
import gleam/json.{type Json}
import gleam/string
import gleam/list
import gleam/result
import gleam/option
import gleam/crypto
import birl

// TYPES -----------------------------------------------------------------------

type Header =
  Dict(String, Dynamic)

type Payload =
  Dict(String, Dynamic)

pub type Verified

pub type Unverified

pub opaque type Jwt(status) {
  Jwt(header: Header, payload: Payload)
}

pub type JwtDecodeError {
  ///
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
}

pub type Algorithm {
  HS256
}

// CONSTRUCTORS ----------------------------------------------------------------

///
pub fn new() -> Jwt(Unverified) {
  let header =
    dict.new()
    |> dict.insert("typ", dynamic.from("JWT"))
    |> dict.insert("alg", dynamic.from("none"))
  let payload = dict.new()

  Jwt(header, payload)
}

///
pub fn from_string(
  jwt_string: String,
) -> Result(Jwt(Unverified), JwtDecodeError) {
  use #(header, payload, _) <- result.try(parts(jwt_string))
  Ok(Jwt(header, payload))
}

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
    "HS256" -> {
      let sig =
        get_signature(encoded_header <> "." <> encoded_payload, HS256, secret)
      case sig == signature {
        True -> {
          Ok(Jwt(header: header, payload: payload))
        }
        False -> Error(InvalidSignature)
      }
    }
    _ -> panic as "Unimplemented signature algorithm"
  }
}

// PAYLOAD ---------------------------------------------------------------------

///
pub fn get_issuer(from jwt: Jwt(a)) -> Result(String, Nil) {
  use issuer <- result.try(
    jwt.payload
    |> dict.get("iss"),
  )

  issuer
  |> dynamic.string()
  |> result.nil_error()
}

///
pub fn get_subject(from jwt: Jwt(a)) -> Result(String, Nil) {
  use issuer <- result.try(
    jwt.payload
    |> dict.get("sub"),
  )

  issuer
  |> dynamic.string()
  |> result.nil_error()
}

///
pub fn get_payload_claim(
  from jwt: Jwt(a),
  claim claim: String,
  decoder decoder: fn(Dynamic) -> Result(String, List(dynamic.DecodeError)),
) -> Result(String, Nil) {
  use claim_value <- result.try(
    jwt.payload
    |> dict.get(claim),
  )

  claim_value
  |> decoder()
  |> result.nil_error()
}

///
pub fn set_issuer(jwt: Jwt(a), to iss: String) -> Jwt(a) {
  let new_payload = dict.insert(jwt.payload, "iss", dynamic.from(iss))

  Jwt(..jwt, payload: new_payload)
}

///
pub fn set_subject(jwt: Jwt(a), to sub: String) -> Jwt(a) {
  let new_payload = dict.insert(jwt.payload, "sub", dynamic.from(sub))

  Jwt(..jwt, payload: new_payload)
}

///
pub fn set_audience(jwt: Jwt(a), to aud: String) -> Jwt(a) {
  let new_payload = dict.insert(jwt.payload, "aud", dynamic.from(aud))

  Jwt(..jwt, payload: new_payload)
}

///
pub fn set_expiration(jwt: Jwt(a), to exp: Int) -> Jwt(a) {
  let new_payload = dict.insert(jwt.payload, "exp", dynamic.from(exp))

  Jwt(..jwt, payload: new_payload)
}

///
pub fn set_not_before(jwt: Jwt(a), to nbf: Int) -> Jwt(a) {
  let new_payload = dict.insert(jwt.payload, "nbf", dynamic.from(nbf))

  Jwt(..jwt, payload: new_payload)
}

///
pub fn set_issued_at(jwt: Jwt(a), to iat: Int) -> Jwt(a) {
  let new_payload = dict.insert(jwt.payload, "iat", dynamic.from(iat))

  Jwt(..jwt, payload: new_payload)
}

///
pub fn set_jwt_id(jwt: Jwt(a), to jti: String) -> Jwt(a) {
  let new_payload = dict.insert(jwt.payload, "jti", dynamic.from(jti))

  Jwt(..jwt, payload: new_payload)
}

///
pub fn set_payload_claim(
  jwt: Jwt(a),
  set claim: String,
  to value: Json,
) -> Jwt(a) {
  let new_payload = dict.insert(jwt.payload, claim, dynamic.from(value))

  Jwt(..jwt, payload: new_payload)
}

// HEADER ----------------------------------------------------------------------

pub fn set_header_claim(
  jwt: Jwt(a),
  set claim: String,
  to value: Json,
) -> Jwt(a) {
  let new_header = dict.insert(jwt.header, claim, dynamic.from(value))

  Jwt(..jwt, header: new_header)
}

// ENCODER ---------------------------------------------------------------------

pub fn to_string(jwt: Jwt(a)) -> String {
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

pub fn to_signed_string(jwt: Jwt(a), alg: Algorithm, secret: String) -> String {
  case alg {
    HS256 -> {
      let header_with_alg =
        dict.insert(jwt.header, "alg", dynamic.from("HS256"))
      let jwt_body =
        Jwt(..jwt, header: header_with_alg)
        |> to_string()

      let jwt_signature =
        jwt_body
        |> bit_array.from_string()
        |> crypto.hmac(crypto.Sha256, bit_array.from_string(secret))
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
    HS256 -> {
      data
      |> bit_array.from_string()
      |> crypto.hmac(crypto.Sha256, bit_array.from_string(secret))
      |> bit_array.base64_url_encode(False)
    }
  }
}

fn parts(
  jwt_string: String,
) -> Result(#(Header, Payload, option.Option(String)), JwtDecodeError) {
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
    -1 -> option.None
    v -> option.Some(v)
  }

  case exp {
    option.None -> Ok(Nil)
    option.Some(v) -> {
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
    -1 -> option.None
    v -> option.Some(v)
  }

  case nbf {
    option.None -> Ok(Nil)
    option.Some(v) -> {
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
