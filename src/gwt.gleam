// IMPORTS ---------------------------------------------------------------------

import gleam/bit_array
import gleam/dict.{type Dict}
import gleam/dynamic.{type Dynamic}
import gleam/json.{type Json}
import gleam/string
import gleam/list
import gleam/result
import gleam/crypto

// TYPES -----------------------------------------------------------------------

type Header =
  Dict(String, Dynamic)

type Payload =
  Dict(String, Dynamic)

pub opaque type Jwt {
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
  NoAlg
}

pub type Algorithm {
  HS256
}

// CONSTRUCTORS ----------------------------------------------------------------

///
pub fn new() -> Jwt {
  let header =
    dict.new()
    |> dict.insert("typ", dynamic.from("JWT"))
    |> dict.insert("alg", dynamic.from("none"))
  let payload = dict.new()

  Jwt(header, payload)
}

///
pub fn from_string(jwt_string: String) -> Result(Jwt, JwtDecodeError) {
  let jwt_parts = string.split(jwt_string, ".")
  let maybe_header = list.at(jwt_parts, 0)
  let maybe_payload = list.at(jwt_parts, 1)
  // let maybe_signature = list.at(jwt_parts, 2)

  case maybe_header, maybe_payload {
    Error(Nil), _ -> Error(MissingHeader)
    _, Error(Nil) -> Error(MissingPayload)
    Ok(encoded_header), Ok(encoded_payload) -> {
      let header = {
        use res <- result.try(
          encoded_header
          |> bit_array.base64_url_decode()
          |> result.replace_error(InvalidHeader),
        )

        use res <- result.try(
          res
          |> bit_array.to_string()
          |> result.replace_error(InvalidHeader),
        )

        json.decode(res, dynamic.dict(dynamic.string, dynamic.dynamic))
        |> result.replace_error(InvalidHeader)
      }

      let payload = {
        use res <- result.try(
          encoded_payload
          |> bit_array.base64_url_decode()
          |> result.replace_error(InvalidHeader),
        )

        use res <- result.try(
          res
          |> bit_array.to_string()
          |> result.replace_error(InvalidHeader),
        )

        json.decode(res, dynamic.dict(dynamic.string, dynamic.dynamic))
        |> result.replace_error(InvalidHeader)
      }

      case header, payload {
        Error(_), _ -> Error(InvalidHeader)
        _, Error(_) -> Error(InvalidPayload)
        Ok(header), Ok(payload) -> Ok(Jwt(header, payload))
      }
    }
  }
}

///
pub fn from_signed_string(
  jwt_string: String,
  secret: String,
) -> Result(Jwt, JwtDecodeError) {
  let jwt_parts = string.split(jwt_string, ".")

  use signature <- result.try(
    list.at(jwt_parts, 2)
    |> result.replace_error(MissingSignature),
  )

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

  use alg <- result.try(
    dict.get(header, "alg")
    |> result.replace_error(NoAlg),
  )

  case dynamic.string(alg) {
    Ok("HS256") -> {
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
pub fn get_issuer(from jwt: Jwt) -> Result(String, Nil) {
  use issuer <- result.try(
    jwt.payload
    |> dict.get("iss"),
  )

  issuer
  |> dynamic.string()
  |> result.nil_error()
}

///
pub fn get_subject(from jwt: Jwt) -> Result(String, Nil) {
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
  from jwt: Jwt,
  claim claim: String,
  decoder decoder: fn(Dynamic) -> Result(a, List(dynamic.DecodeError)),
) -> Result(a, Nil) {
  use claim_value <- result.try(
    jwt.payload
    |> dict.get(claim),
  )

  claim_value
  |> decoder()
  |> result.nil_error()
}

///
pub fn set_payload_issuer(jwt: Jwt, to iss: String) -> Jwt {
  let new_payload = dict.insert(jwt.payload, "iss", dynamic.from(iss))

  Jwt(..jwt, payload: new_payload)
}

///
pub fn set_payload_subject(jwt: Jwt, to sub: String) -> Jwt {
  let new_payload = dict.insert(jwt.payload, "sub", dynamic.from(sub))

  Jwt(..jwt, payload: new_payload)
}

///
pub fn set_payload_audience(jwt: Jwt, to aud: String) -> Jwt {
  let new_payload = dict.insert(jwt.payload, "aud", dynamic.from(aud))

  Jwt(..jwt, payload: new_payload)
}

///
pub fn set_payload_expiration(jwt: Jwt, to exp: Int) -> Jwt {
  let new_payload = dict.insert(jwt.payload, "exp", dynamic.from(exp))

  Jwt(..jwt, payload: new_payload)
}

///
pub fn set_payload_not_before(jwt: Jwt, to nbf: Int) -> Jwt {
  let new_payload = dict.insert(jwt.payload, "nbf", dynamic.from(nbf))

  Jwt(..jwt, payload: new_payload)
}

///
pub fn set_payload_issued_at(jwt: Jwt, to iat: Int) -> Jwt {
  let new_payload = dict.insert(jwt.payload, "iat", dynamic.from(iat))

  Jwt(..jwt, payload: new_payload)
}

///
pub fn set_payload_jwt_id(jwt: Jwt, to jti: String) -> Jwt {
  let new_payload = dict.insert(jwt.payload, "jti", dynamic.from(jti))

  Jwt(..jwt, payload: new_payload)
}

///
pub fn set_payload_claim(jwt: Jwt, set claim: String, to value: Json) -> Jwt {
  let new_payload = dict.insert(jwt.payload, claim, dynamic.from(value))

  Jwt(..jwt, payload: new_payload)
}

// HEADER ----------------------------------------------------------------------

pub fn set_header_claim(jwt: Jwt, set claim: String, to value: Json) -> Jwt {
  let new_header = dict.insert(jwt.header, claim, dynamic.from(value))

  Jwt(..jwt, header: new_header)
}

// ENCODER ---------------------------------------------------------------------

pub fn to_string(jwt: Jwt) -> String {
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

pub fn to_signed_string(jwt: Jwt, alg: Algorithm, secret: String) -> String {
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
      _ -> panic
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
