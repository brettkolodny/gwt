// IMPORTS ---------------------------------------------------------------------

import gleam/dict.{type Dict}
import gleam/dynamic.{type Dynamic}
import gleam/json.{type Json}
import gleam/string
import gleam/option.{type Option} as o
import gleam/list
import gleam/int
import gleam/result

// TYPES -----------------------------------------------------------------------

type Header =
  Dict(String, Dynamic)

type Payload =
  Dict(String, Dynamic)

pub opaque type Jwt {
  Jwt(header: Header, payload: Payload, signature: Option(String))
}

pub type DecodeErrors {
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
}

// CONSTRUCTORS ----------------------------------------------------------------

///
pub fn new() -> Jwt {
  let header =
    dict.new()
    |> dict.insert("typ", dynamic.from("JWT"))
    |> dict.insert("alg", dynamic.from("none"))
  let payload = dict.new()

  Jwt(header, payload, o.None)
}

///
pub fn from_string(jwt_string: String) -> Result(Jwt, DecodeErrors) {
  let jwt_parts = string.split(jwt_string, ".")
  let maybe_header = list.at(jwt_parts, 0)
  let maybe_payload = list.at(jwt_parts, 1)
  // let maybe_signature = list.at(jwt_parts, 2)

  case maybe_header, maybe_payload {
    Error(Nil), _ -> Error(MissingHeader)
    _, Error(Nil) -> Error(MissingPayload)
    Ok(encoded_header), Ok(encoded_payload) -> {
      let header =
        encoded_header
        |> base64_url_safe_to_base64()
        |> base64_decode_()
        |> json.decode(dynamic.dict(dynamic.string, dynamic.dynamic))

      let payload =
        encoded_payload
        |> base64_url_safe_to_base64()
        |> base64_decode_()
        |> json.decode(dynamic.dict(dynamic.string, dynamic.dynamic))

      case header, payload {
        Error(_), _ -> Error(InvalidHeader)
        _, Error(_) -> Error(InvalidPayload)
        Ok(header), Ok(payload) -> Ok(Jwt(header, payload, o.None))
      }
    }
  }
}

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
pub fn get_claim(
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
pub fn set_issuer(jwt: Jwt, to iss: String) -> Jwt {
  let new_payload = dict.insert(jwt.payload, "iss", dynamic.from(iss))

  Jwt(..jwt, payload: new_payload)
}

///
pub fn set_subject(jwt: Jwt, to sub: String) -> Jwt {
  let new_payload = dict.insert(jwt.payload, "sub", dynamic.from(sub))

  Jwt(..jwt, payload: new_payload)
}

///
pub fn set_audience(jwt: Jwt, to aud: String) -> Jwt {
  let new_payload = dict.insert(jwt.payload, "aud", dynamic.from(aud))

  Jwt(..jwt, payload: new_payload)
}

///
pub fn set_expiration(jwt: Jwt, to exp: Int) -> Jwt {
  let new_payload = dict.insert(jwt.payload, "exp", dynamic.from(exp))

  Jwt(..jwt, payload: new_payload)
}

///
pub fn set_not_before(jwt: Jwt, to nbf: Int) -> Jwt {
  let new_payload = dict.insert(jwt.payload, "nbf", dynamic.from(nbf))

  Jwt(..jwt, payload: new_payload)
}

///
pub fn set_issued_at(jwt: Jwt, to iat: Int) -> Jwt {
  let new_payload = dict.insert(jwt.payload, "iat", dynamic.from(iat))

  Jwt(..jwt, payload: new_payload)
}

///
pub fn set_jwt_id(jwt: Jwt, to jti: String) -> Jwt {
  let new_payload = dict.insert(jwt.payload, "jti", dynamic.from(jti))

  Jwt(..jwt, payload: new_payload)
}

///
pub fn set_private_payload_claim(
  jwt: Jwt,
  set claim: String,
  to value: Json,
) -> Jwt {
  let new_payload = dict.insert(jwt.payload, claim, dynamic.from(value))

  Jwt(..jwt, payload: new_payload)
}

pub fn to_string(jwt: Jwt) -> String {
  let Jwt(header, payload, signature) = jwt

  let header_string =
    header
    |> dict_to_json_object()
    |> json.to_string()
    |> base64_encode_()
    |> base64_string_to_url_safe()

  let payload_string =
    payload
    |> dict_to_json_object()
    |> json.to_string()
    |> base64_encode_()
    |> base64_string_to_url_safe()

  case signature {
    o.Some(s) -> {
      let base64_signature =
        s
        |> base64_encode_()
        |> base64_string_to_url_safe()

      header_string <> "." <> payload_string <> "." <> base64_signature
    }
    o.None -> {
      header_string <> "." <> payload_string
    }
  }

  header_string <> "." <> payload_string
}

// UTILITIES -------------------------------------------------------------------

@external(erlang, "base64", "encode")
@external(javascript, "./ffi.mjs", "base64Encode")
fn base64_encode_(str: String) -> String

@external(erlang, "base64", "decode")
@external(javascript, "./ffi.mjs", "base64Decode")
fn base64_decode_(str: String) -> String

fn base64_string_to_url_safe(str: String) -> String {
  str
  |> string.replace("=", "")
  |> string.replace("+", "-")
  |> string.replace("/", "_")
}

fn base64_url_safe_to_base64(str: String) -> String {
  let padding =
    str
    |> string.length()
    |> int.modulo(4)
    |> result.unwrap(0)
    |> fn(x) {
      case x {
        0 -> 0
        _ -> 4 - x
      }
    }
    |> string.repeat("=", _)

  let encoded_string =
    str
    |> string.replace("-", "+")
    |> string.replace("_", "/")

  encoded_string <> padding
}

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
