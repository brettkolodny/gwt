// IMPORTS ---------------------------------------------------------------------

import gleam/dict.{type Dict}
import gleam/json.{type Json}

// TYPES -----------------------------------------------------------------------

type Header =
  Dict(String, Json)

type Body =
  Dict(String, Json)

pub opaque type Jwt {
  Jwt(header: Header, body: Body)
}

// CONSTRUCTORS ----------------------------------------------------------------

///
pub fn new() -> Jwt {
  let header = dict.insert(dict.new(), "alg", json.string("none"))
  let body = dict.new()

  Jwt(header, body)
}

///
pub fn set_issuer(jwt: Jwt, to iss: String) -> Jwt {
  let Jwt(header, body) = jwt
  let new_body = dict.insert(body, "iss", json.string(iss))

  Jwt(header, new_body)
}

///
pub fn set_subject(jwt: Jwt, to sub: String) -> Jwt {
  let Jwt(header, body) = jwt
  let new_body = dict.insert(body, "sub", json.string(sub))

  Jwt(header, new_body)
}

///
pub fn set_audience(jwt: Jwt, to aud: String) -> Jwt {
  let Jwt(header, body) = jwt
  let new_body = dict.insert(body, "aud", json.string(aud))

  Jwt(header, new_body)
}

///
pub fn set_expiration(jwt: Jwt, to exp: Int) -> Jwt {
  let Jwt(header, body) = jwt
  let new_body = dict.insert(body, "exp", json.int(exp))

  Jwt(header, new_body)
}

///
pub fn set_not_before(jwt: Jwt, to nbf: Int) -> Jwt {
  let Jwt(header, body) = jwt
  let new_body = dict.insert(body, "nbf", json.int(nbf))

  Jwt(header, new_body)
}

///
pub fn set_issued_at(jwt: Jwt, to iat: Int) -> Jwt {
  let Jwt(header, body) = jwt
  let new_body = dict.insert(body, "iat", json.int(iat))

  Jwt(header, new_body)
}

///
pub fn set_jwt_id(jwt: Jwt, to jti: String) -> Jwt {
  let Jwt(header, body) = jwt
  let new_body = dict.insert(body, "jti", json.string(jti))

  Jwt(header, new_body)
}
///
