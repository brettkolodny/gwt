import gleeunit

@target(javascript)
import gleam/javascript/promise
@target(javascript)
import gleeunit/should
@target(javascript)
import gwt
@target(javascript)
import gwt/javascript/rsa

pub const pem_private_key = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDBMwjEz1dAdJMj
tYrF0xyYka1EOlEFGTi8WzDYx+JVlcQHN8VjdHKdXodC29DeZsuGh8DdQzpLVX2N
0hs+Q/E3Mt2JWQidEExIj2ov9Ib3WcpdY9byuotfm4zzheCNTmZHI6AkfWaTo2So
iyoH83CkSpydZqTq++Azei5JOpnVt3Sl7GhylTch4BrEzP7x6mSCjkoiM7HLggSA
gwGWN+JhEkwQh81o2RL2bX79LyN1gwKBVyYO0KFPwXWteg4wcjDNdn5t9Cu8WOeD
+1lGB1Ymg6abQZRJOyYVuxosleSiv3VogM9jqSMSwiZmzPCuPVhA5WsfKB3sAeI4
Oy2xtqrTAgMBAAECggEAHxwRqGdevGFJJDHic7Jn42Vpyhe93h1Oln30oqOlHXTt
SOBBJ5+jqRWEoE53Fqjk0vffJYHizCiq/AA+JMuZ9vJ429n7Whc6wWBej/RHG2NZ
A6rE/Pbu5GlOzBPdscNTEtd4vQd4UgO4fK9UCE258KqXB310xuXiF0fwVhhalyAY
tVsi5Ww2yVCG/0xM4WvOZe3eHRf7nHhdTvwHJ/BtVHQfljRvsG4lIFyn9z+pcEIT
ydH2Cs/j/CTrNQ+tt9xSyE+uFsgYtUKAjv+mC93TkAUU4CpKdeb1Q+SNwzK3NMuP
zVVQlp+ZGmOIdZc1iAPMfmb/hX69kD3rDzuiIjps8QKBgQDor0R0KmfOkdx3NDLu
3NQk2dsFTiMRiLCmhO5V+41wpDzng4Aaf6vjjtX2wLusrX7ZIu+ZSONNyWd85fm1
i3mBDwOxQHRASqb2dUCv/ExFRxyCQRvoNO1Wj2YzW5q/jq8bk/ms4G1faD1XSW0A
rdEhMwJ6LME7I/8KbH7zJaPZiwKBgQDUjuf9lWntp/lYg2Xg4c/hDqb+Nnq3MtUC
4jK8Pw0xsrTvFVBU1vApWhwGMEhEZfmh3P3Pdxzgu5Oy0XlwHRMEAKm2iImQDb60
vR5WoHU9UWb5h6buOkIjY9cnZgOBFBgAiYSKgqWP8oCqHhYXdv2C23DtllWi+1rM
BtxWi3pM2QKBgQDJgTcj7rFVOAYYCVFugDkL7Mp67q75+UkZ/Ba2yZE0klbYG45t
5FDEUadD+KbOpLUsb8/VDEUk0R1ZEYRNzwqbVJhbATlrj/rFhsdNYI3glPPAbYgw
cN10z9yu7061Q2ir1lsrdnPhYtF0bPcD1oM8YANuMKHqiILO0SSjht49fwKBgEHp
NmLZzAkXxyf9RsAfBXkCNCIr/o2EQ60rOxRIcOzyP0zLzSchp0MLYBlDK4WaIXhh
sIp+owPE5p3SetebDGR3WCjz2cRDntkos5mlE/W5ojbKK6c/hXa35OWgqoGCG5c/
DUxuCqzCQ8d8oNkR2raTGUdzEIcDbjpJ/lUP1xKxAoGBALPo0YGQDidFPhaHZY9g
ZvIygzb46HDa5cBFMZShdfx7q4CpGkzUbmDSWf5B2PxYR+6GqwR5u4ohiq4Dad5X
mp3uDyI91nYLO/SafkwTQ2CCXy6zUKQ+Uc8+piAubeQXz1Y6jwCfDyJsJQjOMS0O
sulfbFJ8acGEVNn7TFeeRfhA
-----END PRIVATE KEY-----"

pub const pem_public_key = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwTMIxM9XQHSTI7WKxdMc
mJGtRDpRBRk4vFsw2MfiVZXEBzfFY3RynV6HQtvQ3mbLhofA3UM6S1V9jdIbPkPx
NzLdiVkInRBMSI9qL/SG91nKXWPW8rqLX5uM84XgjU5mRyOgJH1mk6NkqIsqB/Nw
pEqcnWak6vvgM3ouSTqZ1bd0pexocpU3IeAaxMz+8epkgo5KIjOxy4IEgIMBljfi
YRJMEIfNaNkS9m1+/S8jdYMCgVcmDtChT8F1rXoOMHIwzXZ+bfQrvFjng/tZRgdW
JoOmm0GUSTsmFbsaLJXkor91aIDPY6kjEsImZszwrj1YQOVrHygd7AHiODstsbaq
0wIDAQAB
-----END PUBLIC KEY-----
"

pub const invalid_pem_public_key = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwTMIxM9XQHSTI7WKxdMc
mJGtRDpRBRk4vFsw2MfiVZXEBzfFY3RynV6HQtvQ3mbLhofA3UM6S1V9jdIbPkPx
NzLdiVkInRBMSI9qL/SG91nKXWPW8rqLX5uM84XgjU5mRyOgJH1mk6NkqIsqB/Nw
pEqcnWak6vvgM3ouSTqZ1bd0pexocpU3IeAaxMz+8epkgo5KIjOxy4IEgIMBljfi
YRJMEIfNaNkS9m1+/S8jdYMCgVcmDtChT8F1rXoOMHIwzXZ+bfQrvFjng/tZRgdW
JoOmm0GUSTsmFbsaLJXkor91aIDPY6kjEsImZszwrj1YQOVrHygd7AHiODstsbaq
0wIDAQAA
-----END PUBLIC KEY-----
"

pub fn main() {
  gleeunit.main()
}

@target(javascript)
pub fn load_public_key_test() {
  use key <- promise.await(rsa.pem_to_rsa_public_key(pem_public_key, rsa.RS256))

  key
  |> should.be_ok()
  |> promise.resolve()
}

@target(javascript)
pub fn load_private_key_test() {
  use key <- promise.await(rsa.pem_to_rsa_private_key(
    pem_private_key,
    rsa.RS256,
  ))

  key
  |> should.be_ok()
  |> promise.resolve()
}

@target(javascript)
pub fn sign_and_verify_test() {
  use maybe_private_key <- promise.await(rsa.pem_to_rsa_private_key(
    pem_private_key,
    rsa.RS256,
  ))
  let assert Ok(private_key) = maybe_private_key

  use jwt_str <- promise.await(
    gwt.new()
    |> gwt.set_subject("1234567890")
    |> gwt.set_audience("0987654321")
    |> rsa.to_signed_string(private_key),
  )

  use maybe_public_key <- promise.await(rsa.pem_to_rsa_public_key(
    pem_public_key,
    rsa.RS256,
  ))
  let assert Ok(public_key) = maybe_public_key

  use maybe_jwt <- promise.await(rsa.from_signed_string(jwt_str, public_key))
  maybe_jwt
  |> should.be_ok()
  |> promise.resolve()
}

@target(javascript)
pub fn invalid_public_key_fails_test() {
  use maybe_private_key <- promise.await(rsa.pem_to_rsa_private_key(
    pem_private_key,
    rsa.RS256,
  ))
  let assert Ok(private_key) = maybe_private_key

  use jwt_str <- promise.await(
    gwt.new()
    |> gwt.set_subject("1234567890")
    |> gwt.set_audience("0987654321")
    |> rsa.to_signed_string(private_key),
  )

  use maybe_public_key <- promise.await(rsa.pem_to_rsa_public_key(
    invalid_pem_public_key,
    rsa.RS256,
  ))
  let assert Ok(public_key) = maybe_public_key

  use maybe_jwt <- promise.await(rsa.from_signed_string(jwt_str, public_key))
  maybe_jwt
  |> should.be_error()
  |> promise.resolve()
}
