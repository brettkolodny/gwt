import birl
import gleam/dynamic/decode
import gleeunit
import gleeunit/should
import gwt
import gwt/hmac

const signing_secret = "gleam"

pub fn main() {
  gleeunit.main()
}

pub fn encode_decode_signed_jwt_test() {
  let jwt_string =
    gwt.new()
    |> gwt.set_subject("1234567890")
    |> gwt.set_audience("0987654321")
    |> hmac.to_signed_string(hmac.HS256, signing_secret)

  hmac.from_signed_string(jwt_string, "bad secret")
  |> should.be_error

  hmac.from_signed_string(jwt_string, "bad secret")
  |> should.equal(Error(gwt.InvalidSignature))

  let maybe_jwt = hmac.from_signed_string(jwt_string, signing_secret)
  maybe_jwt
  |> should.be_ok()

  let assert Ok(jwt) = hmac.from_signed_string(jwt_string, signing_secret)

  gwt.get_subject(jwt)
  |> should.equal(Ok("1234567890"))

  jwt
  |> gwt.get_payload_claim("aud", decode.string)
  |> should.equal(Ok("0987654321"))

  jwt
  |> gwt.get_payload_claim("iss", decode.string)
  |> should.equal(Error(gwt.MissingClaim))

  let jwt =
    gwt.new()
    |> gwt.set_subject("1234567890")
    |> gwt.set_audience("0987654321")

  jwt
  |> hmac.to_signed_string(hmac.HS256, signing_secret)
  |> hmac.from_signed_string(signing_secret)
  |> should.be_ok()

  jwt
  |> hmac.to_signed_string(hmac.HS384, signing_secret)
  |> hmac.from_signed_string(signing_secret)
  |> should.be_ok()

  jwt
  |> hmac.to_signed_string(hmac.HS512, signing_secret)
  |> hmac.from_signed_string(signing_secret)
  |> should.be_ok()
}

pub fn exp_jwt_test() {
  gwt.new()
  |> gwt.set_subject("1234567890")
  |> gwt.set_audience("0987654321")
  |> gwt.set_expiration(
    {
      birl.now()
      |> birl.to_unix()
    }
    + 100_000,
  )
  |> hmac.to_signed_string(hmac.HS256, signing_secret)
  |> hmac.from_signed_string(signing_secret)
  |> should.be_ok()

  gwt.new()
  |> gwt.set_subject("1234567890")
  |> gwt.set_audience("0987654321")
  |> gwt.set_expiration(0)
  |> hmac.to_signed_string(hmac.HS256, signing_secret)
  |> hmac.from_signed_string(signing_secret)
  |> should.equal(Error(gwt.TokenExpired))
}

pub fn nbf_jwt_test() {
  gwt.new()
  |> gwt.set_subject("1234567890")
  |> gwt.set_audience("0987654321")
  |> gwt.set_not_before(
    {
      birl.now()
      |> birl.to_unix()
    }
    + 100_000,
  )
  |> hmac.to_signed_string(hmac.HS256, signing_secret)
  |> hmac.from_signed_string(signing_secret)
  |> should.equal(Error(gwt.TokenNotValidYet))

  gwt.new()
  |> gwt.set_subject("1234567890")
  |> gwt.set_audience("0987654321")
  |> gwt.set_not_before(0)
  |> hmac.to_signed_string(hmac.HS256, signing_secret)
  |> hmac.from_signed_string(signing_secret)
  |> should.be_ok()
}
