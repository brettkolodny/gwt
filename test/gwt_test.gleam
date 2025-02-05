import birl
import gleam/dynamic/decode
import gleam/json
import gleeunit
import gleeunit/should
import gwt

const signing_secret = "gleam"

pub fn main() {
  gleeunit.main()
}

pub fn encode_decode_unsigned_jwt_test() {
  let jwt_string =
    gwt.new()
    |> gwt.set_subject("1234567890")
    |> gwt.set_audience("0987654321")
    |> gwt.set_not_before(1_704_043_160)
    |> gwt.set_expiration(1_704_046_160)
    |> gwt.set_jwt_id("2468")
    |> gwt.to_string()

  let maybe_jwt = gwt.from_string(jwt_string)

  maybe_jwt
  |> should.be_ok()

  let assert Ok(jwt) = gwt.from_string(jwt_string)

  gwt.get_subject(jwt)
  |> should.equal(Ok("1234567890"))

  jwt
  |> gwt.get_payload_claim("aud", decode.string)
  |> should.equal(Ok("0987654321"))

  jwt
  |> gwt.get_payload_claim("iss", decode.string)
  |> should.equal(Error(gwt.MissingClaim))
}

pub fn encode_decode_signed_jwt_test() {
  let jwt_string =
    gwt.new()
    |> gwt.set_subject("1234567890")
    |> gwt.set_audience("0987654321")
    |> gwt.to_signed_string(gwt.HS256, signing_secret)

  gwt.from_signed_string(jwt_string, "bad secret")
  |> should.be_error

  gwt.from_signed_string(jwt_string, "bad secret")
  |> should.equal(Error(gwt.InvalidSignature))

  let maybe_jwt = gwt.from_signed_string(jwt_string, signing_secret)
  maybe_jwt
  |> should.be_ok()

  let assert Ok(jwt) = gwt.from_signed_string(jwt_string, signing_secret)

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
  |> gwt.to_signed_string(gwt.HS256, signing_secret)
  |> gwt.from_signed_string(signing_secret)
  |> should.be_ok()

  jwt
  |> gwt.to_signed_string(gwt.HS384, signing_secret)
  |> gwt.from_signed_string(signing_secret)
  |> should.be_ok()

  jwt
  |> gwt.to_signed_string(gwt.HS512, signing_secret)
  |> gwt.from_signed_string(signing_secret)
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
  |> gwt.to_signed_string(gwt.HS256, signing_secret)
  |> gwt.from_signed_string(signing_secret)
  |> should.be_ok()

  gwt.new()
  |> gwt.set_subject("1234567890")
  |> gwt.set_audience("0987654321")
  |> gwt.set_expiration(0)
  |> gwt.to_signed_string(gwt.HS256, signing_secret)
  |> gwt.from_signed_string(signing_secret)
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
  |> gwt.to_signed_string(gwt.HS256, signing_secret)
  |> gwt.from_signed_string(signing_secret)
  |> should.equal(Error(gwt.TokenNotValidYet))

  gwt.new()
  |> gwt.set_subject("1234567890")
  |> gwt.set_audience("0987654321")
  |> gwt.set_not_before(0)
  |> gwt.to_signed_string(gwt.HS256, signing_secret)
  |> gwt.from_signed_string(signing_secret)
  |> should.be_ok()
}

pub fn custom_payload_test() {
  let user_data = json.object([#("age", json.int(27))])

  let assert Ok(jwt) =
    gwt.new()
    |> gwt.set_payload_claim("email", json.string("lucy@gleam.run"))
    |> gwt.set_payload_claim("data", user_data)
    |> gwt.to_string()
    |> gwt.from_string()

  jwt
  |> gwt.get_payload_claim("email", decode.string)
  |> should.equal(Ok("lucy@gleam.run"))

  let data_decoder = {
    use age <- decode.field("age", decode.int)
    decode.success(age)
  }

  jwt
  |> gwt.get_payload_claim("data", data_decoder)
  |> should.equal(Ok(27))
}
