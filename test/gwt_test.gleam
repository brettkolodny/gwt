import gleeunit
import gleeunit/should
import gleam/dynamic
import gwt

// const signing_secret = "gleam"

pub fn main() {
  gleeunit.main()
}

pub fn encode_unsigned_jwt_test() {
  let jwt_string =
    gwt.new()
    |> gwt.set_subject("1234567890")
    |> gwt.set_audience("0987654321")
    |> gwt.set_not_before(1_704_043_160)
    |> gwt.set_expiration(1_704_046_160)
    |> gwt.set_jwt_id("2468")
    |> gwt.to_string()

  jwt_string
  |> should.equal(
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmJmIjoxNzA0MDQzMTYwLCJqdGkiOiIyNDY4IiwiZXhwIjoxNzA0MDQ2MTYwLCJhdWQiOiIwOTg3NjU0MzIxIn0",
  )
}

pub fn decode_unsigned_jwt_test() {
  let jwt_string =
    gwt.new()
    |> gwt.set_subject("1234567890")
    |> gwt.set_audience("0987654321")
    |> gwt.set_not_before(1_704_043_160)
    |> gwt.set_expiration(1_704_046_160)
    |> gwt.set_jwt_id("2468")
    |> gwt.to_string()

  let assert Ok(jwt) = gwt.from_string(jwt_string)

  gwt.get_subject(jwt)
  |> should.equal(Ok("1234567890"))

  jwt
  |> gwt.get_claim("aud", dynamic.string)
  |> should.equal(Ok("0987654321"))

  jwt
  |> gwt.get_claim("iss", dynamic.string)
  |> should.equal(Error(Nil))
}
