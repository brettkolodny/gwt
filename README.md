# gwt

Encode and decode JWTs.

[![Package Version](https://img.shields.io/hexpm/v/gwt)](https://hex.pm/packages/gwt)
[![Hex Docs](https://img.shields.io/badge/hex-docs-ffaff3)](https://hexdocs.pm/gwt/)

## Quickstart

```gleam
import gwt.{type Jwt, type Verified, type Unverified}

pub fn main() {
  let jwt_builder =
    gwt.new()
    |> gwt.set_subject("1234567890")
    |> gwt.set_audience("0987654321")
    |> gwt.set_not_before(1_704_043_160)
    |> gwt.set_expiration(1_704_046_160)
    |> gwt.set_jwt_id("2468")

  let jwt_without_signature = gwt.to_string(jwt_builder)
  let jwt_with_signature = gwt.to_signed_string(jwt_builder, gwt.HS256, "lucy")

  let assert Ok(unverified_jwt) =
    jwt_without_signature
    |> gwt.from_string()

  let assert Ok(verified_jwt) =
    jwt_with_signature
    |>gwt.from_signed_string("lucy")
}
```

## Installation

```sh
gleam add gwt
```

The documentation can be found at <https://hexdocs.pm/gwt>.
