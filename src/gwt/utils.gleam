import gleam/dict.{type Dict}
import gleam/json.{type Json}

@internal
pub fn dict_to_json_object(d: Dict(String, Json)) -> Json {
  let key_value_list = {
    use acc, key, value <- dict.fold(d, [])
    [#(key, value), ..acc]
  }

  json.object(key_value_list)
}
