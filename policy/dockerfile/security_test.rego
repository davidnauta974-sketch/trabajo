package main

import rego.v1

test_explicit_non_root if { result := deny with input as [{"Cmd":"from","Stage":0,"Value":["scratch"]},{"Cmd":"user","Stage":0,"Value":["10001:10001"]}]; count(result) == 0 }
test_missing_final_user if { result := deny with input as [{"Cmd":"from","Stage":0,"Value":["scratch"]}]; count(result) == 1 }
test_user_zero if { result := deny with input as [{"Cmd":"from","Stage":0,"Value":["scratch"]},{"Cmd":"user","Stage":0,"Value":["0"]}]; count(result) == 1 }
test_later_root_overrides_nonroot if { result := deny with input as [{"Cmd":"from","Stage":0,"Value":["scratch"]},{"Cmd":"user","Stage":0,"Value":["10001"]},{"Cmd":"user","Stage":0,"Value":["root"]}]; count(result) == 1 }
test_nonroot_builder_does_not_protect_runtime if { result := deny with input as [{"Cmd":"from","Stage":0,"Value":["golang"]},{"Cmd":"user","Stage":0,"Value":["10001"]},{"Cmd":"from","Stage":1,"Value":["scratch"]}]; count(result) == 1 }
test_secret_arg_rejected if { result := deny with input as [{"Cmd":"from","Stage":0,"Value":["scratch"]},{"Cmd":"arg","Stage":0,"Value":["API_TOKEN"]},{"Cmd":"user","Stage":0,"Value":["10001"]}]; count(result) == 1 }
test_secret_second_env_rejected if { result := deny with input as [{"Cmd":"from","Stage":0,"Value":["scratch"]},{"Cmd":"env","Stage":0,"Value":["APP_MODE","test","=","API_KEY","ficticio","="]},{"Cmd":"user","Stage":0,"Value":["10001"]}]; count(result) == 1 }
