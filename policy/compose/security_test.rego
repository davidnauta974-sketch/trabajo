package main

import rego.v1

safe := {"services": {"web": {"user": "10001:10001", "environment": {"API_KEY_FILE": "/run/secrets/api_key"}, "ports": ["127.0.0.1:8080:8080"]}}}

test_secure_compose if { result := deny with input as safe; count(result) == 0 }
test_root_rejected if { result := deny with input as {"services": {"web": {"user": "0:0"}}}; count(result) == 1 }
test_missing_user_rejected if { result := deny with input as {"services": {"web": {}}}; count(result) == 1 }
test_named_root_rejected if { result := deny with input as {"services": {"web": {"user": "root"}}}; count(result) == 1 }
test_named_user_unverifiable if { result := deny with input as {"services": {"web": {"user": "app"}}}; count(result) == 1 }
test_numeric_uid_accepted if { result := deny with input as {"services": {"web": {"user": 10001}}}; count(result) == 0 }
test_secret_map_rejected if { result := deny with input as {"services": {"web": {"user":"10001", "environment":{"PASSWORD":"ficticio"}}}}; count(result) == 1 }
test_secret_list_rejected if { result := deny with input as {"services": {"web": {"user":"10001", "environment":["TOKEN=ficticio"]}}}; count(result) == 1 }
test_inherited_secret_rejected if { result := deny with input as {"services": {"web": {"user":"10001", "environment":["TOKEN"]}}}; count(result) == 1 }
test_default_secret_rejected if { result := deny with input as {"services": {"web": {"user":"10001", "environment":{"TOKEN":"${TOKEN:-ficticio}"}}}}; count(result) == 1 }
test_required_reference_accepted if { result := deny with input as {"services": {"web": {"user":"10001", "environment":{"TOKEN":"${TOKEN:?obligatorio}"}}}}; count(result) == 0 }
test_port_80_rejected if { result := deny with input as {"services":{"web":{"user":"10001","ports":["8080:80"]}}}; count(result) == 1 }
test_host_port_80_rejected if { result := deny with input as {"services":{"web":{"user":"10001","ports":["80:8080"]}}}; count(result) == 1 }
test_long_port_rejected if { result := deny with input as {"services":{"web":{"user":"10001","ports":[{"target":8080,"published":"443"}]}}}; count(result) == 1 }
test_range_port_rejected if { result := deny with input as {"services":{"web":{"user":"10001","ports":["900-1100:8080-8280"]}}}; count(result) == 1 }
test_ipv6_accepted if { result := deny with input as {"services":{"web":{"user":"10001","ports":["[::1]:8080:8080"]}}}; count(result) == 0 }
test_dynamic_port_rejected if { result := deny with input as {"services":{"web":{"user":"10001","ports":["${PORT}:8080"]}}}; count(result) == 1 }
test_privileged_rejected if { result := deny with input as {"services":{"web":{"user":"10001","privileged":true}}}; count(result) == 1 }
test_socket_rejected if { result := deny with input as {"services":{"web":{"user":"10001","volumes":["/var/run/docker.sock:/var/run/docker.sock"]}}}; count(result) == 1 }
test_url_credentials_rejected if { result := deny with input as {"services":{"web":{"user":"10001","labels":{"connection":"postgres://demo:ficticio@db/app"}}}}; count(result) == 1 }
