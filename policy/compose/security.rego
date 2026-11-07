package main

import rego.v1

# A numeric non-zero UID is required. Names alone do not prove the image UID.
non_root(user) if {
    regex.match(`^[1-9][0-9]*(:[1-9][0-9]*)?$`, sprintf("%v", [user]))
}

deny contains sprintf("PRIV001: servicio %s debe declarar UID numerico distinto de cero", [name]) if {
    some name, service in input.services
    not non_root(object.get(service, "user", ""))
}

deny contains sprintf("PRIV002: servicio %s no puede usar privileged", [name]) if {
    some name, service in input.services
    object.get(service, "privileged", false) == true
}

deny contains sprintf("PRIV003: servicio %s no puede montar el socket Docker", [name]) if {
    some name, service in input.services
    some mount in object.get(service, "volumes", [])
    contains(sprintf("%v", [mount]), "docker.sock")
}

sensitive(key) if {
    regex.match(`(?i)(password|passwd|token|secret|api[_-]?key|access[_-]?key|private[_-]?key|database_url|connection_string|credential)`, key)
}

deny contains "SEC002: una configuracion contiene una URL con credenciales incorporadas" if {
    walk(input.services, [_, value])
    is_string(value)
    regex.match(`(?i)[a-z][a-z0-9+.-]*://[^/@:\s]+:[^/@\s]+@`, value)
}

external_reference(value) if {
    is_string(value)
    # Mandatory expansion only: a plaintext default such as ${TOKEN:-abc} is rejected.
    regex.match(`^\$\{[A-Z][A-Z0-9_]*:\?[^}]+\}$`, value)
}

file_reference(key, value) if {
    endswith(upper(key), "_FILE")
    is_string(value)
    startswith(value, "/run/secrets/")
    count(value) > count("/run/secrets/")
}

safe_secret(key, value) if { external_reference(value) }
safe_secret(key, value) if { file_reference(key, value) }

environment_entry(service) := entries if {
    env := object.get(service, "environment", {})
    is_object(env)
    entries := {[key, value] | some key, value in env}
} else := entries if {
    env := object.get(service, "environment", [])
    is_array(env)
    entries := {[key, value] |
        some entry in env
        pieces := split(entry, "=")
        key := pieces[0]
        value := concat("=", array.slice(pieces, 1, count(pieces)))
    }
}

deny contains sprintf("SEC001: servicio %s define %s sin referencia segura", [name, key]) if {
    some name, service in input.services
    some pair in environment_entry(service)
    key := pair[0]
    sensitive(key)
    not safe_secret(key, pair[1])
}

# Both container target and published host ports must be >= 1024.
port_values(port) := values if {
    is_string(port)
    pieces := split(split(port, "/")[0], ":")
    count(pieces) == 1
    values := [pieces[0]]
} else := values if {
    is_string(port)
    pieces := split(split(port, "/")[0], ":")
    count(pieces) >= 2
    values := array.slice(pieces, count(pieces)-2, count(pieces))
} else := [sprintf("%v", [port])] if {
    is_number(port)
} else := values if {
    is_object(port)
    values := [sprintf("%v", [object.get(port, "target", "")])]
    not object.get(port, "published", false)
} else := values if {
    is_object(port)
    object.get(port, "published", false)
    values := [sprintf("%v", [port.target]), sprintf("%v", [port.published])]
}

valid_port(value) if {
    regex.match(`^[0-9]+(-[0-9]+)?$`, value)
    parts := split(value, "-")
    every part in parts {
        number := to_number(part)
        number >= 1024
        number <= 65535
    }
    to_number(parts[0]) <= to_number(parts[count(parts)-1])
}

deny contains sprintf("NET001: servicio %s usa un puerto privilegiado o no verificable", [name]) if {
    some name, service in input.services
    some port in object.get(service, "ports", [])
    values := port_values(port)
    some value in values
    not valid_port(value)
}

deny contains sprintf("NET002: servicio %s usa una sintaxis de puerto no admitida", [name]) if {
    some name, service in input.services
    some port in object.get(service, "ports", [])
    not port_values(port)
}
