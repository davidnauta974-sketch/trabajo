package main

import rego.v1

instructions := input if { is_array(input) }

final_stage := max({instruction.Stage | some instruction in instructions; instruction.Cmd == "from"})

users := [index |
    some index, instruction in instructions
    instruction.Cmd == "user"
    instruction.Stage == final_stage
]

deny contains "DF001: la etapa final debe declarar USER con UID numerico distinto de cero" if {
    count(users) == 0
}

deny contains "DF002: el ultimo USER de la etapa final no puede ser root ni un nombre sin UID verificable" if {
    count(users) > 0
    last := max(users)
    user := instructions[last].Value[0]
    not regex.match(`^[1-9][0-9]*(:[1-9][0-9]*)?$`, user)
}

instruction_keys(instruction) := keys if {
    instruction.Cmd == "env"
    keys := {split(value, "=")[0] | some index, value in instruction.Value; index % 3 == 0}
} else := {split(instruction.Value[0], "=")[0]} if {
    instruction.Cmd == "arg"
}

deny contains sprintf("DF003: %s sensible %s no debe incorporar secretos en una imagen", [upper(instruction.Cmd), key]) if {
    some instruction in instructions
    instruction.Cmd in {"env", "arg"}
    some key in instruction_keys(instruction)
    regex.match(`(?i)(password|passwd|token|secret|api[_-]?key|access[_-]?key|private[_-]?key|database_url|credential)`, key)
    # Build-time secrets must use BuildKit secret mounts, not ENV or ARG.
}
