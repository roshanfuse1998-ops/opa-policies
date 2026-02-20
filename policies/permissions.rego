package permissions

default allow = false

# ----------------------------------
# Case 1: config is provided
# ----------------------------------
allow if{
  input.config != null

  users := data.permissions.llm_configs[input.config][input.action[_]]
  users[_] == input.user_id
}

# ----------------------------------
# Case 2: config is NULL + read_all
# ----------------------------------
allow if{
  input.config == null
  input.action[_] == "read_all"

  some cfg
  users := data.permissions.llm_configs[cfg]["read_all"]
  users[_] == input.user_id
}
