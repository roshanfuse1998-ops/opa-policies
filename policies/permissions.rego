package permissions

default allow = false

allow if{
  users := data.permissions.llm_configs[input.config][input.action[_]]
  users[_] == input.user_id
}
