package permissions

default allow = false

allow if{
  users := data.llm_configs_use.llm_configs[input.config][input.action[_]]
  users[_] == input.user_id
}
