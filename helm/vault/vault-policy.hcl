# Policy pour backend
path "secret/data/backend/*" {
  capabilities = ["read"]
}

path "secret/data/keycloak/admin" {
  capabilities = ["read"]
}

# Policy pour frontend
path "secret/data/frontend/*" {
  capabilities = ["read"]
}