# Policy pour backend
path "secret/data/backend/*" {
  capabilities = ["read"]
}

# Policy pour frontend
path "secret/data/frontend/*" {
  capabilities = ["read"]
}