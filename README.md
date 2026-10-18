# fleet-ops-policy

Policy as code for the Fleet Ops demo. Each Permit environment follows one branch: **Development** follows
`main`, **Production** follows `release/2026.10`.

- `terraform/`: the schema (resource types, roles and what they may do, relations, derivations, attribute
  groups). CI plans it on every pull request and applies it on every push: `main` to Development,
  `release/*` to Production. State lives in HCP Terraform, one workspace per environment.
- `ci/permit_snapshot.py`: Permit can't undo a delete, so before each apply CI saves the role assignments
  and relationships the plan deletes, and when a push reverts a commit, CI restores what that commit's run
  saved.
- `custom/`: custom Rego rules (tenant isolation, fleet rules) and their tests, which Permit's PDP loads
  from this branch. CI runs `opa test` on every pull request.
- Everything else is Permit's generated policy.
