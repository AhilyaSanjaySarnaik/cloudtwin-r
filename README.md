# CloudTwin-R

CloudTwin-R is a Ruby 3.3+ research prototype for bounded, explainable IAM counterfactual analysis using synthetic JSON fixtures.

It separates identity authorization from role trust authorization, reports `ALLOWED`, `DENIED`, or `UNKNOWN`, and gives explicit denies precedence. `UNKNOWN` means required evidence is missing or a condition is unsupported; it is not a synonym for known implicit deny.

## Usage

```sh
bundle install
bundle exec ruby -Ilib:test test/test_cloudtwin.rb
bin/cloudtwin compare fixtures/baseline.json fixtures/changed_policy.json arn:aws:iam::111122223333:user/researcher
bin/cloudtwin validate fixtures/validation_scenario.json
```

`validate` is dry-run by default. `--live` is an opt-in reference call to `SimulateCustomPolicy`; it requires an injected client in library use and never creates AWS resources. Local tests use no credentials and do not call AWS.

## Scope

This is not full IAM compatibility. Unsupported features and missing context are documented in [docs/limitations.md](docs/limitations.md), with open research questions in [docs/research_questions.md](docs/research_questions.md). The existing [AWS validation workflow](.github/workflows/aws-validation.yml) and its OIDC configuration are preserved.
