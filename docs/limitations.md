# Limitations

CloudTwin-R is a bounded research prototype, not an AWS IAM-compatible authorization engine.

- It implements a small subset of action/resource wildcard matching, selected condition operators, identity policies, and role trust policies.
- It does not model permissions boundaries, SCPs, session policies, resource policies, session tags, policy variables, MFA, source identity, VPC endpoint policies, or every IAM condition/operator.
- Missing context and unsupported conditions produce `UNKNOWN`; a matching explicit deny still produces `DENIED`.
- The graph traversal is bounded, currently focused on a principal-to-role hop, and can omit paths beyond the configured depth.
- AWS IAM simulator results are reference observations for the submitted simulation, not complete ground truth for an account.
- Validation is dry-run by default. Live mode requires an explicitly injected SDK client and must not be used by local tests.

The prototype never creates, modifies, or deletes AWS resources.
