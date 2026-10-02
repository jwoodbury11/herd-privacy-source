# Shipping Herd

Deploy the component being changed. Web and shared-service changes do not require an iPhone build, a scheduler deployment, a new evaluator image, a full test suite, or a signed all-platform release package. There are no mandatory GitHub release checks.

Use judgment to test the behavior at risk, reuse checks already completed on unchanged inputs, and verify the result in the running product. Commit and push the change so the deployed source is recoverable. Use the existing Sites project for web deployments. Upload to TestFlight when shipping native changes.

Keep existing runtime credentials, evaluator keys, attestation pins, account isolation, and ballot privacy intact. Their configuration can be reused across ordinary deployments. The public deployment record identifies the deployed source separately from the historical signed trust configuration. The independent runtime monitor continues checking evaluator attestation, response-log continuity, and App Clip association; web releases do not wait on an artifact audit or monitor stabilization window.

The tools under `release/` remain available to inspect historical evidence or make an intentional trust change. They are not a required publishing pipeline. Historical runbooks and audits do not impose release gates.
