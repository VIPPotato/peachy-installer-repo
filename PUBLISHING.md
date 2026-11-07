# Publishing signed catalogue updates

The `main` branch contains author-facing records and tooling. The generated `catalogue` branch is the public feed consumed by Peachy. A catalogue signature authenticates metadata; it does not qualify a package, loader or installation capability.

## Publish reviewed changes

1. Validate the source records with the commands in [Contributing](CONTRIBUTING.md).
2. Update `catalogue.json` with a revision greater than the published revision, a current UTC generation time and an expiry at most 31 days later. Keep the full interval inside the signing key's validity window. Reusing a revision requires identical index bytes; changing expiry or whitespace requires a new revision.
3. Review and commit only the intended source, documentation, tests and workflow changes to `main`. Keep payloads, generated output, private keys, workstation notes and evidence out of the commit.
4. The main-push workflow validates/builds on Linux, then runs Windows CNG and publication tests. The trusted Windows job builds a fresh snapshot, signs its exact index and verifies it using the public point before publication.
5. Check the workflow at that exact source commit. The publisher must report the generated feed commit and complete its remote member readback. A successful build or unsigned artifact is not a published signed feed.

A maintainer can also run the existing workflow against `main`:

```text
gh workflow run build-catalogue.yml --repo VIPPotato/peachy-installer-repo --ref main
```

An unchanged snapshot retains the existing feed commit even if a new randomized ECDSA signature was produced. Re-running the workflow does not extend the signed expiry. There is no scheduled renewal; maintainers must publish a new revision before expiry to keep the feed current.

## Key custody

The repository secret `PEACHY_CATALOGUE_SIGNING_KEY` holds a base64 Windows CNG P-256 private blob. Only this workflow's signing step receives it, on trusted default-branch input; its pull-request path does not receive the secret or run the publisher. The signer removes it from the process environment before starting Python helpers and never writes it to a local file or command argument.

The matching `catalogue-signing-policy.json` is public. It contains the public point, key identity, validity limits and initial revision/generation floors. Peachy's copy is compiled into the client; publishing a policy file cannot import new trust into an existing client.

The one-time `tools/provision_catalogue_key.ps1` command refuses automatic replacement when a policy or signing secret exists. It is not part of a build or routine publication. Its `-CheckOnly` mode exercises an ephemeral key without provisioning anything. Never print private material, commit it, add it to an artifact, or copy it into issue or CI logs.

A trusted workflow can use its signing key, so maintain access to `main`, workflow code and repository secrets carefully. This is an online signing key, not an offline root or hardware-backed custody scheme. Replacing or revoking it requires reviewed publisher changes and an independently delivered client-policy update. There is no automatic application updater or completed compromise-recovery procedure.

## Publication safeguards

The publisher requires a clean checkout at the exact source commit and checks that remote `main` still matches it. It signs only the validated generated membership, including entry, recipe and release hashes. Unexpected members, edited schemas, unsafe paths, absent signatures, expired candidates, revision rollback and same-revision changes are refused.

Publication appends to the existing feed history using a normal fast-forward push. It does not force-push, create a release or tag, publish application source, install a mod, or alter repository protections. A concurrent branch/source change is an error rather than permission to overwrite it.

Previous feed signatures may be checked at their historical validity time to compare original bytes and revision history. New candidates always need current-time validation. An expired previous feed cannot make an expired candidate acceptable.

On the client, network or validation failure retains the previous catalogue and selection. Cached data can remain readable after expiry, but it is display-only when current authentication fails. Offline clients cannot learn a revocation that has not reached them; local storage does not provide trusted time or prevent complete state deletion/replay.
