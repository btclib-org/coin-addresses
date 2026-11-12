# Security policy

## Reporting a vulnerability

If you have found a security vulnerability, please do not open a GitHub
issue: an issue is public from the moment it is filed, and so is the
window between filing it and a fix being released.

Report it privately instead, by
[opening a security advisory](https://github.com/btclib-org/coin-addresses/security/advisories/new).
Only the maintainers can see it, the discussion stays private until an
advisory is published, and a CVE can be requested from it if the
vulnerability warrants one.

If you have no GitHub account, or would rather not use it for this,
responsible disclosure by email to *security at btclib dot org* is
equally welcome.

A report is acknowledged within 7 days, and a fix or a published advisory
follows within 90 days.

A report triaged as easy to rediscover is fixed as soon as possible, since
anyone can find it in the meantime, and its advisory is published with the
fix.

## What belongs here

Everything this package does: deriving the address a coin gives a public
key, validating an address, and the distributions published to PyPI and
their provenance. A validator that accepts an address its specification
refuses, or an address that differs from the one its specification
derives, is a vulnerability to report here. So is a refusal that prints
a secret: section 7's
[*A refusal carries no secret*](https://github.com/btclib-org/.github#a-refusal-carries-no-secret)
says what a refusal may print.

What is above an address is not here: a transaction, a signature or a
wallet is the business of another library. Report a flaw wherever you
found it, though: routing a report is the maintainers' job, not the
reporter's, and a doubt about which project owns a flaw is not a reason
to keep it to yourself.

## Security review

No security review has been done yet.

## Supported versions

Only the latest release is supported. Versions are calendar-based
(`YYYY.M.D`), a fix is published as a new release, and nothing is
backported.

Wheels and sdist are published to PyPI with PEP 740 attestations, through
a workflow that no long-lived token can authenticate for (PyPI Trusted
Publishing), so a distribution can be traced back to the workflow run and
the commit it was built from.

The same files are attached to the GitHub release, and those copies carry
a build provenance attestation of their own, signed in the run that built
them:

```shell
signer=btclib-org/.github/.github/workflows/reusable-build.yml
id=$(gh api repos/btclib-org/coin-addresses --jq .id)
cert='.[].verificationResult.signature.certificate'
```

```shell
gh attestation verify <file> --owner btclib-org \
  --signer-workflow "${signer:?}" \
  --source-ref refs/tags/v<version> --format json \
  --jq "${cert:?}.sourceRepositoryIdentifier" | grep -qx "${id:?}"
```

The exit code is `0` only where a verified attestation names this
repository. The repository is compared by its id, which a rename keeps:
`--repo` compares the current name and refuses every release signed
before a rename.

`<file>` is a distribution file from the release.

`--signer-workflow` is what makes that say which workflow signed, rather
than accepting any attestation this repository has: the signing runs in
`btclib-org/.github`'s `reusable-build.yml`, which `release.yml` calls,
and `--source-ref` is what keeps a build of a branch from passing as the
release.
A CycloneDX bill of materials is attached beside them, generated from the
built wheel and covered by the same attestation. Either distribution file
can also be rebuilt from its tag and compared, the build being
reproducible: RELEASING.md has that command.

## Limitations, not vulnerabilities

These are known and inherent. They are worth stating because this
package is used to teach and to prototype as much as to build:

- **Secret material lives in Python objects**, which are immutable and
    not zeroized: a key handed to the package stays in the process
    memory until garbage collection, and may have been copied by the
    interpreter meanwhile.
- **Nothing here is constant-time.** The package is pure Python.
