# Releasing Sulis

Sulis contains two independently versioned Go modules in one repository:

| Module | Directory | Tag form |
| --- | --- | --- |
| `github.com/borfast/sulis` | repository root | `vX.Y.Z` |
| `github.com/borfast/sulis/store/sql` | `store/sql` | `store/sql/vX.Y.Z` |

The directory prefix on the SQL tag is required by
[Go's multi-module tag rules](https://go.dev/doc/modules/managing-source#multiple-module-source).
A release is not complete until both intended module tags exist and can be
resolved by the Go proxy. The modules can version independently after v1, but
the first stable release publishes both as `v1.0.0` from the same reviewed
commit.

The `v0.1.0` tags predate this process: they are lightweight tags and the
changelog was closed immediately after tagging. Do not copy that sequence.
Starting with v1, release tags are signed annotated tags and the changelog is
closed in the release commit before either tag is created.

## One-time repository protection

Create an active
[tag ruleset](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/creating-rulesets-for-a-repository)
under **Settings → Rules → Rulesets**. Target both `v*` and `store/sql/v*`, and
enable:

- restriction of tag updates and deletions;
- blocking force pushes;
- required signed commits; and
- the status checks that run for a push to `main`: both Go-version `test`
  matrix jobs, `store/sql conformance (postgres)`, `static analysis`, and
  `fuzz smoke`.

Do not select “allow creations even if required status checks are missing.” A
tag must point at a commit whose checks already passed. If tag creation is
restricted to release maintainers, keep the bypass list as small as possible
and do not use bypass to skip status checks during an ordinary release.

The tag ruleset protects the refs; the protected `main` ruleset protects the
content they name. All release preparation changes must therefore arrive
through the normal pull-request review, signed-commit, linear-history, and CI
path on `main`. A release tag is only cut from the exact current `origin/main`
commit. Never tag a release branch or an unmerged pull-request head.

Rulesets validate commit signatures, not the signature on an annotated tag.
The release commands below sign and verify each tag separately. Keep the
private signing key outside the repository.

## Release preparation pull request

Prepare one pull request containing every versioned release artifact. Do not
make a follow-up “release metadata” commit after CI passes.

- [ ] Choose the root and SQL versions independently using semantic
  versioning. For the first stable release they are both `v1.0.0`.
- [ ] Confirm the independent security review is complete, its report is in
  the repository, and every finding has a recorded disposition. Blocking
  findings must be fixed and reviewed before continuing.
- [ ] Rename the relevant `CHANGELOG.md` `[Unreleased]` section to
  `[X.Y.Z] - YYYY-MM-DD`, then open a new empty `[Unreleased]` section above
  it. Confirm every breaking change and migration step is present.
- [ ] For `v1.0.0`, rewrite README.md's **Versioning** section in present
  tense. It must say that the v1 compatibility promise is now active and must
  no longer say Sulis is pre-1.0 or that the public API may break without a
  major-version change. Recheck the stated store-contract and `store/sql`
  exceptions, and keep the link to `SECURITY.md`.
- [ ] Confirm the module paths remain `github.com/borfast/sulis` and
  `github.com/borfast/sulis/store/sql`. Neither path gains `/v1`; that suffix
  begins only at v2.
- [ ] Set `store/sql/go.mod`'s `github.com/borfast/sulis` requirement to the
  root version being released. Keep the local `replace ... => ../..` used to
  test both modules together. Run `go mod tidy` in both module roots and review
  every `go.mod` and `go.sum` change.
- [ ] Review direct and transitive dependency changes against
  `docs/dependencies.md`. Resolve Dependabot and `govulncheck` findings, verify
  license compatibility, and update the recorded rationale when a dependency's
  role or risk changed.
- [ ] Run an API diff for every package covered by README.md's compatibility
  promise (`sulis`, `totp`, `passkey`, `recovery`, and `passwordcheck`) and for
  the public `store/sql` packages. Before `v1.0.0`, compare with the latest v0
  tags as a review report: incompatibilities are allowed only when intentional
  and documented. Save the v1 API baselines for later releases. After v1, an
  incompatible result stops a v1.x release; preserve compatibility or prepare
  a new major module path.
- [ ] Run the complete local gate from a clean checkout:

  ```sh
  gofmt -l .
  go build ./...
  go vet ./...
  go test -race -count=1 ./...
  go run honnef.co/go/tools/cmd/staticcheck@2026.2 ./...
  go run github.com/securego/gosec/v2/cmd/gosec@v2.28.0 ./...
  go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./...

  cd store/sql
  go build ./...
  go vet ./...
  go test -race -count=1 ./...
  go run honnef.co/go/tools/cmd/staticcheck@2026.2 ./...
  go run github.com/securego/gosec/v2/cmd/gosec@v2.28.0 ./...
  go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./...
  ```

  Run the PostgreSQL conformance suite against a real supported PostgreSQL
  instance as CI does; a skipped local PostgreSQL test is not evidence.
- [ ] Obtain the normal review and required CI approvals on the release pull
  request. Record the API-diff result, external-review disposition, and local
  gate in the pull-request description.

The API-diff tool and its version must be pinned when the compatibility-check
backlog item is implemented. Until then, use
[`golang.org/x/exp/apidiff`](https://pkg.go.dev/golang.org/x/exp/apidiff)
against each package and record the exact pseudo-version and commands in the
release pull request. Do not use an unrecorded `@latest` result as release
evidence.

## Verify the exact release commit

Merge the release pull request, then wait for the `push` workflow on `main`.
Do not tag the pull-request commit merely because its checks passed: the commit
on `main` is the release artifact.

From a fresh checkout:

```sh
git fetch --prune origin
git fetch --tags origin
git switch main
git pull --ff-only origin main

test -z "$(git status --porcelain)"
release_commit="$(git rev-parse HEAD)"
test "$release_commit" = "$(git rev-parse origin/main)"
```

- [ ] The worktree is clean, `HEAD` equals `origin/main`, and the commit is
  signed and verified.
- [ ] The full CI workflow is green for `$release_commit`, including both Go
  versions, PostgreSQL conformance, static analysis, secret scanning, and fuzz
  smoke tests. Save the workflow URL in the release record.
- [ ] The release pull request's dependency-review job is green. This job is
  pull-request-only, so verify it on the merged release PR as well as checking
  the push workflow for the exact release commit.
- [ ] No newer commit has reached `origin/main`. If one has, decide whether it
  belongs in the release and repeat validation for the new exact commit.
- [ ] The changelog heading, README wording, `store/sql/go.mod` root version,
  and selected root and SQL version numbers all agree.
- [ ] The active tag ruleset targets both intended tag names and requires the
  expected checks. Do not use an administrator bypass to rescue a release that
  has not met the checklist.

## Create and publish the tags

Set the two versions explicitly; do not derive one from the other after the
modules begin releasing independently. The examples below show the first
stable release:

```sh
root_version=v1.0.0
sql_version=v1.0.0
release_commit="$(git rev-parse HEAD)"

git tag -s -m "sulis $root_version" \
  "$root_version" "$release_commit"
git tag -s -m "sulis/store/sql $sql_version" \
  "store/sql/$sql_version" "$release_commit"

git tag -v "$root_version"
git tag -v "store/sql/$sql_version"
test "$(git rev-list -n 1 "$root_version")" = "$release_commit"
test "$(git rev-list -n 1 "store/sql/$sql_version")" = "$release_commit"
```

[`git tag -s`](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-tags)
creates a signed annotated tag. Inspect both annotations and signatures before
publishing. Also confirm neither name already exists on the remote:

```sh
test -z "$(git ls-remote --tags origin "refs/tags/$root_version")"
test -z "$(git ls-remote --tags origin "refs/tags/store/sql/$sql_version")"
```

Push both refs in one command so the repository does not advertise only half
of the intended release:

```sh
git push origin "$root_version" "store/sql/$sql_version"
```

Never move, replace, or delete a published release tag. If anything is wrong,
fix it on `main` through a pull request and publish a patch version.

## Verify publication

- [ ] GitHub displays both tag signatures as verified and both tags resolve to
  `$release_commit`.
- [ ] Create release records for both module tags, using the corresponding
  changelog text and linking to the external review and CI run. Mark a v1
  release as a stable release, not a prerelease.
- [ ] Ask the public Go proxy for both versions from outside the repository:

  ```sh
  GOPROXY=https://proxy.golang.org go list -m \
    github.com/borfast/sulis@v1.0.0
  GOPROXY=https://proxy.golang.org go list -m \
    github.com/borfast/sulis/store/sql@v1.0.0
  ```

- [ ] Check the root and SQL packages on pkg.go.dev after indexing completes.
- [ ] Re-read README.md as a new consumer. For `v1.0.0`, there must be no stale
  pre-v1 warning, future-tense compatibility promise, or instruction to expect
  breaking changes within v1.
- [ ] Open the next milestone or tracking issue and continue accumulating
  changes under the new changelog `[Unreleased]` section.

Keep the release commit, tag names, CI URL, API-diff output, dependency review,
external-review disposition, and tag-signature verification together in the
release record. That evidence is what lets a later audit establish exactly
what was reviewed, tested, signed, and published.
