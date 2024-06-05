# Release cheatsheet

The CI handles most of the release process. All that is required is pushing a tag in the form of `v{semver}`. Where
`{semver}` is a semantic version (e.g. `0.1.3`). This may include a pre-release part (e.g. `0.1.3-alpha.1`).

> [!IMPORTANT]
> The CI will check if the version of the tag matches the version of the crates. If they don't align, the release build
> will fail. See below for more information.

## What we promise

Right now everything is in flux. We do not make any promises on the API (internal Rust APIs or external HTTP APIs).

We simply release `0.x` versions as we see fit. And it is ok to directly go from an `alpha` pre-release to a proper
release. We don't honor the semver promises (sorry).

Right now, we use the following pre-release modifiers (this might change in the future):

* `alpha` – for any pre-release
* `rc` – for something we plan to properly release

We also don't publish to crates.io, only release a tag, binary artifacts and container images.

For `1.0.0` and beyond, this should work differently. Maybe even before. However, there are no plans for that yet.

## Pre-requisites

* You have some common developer tools for Rust installed (e.g. `cargo`, `git`)
* Your local `main` branch is in sync with the upstream `main` branch. The git remote for upstream is named `upstream`.
* You have `cargo release` installed. This can be done using `cargo install cargo-release`.

## Performing the release

In a nutshell, the steps are:

* Ensure the cargo versions are aligned with the release tag that we create next
* Tag the release
* Push the tag

To make it clearer what got released and what is part of the next release, it makes sense to create a PR *before*
pushing the release tag. This will also make step 1 easier for the *next* release, as that's already been taken care of.

The following instructions walk you through the process on the example of releasing `0.0.0-alpha.1`, which you need
to replace with the actual release.

### Tag

On an up-to-date main branch, create a (local) tag for the next version:

```bash
git tag v0.0.0-alpha.1
```

### Bump version on main

Check out a new branch for preparing the release: 

```bash
git checkout -b next-release
```

Uptick the version:

```bash
cargo release version alpha
```

If the result looks good, execute the changes using:

```bash
cargo release version alpha -x
```

Commit the changes to git:

```bash
git commit -a -m "chore: next development version"
```

### Create and merge the PR

Create a PR as usual for `main`. Have the CI check it and get a +1. Either use the auto-merge button, or merge it
manually when it's ready.

### Revisit the tag (optional)

You might want to revisit the tag. If between creating your local tag and the merge of the "uptick PR" any important
changes got merged, you might consider picking them up into the release too. You can update the local tag using:

```bash
git tag v0.0.0-alpha.1 --force
```

### Trigger the release

Once you think it's ready, push the release tag to upstream:

```bash
git push upstream v0.0.0-alpha.1
```

Monitor the outcome! 🎂

## If things go wrong

### Unaligned versions

If the current crate versions have already been released, then you need to bump the versions upfront.

### Broken stuff

Technically, it is possible to make changes to the tag and just force-push it again.

However, in most cases, it might be easier to accept defeat and try again with a new version.

## Test/personal release

To test, you can push a release tag to your personal fork of the repository. By default, this will run the release
workflow in your personal repository, and create a release there. If that's ok for your fork, you can push and force
push tags as you like, to fix and test the release process.

## Alternative approaches

It is possible to just push the tag without waiting for the "next version" PR to be merged. The downside is that it
might happen that something gets merged for the version that is just being released. In this case, it might look
that this change should be part of the release, but in fact is not. The git log will tell you that, but it might look
confusing.
