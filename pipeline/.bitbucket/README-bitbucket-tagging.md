# Bitbucket Tag Flow for SPSDK

This document describes branch-aware tagging automation used by SPSDK.

## Scope

- This setup adds tagging logic and Jenkins pipeline configuration to the repository.
- It does **not** rely on Bitbucket Pipelines.

## Managed branch model

- `master` is the development branch.
- `release/X.Y.Z` is the release stabilization branch.

## Managed tag format

- `vX.Y.Z-DEVn`
- `vX.Y.Z-RCn`

## Automated behavior

### On `release/X.Y.Z`

1. The script verifies that at least one `vX.Y.Z-DEVn` tag exists (DEV anchor).
2. If no DEV anchor exists, it creates `vX.Y.Z-DEV0` automatically and ends that run.
3. For each next new commit on release branch, it creates sequential RC tags:
   - first tagged release commit: `vX.Y.Z-RC0`
   - next commit: `vX.Y.Z-RC1`
   - and so on.
4. If HEAD is already tagged with matching RC, it does nothing (idempotent).

### On `master`

1. The script scans `origin/release/*` branches and takes the highest release version tuple.
2. It computes the next minor version and creates exactly one tag:
   - `vX.(Y+1).0-DEV0` (the patch component is always reset to `0` when bumping the minor)
3. Once this tag exists, no additional automatic tags are created on `master`.

## Release-finalization manual step

Per agreed process, final clean release tag is manual:

1. Identify the final release commit currently tagged as last `RC`.
2. Create and push clean `vX.Y.Z` tag on the same commit.
3. Keep existing `RC` tag(s); the clean release tag is added as an extra tag.

## Jenkins integration

- Pipeline file: `pipeline/Jenkinsfile-tag-flow`
- Tagging script: `pipeline/.bitbucket/ci/auto_tag_flow.py`
- Auth source: Jenkins credential from keystore (`bitbucket-https-ci`)

Recommended Jenkins job type:
- Multibranch Pipeline job pointing to this repository.

Recommended branch filters:
- Include `master`
- Include `release/*`

## Option 1: Dedicated first Jenkins job

This repository now includes a dedicated Jenkins pipeline file for tag flow:
- `pipeline/Jenkinsfile-tag-flow`

Use it as a separate Multibranch Pipeline job, for example:
- Job name: `spsdk-tag-flow`
- Branch discovery: enabled
- Include branches: `master` and `release/*`

To run tag flow before other CI jobs:
1. Configure `spsdk-tag-flow` to trigger on repository events for `master` and `release/*`.
2. Configure downstream jobs (codecheck, docs, deploy, etc.) to start only after `spsdk-tag-flow` success for the same branch/commit.
3. Keep tag creation only in `spsdk-tag-flow` to avoid race conditions and duplicate tag attempts.

Recommended downstream policy:
- If `spsdk-tag-flow` fails, do not run downstream pipelines.
- If `spsdk-tag-flow` reports no-op (already tagged or branch out of scope), downstream pipelines may continue.

## Important operational notes

- Jenkins SCM credential must allow fetch/push tags to origin.
- Re-runs are safe; existing tags are re-checked and not duplicated.
- Script fetches tags and remote release refs before computing next tags.
- Final `vX.Y.Z` tag is a manual add-on tag and does not replace `RC` tags.
- Missing release DEV anchor no longer fails the run; script creates `vX.Y.Z-DEV0` fallback.
