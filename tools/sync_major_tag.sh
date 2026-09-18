#!/usr/bin/env bash
set -euo pipefail

if [[ ! "${RELEASE_TAG:-}" =~ ^v([0-9]+)\.[0-9]+\.[0-9]+$ ]]; then
  echo 'Release tag must be a stable vMAJOR.MINOR.PATCH tag.' >&2
  exit 2
fi
major="${BASH_REMATCH[1]}"
if [[ ! "${RELEASE_SHA:-}" =~ ^[0-9a-f]{40}$ ]]; then
  echo 'Release SHA must be a commit SHA.' >&2
  exit 2
fi
if [[ ! "${GITHUB_REPOSITORY:-}" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
  echo 'A GitHub repository is required.' >&2
  exit 2
fi

ref="v${major}"
endpoint="repos/${GITHUB_REPOSITORY}/git/refs/tags/${ref}"

if existing="$(gh api "$endpoint" --jq '.object.sha' 2>/dev/null)"; then
  if [[ "$existing" == "$RELEASE_SHA" ]]; then
    echo "${ref} already points to ${RELEASE_TAG}."
    exit 0
  fi
  gh api --method PATCH "$endpoint" -f sha="$RELEASE_SHA" -F force=true >/dev/null
else
  gh api --method POST "repos/${GITHUB_REPOSITORY}/git/refs" \
    -f ref="refs/tags/${ref}" -f sha="$RELEASE_SHA" >/dev/null
fi
echo "${ref} now points to ${RELEASE_TAG}."
