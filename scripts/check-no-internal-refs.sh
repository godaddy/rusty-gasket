#!/usr/bin/env bash
#
# Fails if any GoDaddy-internal reference leaks into this public repository.
# Run in CI and locally before publishing. The project's legitimate public
# identity (the github.com/godaddy/rusty-gasket URL, docs.rs links, the
# opensource@godaddy.com contact) is allowed; internal systems, hostnames,
# registries, and identity namespaces are not.
set -euo pipefail

echo "Checking for leaked GoDaddy-internal references..."

# High-signal internal markers: internal orgs/hosts, Artifactory/JFrog,
# the jomax identity namespace, Katana/PCP, internal SSO, internal Slack.
pattern='gdcorp|gdartifactory|jfrog|int\.gdcorp|secureserver|jomax|artifactory|katana|sso\.godaddy|enterprise\.slack'

# Search source, manifests, docs, workflows, and scripts. Exclude this
# script (it necessarily contains the pattern) and the git/target dirs.
if grep -RInE "$pattern" . \
    --include='*.rs' --include='*.toml' --include='*.md' \
    --include='*.yaml' --include='*.yml' --include='*.sh' \
    --exclude='check-no-internal-refs.sh' \
    --exclude-dir='.git' --exclude-dir='target' 2>/dev/null \
    | grep -vE 'docs\.rs/rusty-gasket'; then
  echo "ERROR: internal reference(s) found above — scrub before publishing." >&2
  exit 1
fi

echo "OK: no internal references found."
