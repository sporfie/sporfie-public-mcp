#!/bin/sh
# Build and push the Sporfie Public API MCP image (linux/arm64 by default).
# Tag shape: {prod|dev}-<sha7>-<version> (prod on main/master). No :latest.
#
# Usage: IMAGE_REPOSITORY=<registry>/<repository> ./deployImage.sh
# An Amazon ECR registry is logged into first (needs the AWS CLI and credentials).
set -eu

: "${IMAGE_REPOSITORY:?set IMAGE_REPOSITORY=<registry>/<repository>}"
PLATFORM="${PLATFORM:-linux/arm64}"

current_branch=$(git rev-parse --abbrev-ref HEAD)
short_sha=$(git rev-parse HEAD | cut -c1-7)
# The version lives in pyproject.toml only; the image tag follows it.
version=$(sed -n 's/^version = "\(.*\)"$/\1/p' pyproject.toml | head -n 1)
: "${version:?could not read the version from pyproject.toml}"

if [ "$current_branch" = "main" ] || [ "$current_branch" = "master" ]; then
    tag_prefix="prod"
else
    tag_prefix="dev"
fi

TAG="${tag_prefix}-${short_sha}-${version}"
REMOTE="${IMAGE_REPOSITORY}:${TAG}"
registry="${IMAGE_REPOSITORY%%/*}"

case "$registry" in
    *.dkr.ecr.*.amazonaws.com)
        region=$(echo "$registry" | cut -d. -f4)
        echo ">> ECR login ($region)"
        aws ecr get-login-password --region "$region" \
          | docker login --username AWS --password-stdin "$registry"
        ;;
esac

echo ">> building + pushing $REMOTE (platform $PLATFORM)"
docker buildx build \
  --platform "$PLATFORM" \
  --tag "$REMOTE" \
  --push \
  .

cat <<EOM

============================================================
Pushed:
  $REMOTE

Next: pin tag ${TAG} in the deployment manifests.
============================================================
EOM
