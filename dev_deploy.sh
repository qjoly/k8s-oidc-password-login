RANDOM_NUMBER=$((RANDOM % 1000 + 1))
echo "Starting deployment with random number: $RANDOM_NUMBER"

podman build --platform linux/amd64 -t ttl.sh/oidc-provider:$RANDOM_NUMBER -f Dockerfile .
if [ $? -ne 0 ]; then
  echo "Build failed, exiting."
  exit 1
fi

echo "Build successful, pushing image with tag ttl.sh/oidc-provider:$RANDOM_NUMBER"
podman push ttl.sh/oidc-provider:$RANDOM_NUMBER
if [ $? -ne 0 ]; then
  echo "Push failed, exiting."
  exit 1
fi

kubectl set image -n oidc-app deployments oidc-coffee-example  oidc-coffee-example=ttl.sh/oidc-provider:$RANDOM_NUMBER
if [ $? -ne 0 ]; then
  echo "Failed to update oidc-coffee-example deployment, exiting."
  exit 1
fi