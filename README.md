# f5-github-auto-documents

docker run -d \
  --name github-runner \
  -e RUNNER_NAME=github-runner \
  -e RUNNER_WORKDIR=/tmp/github-runner \
  -e RUNNER_TOKEN=<YOUR_RUNNER_TOKEN> \
  -e RUNNER_REPOSITORY_URL=https://github.com/maniak-academy/f5-github-auto-documents \
  -e RUNNER_LABELS=self-hosted,Linux,X64 \
  -e ORG_RUNNER=false \
  -e RUN_AS_ROOT=true \
  -v /var/run/docker.sock:/var/run/docker.sock \
  myoung34/github-runner:latest