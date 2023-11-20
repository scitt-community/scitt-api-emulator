jq < ${HOME}/Documents/fediverse/scitt_federation_bob/config.json \
&& sleep 2 \
&& scitt-emulator server \
  --workspace ${HOME}/Documents/fediverse/scitt_federation_bob/workspace_bob/ \
  --tree-alg CCF \
  --port 6000 \
  --middleware \
    scitt_emulator.federation_activitypub_bovine:SCITTFederationActivityPubBovine \
    scitt_emulator.github_webhook_notary:GitHubWebhookNotaryMiddleware \
  --middleware-config-path \
    ${HOME}/Documents/fediverse/scitt_federation_bob/config.json \
    -
