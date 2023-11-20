jq < ${HOME}/Documents/fediverse/scitt_federation_alice/config.json \
&& sleep 2 \
&& scitt-emulator server \
 --workspace ${HOME}/Documents/fediverse/scitt_federation_alice/workspace_alice/ \
 --tree-alg CCF \
 --port 7000 \
 --middleware scitt_emulator.federation_activitypub_bovine:SCITTFederationActivityPubBovine \
 --middleware-config-path ${HOME}/Documents/fediverse/scitt_federation_alice/config.json
