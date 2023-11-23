curl -sfL https://github.com/scitt-community/scitt-api-emulator/archive/$(git log -n 1 --format=%H).tar.gz | sha384sum - | awk '{print $1}'

scitt-emulator client retrieve-claim --entry-id sha384:fe1952f763cf8947b6bc49902d7ec5f4a006c9358d2c6349b07896bf0967ebb7395eba7b30c9b7896b4096bc140a5f42 --url https://scitt.unstable.chadig.com --out webhook.push.cose
