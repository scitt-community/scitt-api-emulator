

newman run sanity.postman_collection.json \
--reporters cli,htmlextra \
--reporter-htmlextra-skipSensitiveData \
--reporter-htmlextra-export "../docs/index.html" \

