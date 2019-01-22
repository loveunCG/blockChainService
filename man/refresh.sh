#!/bin/bash

base=https://docs.dappbox.net/man/
pages=(
	dappbox.1
	stdiscosrv.1
	strelaysrv.1
	dappbox-config.5
	dappbox-stignore.5
	dappbox-device-ids.7
	dappbox-event-api.7
	dappbox-faq.7
	dappbox-networking.7
	dappbox-rest-api.7
	dappbox-security.7
	dappbox-versioning.7
	dappbox-bep.7
	dappbox-localdisco.7
	dappbox-globaldisco.7
	dappbox-relay.7
)

for page in "${pages[@]}" ; do
	curl -sLO "$base$page"
done
