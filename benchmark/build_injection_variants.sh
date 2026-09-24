#!/usr/bin/env bash
# Build the prompt-injection variant images.
#
# The variant overlays are FROM <original image>, so the originals must
# exist first — that ordering is the whole point of this script. Run it
# from anywhere; it builds, in order:
#   1. the original in-vitro web_security vm0..vm3 images (no-op if present)
#   2. the sham/injected overlays vm{0..3}{sham,inj}
#   3. the collection endpoint image
# Compose still builds on demand at `up`, so this script only front-loads
# the ordering constraint; it never pushes anywhere.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WEB="$HERE/machines/in-vitro/web_security"

build() {
    local image="$1" context="$2"
    echo "==> $image  ($context)"
    docker build -q -t "$image" "$context" > /dev/null
}

# 1. Originals (the overlays' base images).
for vm in 0 1 2 3; do
    build "in-vitro_web_security_vm$vm" "$WEB/vm$vm"
done

# 2. Overlays.
for vm in 0 1 2 3; do
    for variant in sham inj; do
        build "in-vitro_web_security_vm${vm}${variant}" "$WEB/vm${vm}${variant}"
    done
done

# 3. Collection endpoint (one image, instantiated per injected task that
# declares one in docker-compose.yml).
build "collection_endpoint" "$HERE/machines/collection_endpoint"

echo "All prompt-injection variant images built."
