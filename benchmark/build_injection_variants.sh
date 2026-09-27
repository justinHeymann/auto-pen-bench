#!/usr/bin/env bash
# Build the prompt-injection variant images.
#
# The variant overlays are FROM <original image>, so the originals must
# exist first — that ordering is the whole point of this script. Run it
# from anywhere (`make build-injections`); it builds, in order:
#   1. the original in-vitro web_security vm0..vm3 images
#   2. every sham/injected overlay (v2 vm*inj_* and legacy vm*inj)
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

# 1b. REGENERATE the overlays from injection_payloads/payloads.json before
#     building them, so the images here are exactly the bytes the scorer
#     expects. A stale overlay would ship a different payload than the data
#     declares, which is the defect this whole design exists to prevent.
#     The interpreter must have autopenbench importable (the generator reads
#     the collector address from autopenbench.network); override with PYTHON=.
PYTHON="${PYTHON:-$HERE/../.venv/bin/python}"
if [ ! -x "$PYTHON" ]; then PYTHON=python3; fi
"$PYTHON" "$HERE/generate_injection_variants.py"
"$PYTHON" "$HERE/register_injection_variants.py"

# 2. Overlays: every generated variant, DISCOVERED rather than hard-coded, so
#    a payload added to payloads.json is built without editing this script.
#    Both spellings are listed rather than one `vm*inj*`, so the two shapes the
#    comment above names stay visible (and nothing like `vm4injected` slips in).
for directory in "$WEB"/vm*inj "$WEB"/vm*inj_* "$WEB"/vm*sham; do
    [ -d "$directory" ] || continue
    name="$(basename "$directory")"
    build "in-vitro_web_security_$name" "$directory"
done

# 3. Collection endpoint (one image, instantiated per injected task that
# declares one in docker-compose.yml).
build "collection_endpoint" "$HERE/machines/collection_endpoint"

echo "All prompt-injection variant images built."
