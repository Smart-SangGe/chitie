#!/bin/bash

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

IMAGE=${1:-"ubuntu:latest"}
CHITIE_BIN="$(pwd)/target/x86_64-unknown-linux-musl/release/chitie"
LINPEAS_SH="/usr/share/peass/linpeas/linpeas.sh"

if [ ! -f "$CHITIE_BIN" ]; then
	echo -e "${RED}Error: chitie binary not found. Run 'cargo build --release' first.${NC}"
	exit 1
fi

if [ ! -f "$LINPEAS_SH" ]; then
	echo -e "${RED}Error: linpeas.sh not found at $LINPEAS_SH${NC}"
	exit 1
fi

echo -e "${GREEN}Testing on image: $IMAGE${NC}"
echo "-----------------------------------"

# 运行 chitie
echo "Running chitie..."
podman run --rm -v "$CHITIE_BIN:/usr/local/bin/chitie:Z" "$IMAGE" /bin/bash -c "time /usr/local/bin/chitie" >tests/chitie_output.txt 2>tests/chitie_time.txt

# 运行 linpeas
echo "Running linpeas.sh..."
podman run --rm -v "$LINPEAS_SH:/usr/local/bin/linpeas.sh:Z" "$IMAGE" /bin/bash -c "time /usr/local/bin/linpeas.sh" >tests/linpeas_output.txt 2>tests/linpeas_time.txt

echo "-----------------------------------"
echo -e "${GREEN}Results:${NC}"
echo "Chitie Time:"
grep real tests/chitie_time.txt
echo "Linpeas Time:"
grep real tests/linpeas_time.txt

echo "-----------------------------------"
echo "Outputs saved to tests/chitie_output.txt and tests/linpeas_output.txt"
