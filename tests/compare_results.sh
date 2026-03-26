#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

TEST_IMAGE="chitie-test-env"
CHITIE_BIN="$(pwd)/target/release/x86_64-unknown-linux-musl/chitie"
LINPEAS_SH="/usr/share/peass/linpeas/linpeas.sh"

echo -e "${YELLOW}[*] Building vulnerability environment...${NC}"
podman build -t "$TEST_IMAGE" tests/vulnerability-env/

if [ ! -f "$CHITIE_BIN" ]; then
	echo -e "${RED}[!] Chitie binary not found. Building...${NC}"
	cargo build --release
fi

echo -e "${YELLOW}[*] Running chitie...${NC}"
# 使用 --privileged 以便某些提权检查能正常运行，模拟真实渗透环境
podman run --rm --privileged
-v "$CHITIE_BIN:/usr/local/bin/chitie:Z"
"$TEST_IMAGE" /bin/bash -c "time /usr/local/bin/chitie" >tests/chitie_output.txt 2>tests/chitie_time.txt

echo -e "${YELLOW}[*] Running linpeas.sh...${NC}"
podman run --rm --privileged
-v "$LINPEAS_SH:/usr/local/bin/linpeas.sh:Z"
"$TEST_IMAGE" /bin/bash -c "time /usr/local/bin/linpeas.sh" >tests/linpeas_output.txt 2>tests/linpeas_time.txt

echo -e "${GREEN}=====================================${NC}"
echo -e "${GREEN}Performance Summary:${NC}"
echo -n "Chitie Execution Time: "
grep real tests/chitie_time.txt | awk '{print $2}'
echo -n "Linpeas Execution Time: "
grep real tests/linpeas_time.txt | awk '{print $2}'
echo -e "${GREEN}=====================================${NC}"

echo -e "${YELLOW}[*] Comparison check suggestions:${NC}"
echo -e "1. Compare SUID detection: grep 'find' tests/chitie_output.txt vs tests/linpeas_output.txt"
echo -e "2. Compare /etc/passwd check: grep '/etc/passwd' tests/chitie_output.txt"
echo -e "3. Compare Secrets check: grep 'SECRET_TOKEN' tests/chitie_output.txt"
