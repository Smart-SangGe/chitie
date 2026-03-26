#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/tests/out/local-ci"
LOCAL_CI_CONFIG="${LOCAL_CI_CONFIG:-${ROOT_DIR}/tests/local_ci.config}"
CHITIE_BIN="${CHITIE_BIN:-}"
LINPEAS_SH="${LINPEAS_SH:-/usr/share/peass/linpeas/linpeas.sh}"
CONTAINER_RUNTIME="${CONTAINER_RUNTIME:-}"

MATRIX_IMAGES="${MATRIX_IMAGES:-ubuntu:22.04,debian:12}"
RUN_VULN_ENV="${RUN_VULN_ENV:-1}"
VULN_IMAGE_NAME="${VULN_IMAGE_NAME:-chitie-vuln-env:local}"

MIN_PRECISION="${MIN_PRECISION:-0.95}"
MIN_RECALL="${MIN_RECALL:-0.98}"
REQUIRED_PATTERNS="${REQUIRED_PATTERNS:-suid,/etc/passwd,cron,secret_token}"
CHITIE_ONLY_MODULES="${CHITIE_ONLY_MODULES:-}"
CHITIE_ARGS="${CHITIE_ARGS:-}"
LINPEAS_ARGS="${LINPEAS_ARGS:-}"
CONTAINER_DISABLE_PROXY="${CONTAINER_DISABLE_PROXY:-1}"
SCENARIO_JOBS="${SCENARIO_JOBS:-1}"
AUTO_INSTALL_PROCPS="${AUTO_INSTALL_PROCPS:-1}"

if [[ -f "${LOCAL_CI_CONFIG}" ]]; then
  # shellcheck disable=SC1090
  source "${LOCAL_CI_CONFIG}"
fi

if [[ -z "${CONTAINER_RUNTIME}" ]]; then
  if command -v podman >/dev/null 2>&1; then
    CONTAINER_RUNTIME="podman"
  elif command -v docker >/dev/null 2>&1; then
    CONTAINER_RUNTIME="docker"
  else
    echo "[ERROR] Neither podman nor docker found."
    exit 1
  fi
fi

MOUNT_SUFFIX=":ro"
if [[ "${CONTAINER_RUNTIME}" == "podman" ]]; then
  MOUNT_SUFFIX=":ro,Z"
fi

run_container() {
  if [[ "${CONTAINER_DISABLE_PROXY}" == "1" ]]; then
    env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u all_proxy -u ALL_PROXY -u no_proxy -u NO_PROXY \
      "${CONTAINER_RUNTIME}" "$@"
  else
    "${CONTAINER_RUNTIME}" "$@"
  fi
}

build_opts=()
run_opts=()
if [[ "${CONTAINER_RUNTIME}" == "podman" && "${CONTAINER_DISABLE_PROXY}" == "1" ]]; then
  build_opts+=(--http-proxy=false)
  run_opts+=(--http-proxy=false)
fi

write_timing_file() {
  local start_ns="$1"
  local end_ns="$2"
  local err_file="$3"
  local out_file="$4"
  local elapsed_ns
  local sec
  local ms

  elapsed_ns=$((end_ns - start_ns))
  sec=$((elapsed_ns / 1000000000))
  ms=$(((elapsed_ns / 1000000) % 1000))

  {
    printf "real %d.%03ds\n" "${sec}" "${ms}"
    cat "${err_file}"
  } > "${out_file}"
}

prepare_image_with_procps() {
  local image="$1"
  local safe_repo
  local derived_image

  if run_container run "${run_opts[@]}" --rm "${image}" sh -lc 'command -v ps >/dev/null 2>&1'; then
    echo "${image}"
    return 0
  fi

  if [[ "${AUTO_INSTALL_PROCPS}" != "1" ]]; then
    echo "${image}"
    return 0
  fi

  safe_repo="$(echo "${image}" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9._-' '_')"
  derived_image="local-ci-prep-${safe_repo}:latest"

  echo "    [prep] '${image}' missing 'ps'; building '${derived_image}' with procps"
  cat <<EOF | run_container build "${build_opts[@]}" -t "${derived_image}" -f - "${ROOT_DIR}" >/dev/null
FROM ${image}
RUN set -e; \
    if command -v apt-get >/dev/null 2>&1; then \
      apt-get update && apt-get install -y --no-install-recommends procps bash && rm -rf /var/lib/apt/lists/*; \
    elif command -v apk >/dev/null 2>&1; then \
      apk add --no-cache procps bash; \
    elif command -v dnf >/dev/null 2>&1; then \
      dnf install -y procps-ng bash && dnf clean all; \
    elif command -v yum >/dev/null 2>&1; then \
      yum install -y procps-ng bash && yum clean all; \
    else \
      echo "No supported package manager to install procps" >&2; \
      exit 1; \
    fi
EOF
  echo "${derived_image}"
}

if [[ ! -f "${LINPEAS_SH}" ]]; then
  echo "[ERROR] linpeas.sh not found: ${LINPEAS_SH}"
  echo "        Export LINPEAS_SH=/absolute/path/to/linpeas.sh"
  exit 1
fi

mkdir -p "${OUT_DIR}"

echo "[1/5] Baseline checks"
(cd "${ROOT_DIR}" && cargo check && cargo test)

echo "[2/5] Building release binary"
(cd "${ROOT_DIR}" && cargo build --release)

if [[ -n "${CHITIE_BIN}" ]]; then
  if [[ ! -x "${CHITIE_BIN}" ]]; then
    echo "[ERROR] CHITIE_BIN is set but not executable: ${CHITIE_BIN}"
    exit 1
  fi
else
  for candidate in \
    "${ROOT_DIR}/target/x86_64-unknown-linux-musl/release/chitie" \
    "${ROOT_DIR}/target/release/chitie"; do
    if [[ -x "${candidate}" ]]; then
      CHITIE_BIN="${candidate}"
      break
    fi
  done

  if [[ -z "${CHITIE_BIN}" ]]; then
    echo "[ERROR] Built binary not found."
    echo "        Tried:"
    echo "        - ${ROOT_DIR}/target/x86_64-unknown-linux-musl/release/chitie"
    echo "        - ${ROOT_DIR}/target/release/chitie"
    echo "        You can override path with: CHITIE_BIN=/abs/path/to/chitie"
    exit 1
  fi
fi

echo "    Using chitie binary: ${CHITIE_BIN}"

if [[ "${RUN_VULN_ENV}" == "1" ]]; then
  echo "[3/5] Building vulnerability image ${VULN_IMAGE_NAME}"
  run_container build "${build_opts[@]}" -t "${VULN_IMAGE_NAME}" "${ROOT_DIR}/tests/vulnerability-env"
  MATRIX_IMAGES="${MATRIX_IMAGES},${VULN_IMAGE_NAME}"
else
  echo "[3/5] Skipping vulnerability image build"
fi

echo "[4/5] Running parity matrix: ${MATRIX_IMAGES}"
echo "    Proxy passthrough: $([[ "${CONTAINER_DISABLE_PROXY}" == "1" ]] && echo "disabled" || echo "enabled")"
echo "    Scenario jobs: ${SCENARIO_JOBS}"
overall_rc=0

run_scenario() {
  local image="$1"
  local image_trimmed
  local safe_name
  local scenario_dir
  local chitie_out
  local linpeas_out
  local chitie_time
  local linpeas_time
  local chitie_err
  local linpeas_err
  local metrics_json
  local chitie_cmd
  local linpeas_cmd
  local chitie_start_ns
  local chitie_end_ns
  local linpeas_start_ns
  local linpeas_end_ns
  local chitie_rc
  local linpeas_rc
  local cmp_rc
  local effective_image

  image_trimmed="$(echo "${image}" | xargs)"
  [[ -z "${image_trimmed}" ]] && return 0

  safe_name="$(echo "${image_trimmed}" | tr '/: ' '___')"
  scenario_dir="${OUT_DIR}/${safe_name}"
  mkdir -p "${scenario_dir}"

  chitie_out="${scenario_dir}/chitie.txt"
  linpeas_out="${scenario_dir}/linpeas.txt"
  chitie_time="${scenario_dir}/chitie.time"
  linpeas_time="${scenario_dir}/linpeas.time"
  chitie_err="${scenario_dir}/chitie.err"
  linpeas_err="${scenario_dir}/linpeas.err"
  metrics_json="${scenario_dir}/metrics.json"

  chitie_cmd="/usr/local/bin/chitie"
  if [[ -n "${CHITIE_ONLY_MODULES}" ]]; then
    chitie_cmd="${chitie_cmd} -o '${CHITIE_ONLY_MODULES}'"
  fi
  if [[ -n "${CHITIE_ARGS}" ]]; then
    chitie_cmd="${chitie_cmd} ${CHITIE_ARGS}"
  fi

  linpeas_cmd="/usr/local/bin/linpeas.sh"
  if [[ -n "${LINPEAS_ARGS}" ]]; then
    linpeas_cmd="${linpeas_cmd} ${LINPEAS_ARGS}"
  fi

  echo "  -> Scenario: ${image_trimmed}"
  effective_image="$(prepare_image_with_procps "${image_trimmed}")"
  set +e
  chitie_start_ns=$(date +%s%N)
  run_container run "${run_opts[@]}" --rm --privileged \
    -v "${CHITIE_BIN}:/usr/local/bin/chitie${MOUNT_SUFFIX}" \
    "${effective_image}" sh -lc "${chitie_cmd}" \
    >"${chitie_out}" 2>"${chitie_err}"
  chitie_rc=$?
  chitie_end_ns=$(date +%s%N)
  write_timing_file "${chitie_start_ns}" "${chitie_end_ns}" "${chitie_err}" "${chitie_time}"

  linpeas_start_ns=$(date +%s%N)
  run_container run "${run_opts[@]}" --rm --privileged \
    -v "${LINPEAS_SH}:/usr/local/bin/linpeas.sh${MOUNT_SUFFIX}" \
    "${effective_image}" sh -lc "if command -v bash >/dev/null 2>&1; then bash ${linpeas_cmd}; else sh ${linpeas_cmd}; fi" \
    >"${linpeas_out}" 2>"${linpeas_err}"
  linpeas_rc=$?
  linpeas_end_ns=$(date +%s%N)
  write_timing_file "${linpeas_start_ns}" "${linpeas_end_ns}" "${linpeas_err}" "${linpeas_time}"
  rm -f "${chitie_err}" "${linpeas_err}"
  set -e

  if [[ ${chitie_rc} -ne 0 || ${linpeas_rc} -ne 0 ]]; then
    echo "     [FAIL] execution error (chitie=${chitie_rc}, linpeas=${linpeas_rc})"
    return 1
  fi

  set +e
  python3 "${ROOT_DIR}/tests/compare_outputs.py" \
    --chitie "${chitie_out}" \
    --linpeas "${linpeas_out}" \
    --min-precision "${MIN_PRECISION}" \
    --min-recall "${MIN_RECALL}" \
    --required-patterns "${REQUIRED_PATTERNS}" \
    --report-json "${metrics_json}"
  cmp_rc=$?
  set -e

  if [[ ${cmp_rc} -ne 0 ]]; then
    echo "     [FAIL] parity threshold mismatch"
    return 1
  else
    echo "     [PASS] parity thresholds met"
  fi
  return 0
}

IFS=',' read -r -a images <<<"${MATRIX_IMAGES}"
if [[ "${SCENARIO_JOBS}" -gt 1 ]]; then
  pids=()
  for image in "${images[@]}"; do
    run_scenario "${image}" &
    pids+=("$!")
  done

  for pid in "${pids[@]}"; do
    if ! wait "${pid}"; then
      overall_rc=1
    fi
  done
else
  for image in "${images[@]}"; do
    if ! run_scenario "${image}"; then
      overall_rc=1
    fi
  done
fi

echo "[5/5] Artifacts: ${OUT_DIR}"
if [[ ${overall_rc} -ne 0 ]]; then
  echo "[RESULT] LOCAL CI FAILED"
  exit 1
fi

echo "[RESULT] LOCAL CI PASSED"
