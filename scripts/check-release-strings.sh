#!/bin/sh
# Check that a release build of `warden` contains no test-only code:
# no scripted ("mock") planner, no script loader, no audit fault injection,
# no test-hooks feature, and that `provider = "mock"` is rejected.
#
# Usage: scripts/check-release-strings.sh   (from anywhere in the repo)
set -eu

cd "$(dirname "$0")/.."
cargo build --release -p warden-cli --locked
bin=target/release/warden

found=$(strings "$bin" | grep -i -E 'mock|from_script|WARDEN_TEST_FAIL|test-hooks' || true)
if [ -n "$found" ]; then
    echo "FAIL: test-only strings found in $bin:" >&2
    echo "$found" >&2
    exit 1
fi
echo "ok: no test-only strings in $bin"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -m 700 "$tmp/home" "$tmp/root"
printf 'root = "%s"\nprovider = "mock"\nscript = "%s/s.json"\n' "$tmp/root" "$tmp" > "$tmp/home/config.toml"
chmod 600 "$tmp/home/config.toml"
printf 'root = "%s"\nprovider = "mock"\n' "$tmp/root" > "$tmp/home/mock-only.toml"
chmod 600 "$tmp/home/mock-only.toml"

for cfg in config.toml mock-only.toml; do
    set +e
    msg=$("$bin" --home "$tmp/home" agent --config "$tmp/home/$cfg" </dev/null 2>&1)
    code=$?
    set -e
    if [ "$code" -ne 1 ]; then
        echo "FAIL: $cfg: expected exit 1, got $code: $msg" >&2
        exit 1
    fi
    case "$msg" in
        *"unknown provider"*|*"unknown field \`script\`"*) ;;
        *) echo "FAIL: $cfg: unexpected message: $msg" >&2; exit 1 ;;
    esac
    echo "ok: $cfg rejected: $msg"
done
if [ -e "$tmp/home/audit.jsonl" ]; then
    echo "FAIL: a rejected config created an audit log" >&2
    exit 1
fi
echo "ok: release build is free of test hooks"
