#!/bin/sh
#
# Integration test: full embed -> decode roundtrip against a real ELF32
# host binary from dist/. Requires the hydan binaries to be built
# (make) before this script runs. Uses HYDAN_TEST_PASS so getpass()
# is never invoked.

set -e

cd "$(dirname "$0")/.."

HOST=dist/get_zip_pass_32bit

if [ ! -x ./hydan ] || [ ! -x ./hydan-decode ]; then
    echo "FAIL: ./hydan not built (run make first)"
    exit 1
fi

if [ ! -f "$HOST" ]; then
    echo "SKIP: $HOST not found (dist/ not present)"
    exit 0
fi

export HYDAN_TEST_PASS=hydan-integ-secret

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

fail() {
    echo "FAIL: $1"
    exit 1
}

printf 'text message for integration testing\n' > "$TMP/msg.txt"
printf 'bin\000msg\000with\000nul\377bytes' > "$TMP/bin.msg"

for M in "$TMP/msg.txt" "$TMP/bin.msg"; do
    ./hydan "$HOST" "$M" > "$TMP/stegged" 2> "$TMP/embed.log" \
        || fail "embed failed for $M"

    grep -q "^Done\." "$TMP/embed.log" || fail "embed did not report Done"

    ORIG_SZ=$(stat -c%s "$HOST")
    NEW_SZ=$(stat -c%s "$TMP/stegged")
    [ "$ORIG_SZ" = "$NEW_SZ" ] || fail "host size changed ($ORIG_SZ -> $NEW_SZ)"

    ./hydan-decode "$TMP/stegged" > "$TMP/decoded" 2> "$TMP/decode.log" \
        || fail "decode failed for $M"

    cmp -s "$M" "$TMP/decoded" || fail "roundtrip mismatch for $M"

    echo "PASS: roundtrip $(basename "$M")"
done

./hydan-stats "$HOST" > "$TMP/stats.log" 2>&1 || fail "stats failed"
grep -q "Embeddeable insns" "$TMP/stats.log" || fail "stats output unexpected"

echo "PASS: integration tests"
