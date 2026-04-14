#!/usr/bin/env bash
#
# test_queries.sh — end-to-end test for runZeroHound:
#   1. Convert sample-runzero.jsonl → opengraph JSON
#   2. Purge the BloodHound CE database
#   3. Upload the converted file and wait for ingest
#   4. Run every query from QUERIES.md and verify it succeeds
#
# Usage:
#   ./test_queries.sh               # full run (convert, purge, upload, query)
#   ./test_queries.sh --skip-load   # skip convert/purge/upload, wait for pending ingest, then run queries
#
# Prerequisites:
#   - go build has been run (or use "go run .")
#   - BLOODHOUND_URL, BLOODHOUND_USERNAME, BLOODHOUND_PASSWORD (or token vars) are set
#
set -euo pipefail

SKIP_LOAD=false
if [[ "${1:-}" == "--skip-load" ]]; then
    SKIP_LOAD=true
    shift
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BINARY="go run ${SCRIPT_DIR}/."
SAMPLE="${SCRIPT_DIR}/examples/"
CONVERTED=$(mktemp /tmp/runzerohound-test-XXXXXX.json)
QUERIES_MD="${SCRIPT_DIR}/QUERIES.md"

trap 'rm -f "$CONVERTED"' EXIT

# ---- colours ----
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Colour

pass=0
fail=0
skip=0
failures=()

if ! $SKIP_LOAD; then

# ============================================================
# Step 1: Convert
# ============================================================
echo "==> Step 1: Converting ${SAMPLE}/* to opengraph JSON …"
$BINARY convert -o "$CONVERTED" "$SAMPLE"/* 2>&1 | tail -5
if [[ ! -s "$CONVERTED" ]]; then
    echo -e "${RED}FATAL: converted files are empty${NC}"
    exit 1
fi
echo -e "${GREEN}OK${NC} — wrote $(wc -c < "$CONVERTED" | tr -d ' ') bytes to ${CONVERTED}"
echo

# ============================================================
# Step 2: Purge
# ============================================================
echo "==> Step 2: Purging BloodHound CE database …"
$BINARY purge 2>&1
echo -e "${GREEN}OK${NC} — purge accepted"
echo "  Waiting 30s for background analysis cycle to settle …"
sleep 30
echo -e "${GREEN}OK${NC} — purge settled"
echo

# ============================================================
# Step 3: Upload + wait for ingest
# ============================================================
echo "==> Step 3: Uploading converted opengraph file and waiting for ingest …"
$BINARY upload --wait --wait-timeout 120 "$CONVERTED" 2>&1
echo -e "${GREEN}OK${NC} — upload and ingest complete"
echo

else
    echo "==> Skipping load (--skip-load), waiting for pending ingest jobs …"
    $BINARY upload --wait --wait-timeout 120 2>&1
    echo -e "${GREEN}OK${NC} — ingest idle"
    echo
fi

# ============================================================
# Step 4: Run every query from QUERIES.md
# ============================================================
echo "==> Step 4: Running all queries from QUERIES.md …"
echo

# Extract queries: everything between ```cypher and ``` fences
query_name=""
in_query=false
query=""

run_query() {
    local name="$1"
    local q="$2"

    # Skip empty
    if [[ -z "$q" ]]; then
        return
    fi

    printf "  %-70s " "$name"

    # Run the query, capture stdout + stderr
    output=$($BINARY cypher "$q" 2>&1) || true

    # Check for HTTP errors or Go panics in the output
    if echo "$output" | grep -qi "error:"; then
        echo -e "${RED}FAIL${NC}"
        echo "    Query: $q"
        echo "    Output: $output"
        ((fail++)) || true
        failures+=("$name")
        echo
        echo -e "${RED}Stopping on first failure.${NC}"
        echo "============================================"
        echo "  Results: ${GREEN}${pass} passed${NC}, ${RED}${fail} failed${NC}, ${YELLOW}${skip} skipped${NC}"
        echo "============================================"
        exit 1
    fi

    # Must contain valid JSON with a "data" key
    if echo "$output" | grep -q '"data"'; then
        echo -e "${GREEN}PASS${NC}"
        ((pass++)) || true
    else
        echo -e "${YELLOW}SKIP${NC} (empty/unexpected response)"
        echo "    Output: ${output:0:200}"
        ((skip++)) || true
    fi
}

# Parse QUERIES.md and extract query name + cypher blocks
while IFS= read -r line; do
    # Capture section/query heading
    if [[ "$line" =~ ^###\  ]]; then
        # Strip leading ### and whitespace
        query_name="${line#\#\#\# }"
        # Also strip any leading ### for deeper headings
        query_name="${query_name#\# }"
        query_name="${query_name#\# }"
    fi

    # Start of cypher block
    if [[ "$line" == '```cypher' ]]; then
        in_query=true
        query=""
        continue
    fi

    # End of cypher block
    if $in_query && [[ "$line" == '```' ]]; then
        in_query=false
        run_query "$query_name" "$query"
        query=""
        continue
    fi

    # Accumulate query lines
    if $in_query; then
        if [[ -z "$query" ]]; then
            query="$line"
        else
            query="${query} ${line}"
        fi
    fi
done < "$QUERIES_MD"

# ============================================================
# Summary
# ============================================================
echo
echo "============================================"
echo "  Results: ${GREEN}${pass} passed${NC}, ${RED}${fail} failed${NC}, ${YELLOW}${skip} skipped${NC}"
echo "============================================"

if (( fail > 0 )); then
    echo
    echo -e "${RED}Failed queries:${NC}"
    for f in "${failures[@]}"; do
        echo "  - $f"
    done
    echo
    exit 1
fi

echo
echo -e "${GREEN}All queries passed!${NC}"
