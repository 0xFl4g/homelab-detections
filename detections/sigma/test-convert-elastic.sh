#!/bin/bash
# Self-test for convert-elastic.sh: converts tests/lab/ and checks the homelab lab-rule contract.
set -euo pipefail
cd "$(dirname "$0")"
out=$(./convert-elastic.sh "$PWD/tests/lab")
W='.[] | select(.rule_id == "homelab-lab-selftest-whoami")'
L='.[] | select(.rule_id == "homelab-lab-selftest-id-linux")'
fail=0
check() { if jq -e "$2" >/dev/null <<<"$out"; then echo "ok   $1"; else echo "FAIL $1"; fail=1; fi; }
check "two rules"             'length == 2'
check "rule_ids"              '[.[].rule_id] | sort == ["homelab-lab-selftest-id-linux", "homelab-lab-selftest-whoami"]'
check "lab + homelab tags"    'all(.tags | (index("lab") != null) and (index("homelab") != null))'
check "no autoblock/notify"   '[.[].tags[] | select(test("autoblock|notify"; "i"))] | length == 0'
check "lab index"             'all(.index == ["logs-*-lab"])'
check "windows eql query"     "$W"' | .language == "eql" and (.query | test("whoami"; "i"))'
check "linux ECS fields"      "$L"' | .query | test("process\\.executable") and test("process\\.command_line")'
check "no Sigma field names"  'all(.query | test("\\b(Image|CommandLine|ParentImage|ParentCommandLine|TargetFilename)\\b") | not)'
check "house look-back kept"  'all((has("from") or has("interval") or has("meta")) | not)'
check "no sigma id field"     'all(has("id") | not)'
check "house license kept"    'all(has("license") | not)'
check "process start filter"  'all(.query | startswith("process where event.type == \"start\" and ("))'
# one bad file must fail the whole batch and print nothing (a partial array would be pushed)
if b=$(./convert-elastic.sh "$PWD/tests/lab-broken" 2>/dev/null); then echo "FAIL broken batch exits non-zero"; fail=1
elif [ -n "$b" ]; then echo "FAIL broken batch prints nothing"; fail=1
else echo "ok   broken batch fails cleanly"; fi
exit $fail
