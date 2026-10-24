# Sigma rules

Custom Sigma detections for this homelab. Each rule targets a specific threat pattern observed or anticipated in our environment.

## Mapping to Wazuh

Sigma rules are vendor-neutral. To use these in Wazuh, convert via `sigma-cli` or hand-translate into Wazuh's XML rule format under `/mnt/cache/appdata/wazuh/manager/etc/rules/local_rules.xml`.

## Future location

These will be mirrored to a Forgejo repo at `forgejo.sol.example.com/<owner>/sigma-rules` for versioning. Until then, they live here.

## Adding new rules

- Filename: `<short-name>.yml`
- Use `level: low|medium|high|critical` (Sigma convention) — not Wazuh's numeric levels
- Always include `falsepositives:` section with known triggers to refine over time
- Reference primary log source (`logsource:` block) — Wazuh decoder name when applicable
