# My SIEM was storing its own passwords: credentials in Docker exec command lines

**Date:** 2026-09-28 · **Severity:** high (internal exposure) · **Status:** resolved

## Summary

While migrating my homelab SIEM from Wazuh to Elastic Security, the helper scripts I used to call the
Elasticsearch and Kibana APIs passed credentials on the `docker exec` command line. A container that ships
every Docker event into the SIEM recorded those command lines, so five service passwords (including the
Elasticsearch superuser) were indexed, hundreds of times, into the same log stores they protect. My own
detection rules surfaced it the same day. I rotated all five credentials, purged the affected documents, moved
every helper to stdin, and changed the log pipeline so command lines are never indexed again.

## Impact

- **Exposed:** five credentials: the `elastic` superuser, `kibana_system`, and the accounts used by the log
  shipper, the Grafana datasource and the auto-block responder.
- **Where:** three internal log stores: Elasticsearch, the Wazuh indexer and Loki. All are LAN-only; none is
  reachable from the internet.
- **Who could have seen them:** anyone with access to the SIEM or the LAN. Every value was invalidated the
  same day it was found. I didn't run a dedicated hunt for misuse; the stores aren't reachable from outside.
- **Side effects of the fix:** 34 failed logins from the Grafana datasource and 1 from the log shipper, all
  in the minutes between a password changing and the consumer restarting.

## Timeline (UTC, 2026-09-28)

| Time | Event |
|---|---|
| Before 12:20 | Phase 2 of the Elastic migration: many API calls through helper scripts, each a `docker exec <container> curl -u elastic:<password> …` |
| ~12:20 | The new auto-block responder goes live |
| 12:26–12:28 | End-to-end test: block, then unblock, a test address. Three unexpected alerts fire |
| Next | Triage: the alerts came from a rule matching threat-intel addresses in container logs. The address it matched was inside **my own `docker exec` command line**, so command lines were being indexed, and with them every credential I had typed into one |
| Same day | Helpers rewritten to pass credentials and request bodies on stdin; all five credentials rotated and their consumers restarted; 16,140 log documents holding helper command lines deleted from Elasticsearch; the Wazuh store checked (none left) |
| 09-28/29 | Log pipeline changed: Docker `exec_create` events keep only the program name; `exec_start`/`exec_die` are dropped. Unit tests pin both |
| 09-29 | The same trim applied to the Loki path. Loki could not delete data (its delete API was disabled), so the already-invalid values aged out; Loki was retired on 10-08 |

## How it was found

Not by looking for it. The responder test produced three alerts that shouldn't have existed. Following them
back showed the rule was right: a threat-intel address really was in a log line. The log line was my own
command, recorded by the Docker-events shipper. That raised the real question: what else had I typed into
`docker exec`? The answer was `curl -u elastic:…`, many times over.

## Root cause

Two reasonable decisions combined badly:

1. **Docker events carry the full argv.** `exec_create` and `exec_start` events include the complete command
   line. I shipped all Docker events to the SIEM on purpose, because container lifecycle events are useful
   security telemetry.
2. **The helpers put secrets in argv.** `docker exec es curl -u user:password …` is the obvious way to call an
   API inside a container, and it works. It also writes the password into the event stream, into the process
   table, and into anything that reads either.

Neither was wrong alone. Together they turned the SIEM into a password store.

## What changed

- **Secrets travel on stdin, never argv.** The helpers now look like
  `printf '%s\n' "user:$PW" | docker exec -i es sh -c 'IFS= read -r U; exec curl -u "$U" …'`, and request
  bodies go over stdin too (`--data-binary @-`). A recorded exec event now shows only `sh -c IFS= read -r U`.
- **The pipeline doesn't index command lines.** Only `exec_create <program>` reaches the SIEM, enforced by
  pipeline unit tests that fail if a full command line gets through.
- **It's written down where it gets read.** "Never put a secret in a `docker exec` command line" is a standing
  rule in the repo's instructions and is copied into every plan since that touches the hosts.
- **Commits are checked by value (10-02).** The pre-commit hook scans staged changes for secret shapes and
  values, and never prints what it found.

## It happened again, differently (09-30)

Two days later, during a read-only health sweep, an AI coding agent I was using hit a helper script that failed
silently. To debug it, the agent ran it with `bash -x`. Because the script sources an `.env` file, xtrace
printed every value in it into the agent's session log. My instructions to the agent said "don't print
secrets", but not "don't xtrace".

What changed: the helpers now fail loudly on bad input (no silent failure to debug), and every instruction set
for automated work on the hosts now explicitly forbids xtrace on scripts that source secrets.

## Lessons

- **Your telemetry pipeline is in scope.** Anything that records commands records the secrets in them. Decide
  what a log line may contain before shipping it, not after.
- **Argv is public.** Treat a command line like a log line: secrets go on stdin or in files with tight
  permissions.
- **Unexpected alerts are gifts.** The rule that "misfired" was working; following it instead of suppressing
  it found the real problem.
- **Write the rule as the specific behaviour.** "Don't leak secrets" didn't prevent the second incident.
  "Never run `bash -x` on a script that sources `.env`" would have.
