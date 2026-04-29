# Evidence

This directory stores curated validation outputs for portfolio review.

Runtime logs under `logs/` are temporary. They can contain stale records if the lab has been run multiple times. Use the Makefile targets below to reset logs and generate isolated evidence.

## Normal SCADA Workflow Evidence

Generate and validate:

```bash
make evidence-normal
make validate-normal-evidence
```

Saved under:

```text
evidence/phase1-normal-scada-workflow/
```

This evidence shows:

- legitimate HMI/SCADA select-before-operate workflow
- normal `SELECT_BREAKER` and `EXECUTE_BREAKER` RTU events
- valid select token presence and validation
- command responses with `detections: []`
- no critical workflow-bypass detections

## Spoofed Direct RTU Attack Evidence

Generate and validate:

```bash
make evidence-attack
make validate-attack-evidence
```

Saved under:

```text
evidence/phase1-spoofed-direct-rtu-attack/
```

This evidence shows:

- attacker uses `spoof-scada` mode
- attacker claims `source.id=scada-master`
- attacker claims `source.role=SCADA_MASTER`
- RTU accepts the command in vulnerable mode
- breaker opens
- current/load drop near zero
- detections fire for workflow, select-token, and correlation failures

## Why The Detection Evidence Matters

The default attacker does not identify as `ATTACKER`. It spoofs SCADA identity. Detection still fires because client-provided identity is treated as untrusted metadata.

The evidence is therefore based on behavior and workflow validation:

- missing or invalid select token
- missing SCADA command correlation
- RTU event without local pending SCADA command
- direct field-interface control
- unexpected breaker state after polling

## Files

Normal workflow evidence includes:

- `close-response.json`
- `open-response.json`
- `status.json`
- `events.json`
- `rtu.jsonl`
- `scada.jsonl`
- `detections.jsonl`

Attack evidence includes:

- `attacker-output.txt`
- `status.json`
- `events.json`
- `rtu.jsonl`
- `scada.jsonl`
- `detections.jsonl`
