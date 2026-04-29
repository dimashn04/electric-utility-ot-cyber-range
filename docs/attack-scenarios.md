# Attack Scenarios

Phase 1 includes one complete, validated attack path. The goal is to demonstrate a realistic workflow violation without targeting real infrastructure.

## Scenario: Unauthorized Breaker Open With Spoofed SCADA Identity

Objective: show that a direct field-protocol client can operate a breaker when the RTU accepts weakly validated control messages.

### Preconditions

- Lab is running with `docker compose up --build`.
- HMI is available at `http://localhost:18081`.
- `RTU_VULNERABLE_MODE=true`.
- Breaker is initially `CLOSED`.

To ensure a clean precondition through the HMI/SCADA path:

```bash
curl -fsS -X POST http://localhost:18081/api/commands/breaker/close
```

### Attack Command

```bash
docker compose run --rm attacker python attacks/unauthorized_breaker_open.py
```

Default mode is `spoof-scada`.

### Expected Attacker Behavior

- Attacker connects directly to `rtu-simulator:2404`.
- Attacker claims `source.id=scada-master`.
- Attacker claims `source.role=SCADA_MASTER`.
- Attacker sends `EXECUTE_BREAKER OPEN`.
- Attacker has no valid `select_token`.
- Attacker has no valid SCADA command workflow correlation.
- RTU accepts the command in vulnerable mode.

### Expected HMI Result

- Breaker symbol changes to `OPEN`.
- Downstream feeder/load line shows de-energized state.
- Current/load drop near zero.
- Alarm banner activates.
- Recent RTU event shows a spoofed direct `EXECUTE_BREAKER` command.
- SCADA detections show workflow, select-token, and correlation failures.

### Expected Evidence

Use the evidence target for repeatable validation:

```bash
make evidence-attack
make validate-attack-evidence
```

Evidence is saved under:

```text
evidence/phase1-spoofed-direct-rtu-attack/
```

Important files:

- `attacker-output.txt`
- `status.json`
- `events.json`
- `rtu.jsonl`
- `scada.jsonl`
- `detections.jsonl`

### Detection Rules Expected

RTU-side:

- `COMMAND_WITHOUT_VALID_SELECT`
- `DIRECT_FIELD_INTERFACE_CONTROL`
- `CLAIMED_SOURCE_MISMATCH`
- `SEQUENCE_ANOMALY` when sequence tracking observes a reset or mismatch

SCADA-side:

- `UNKNOWN_CORRELATION_ID`
- `UNMATCHED_BREAKER_TRANSITION`
- `RTU_EVENT_WITHOUT_LOCAL_PENDING_COMMAND`

The default attack does not depend on `source.role=ATTACKER`. It claims SCADA identity and is still detected because workflow evidence is missing.

### Mitigation Discussion

The lab models the vulnerable behavior for demonstration. A hardened design would reject `EXECUTE_BREAKER` unless the command has:

- a valid select-before-operate token
- an authenticated SCADA channel
- a valid SCADA-issued correlation record
- replay protection
- expected sequence behavior
- an authorized network path

## Scenario: GENERAL_INTERROGATION Abuse

Objective: show that a direct field-protocol client can aggressively query the RTU for synthetic process state and point metadata.

This is a reconnaissance/enumeration scenario. It should not change breaker state.

### Preconditions

- Lab is running with `docker compose up --build`.
- HMI is available at `http://localhost:18081`.
- Breaker is `CLOSED`.

### Attack Command

```bash
docker compose run --rm attacker python attacks/general_interrogation_abuse.py --count 20 --delay 0.1
```

Default mode is `spoof-scada`.

### Expected Behavior

- Attacker connects directly to `rtu-simulator:2404`.
- Attacker repeatedly sends `GENERAL_INTERROGATION`.
- RTU returns synthetic breaker state, telemetry, point summary, address-style metadata, latest event index, and timestamps.
- RTU and SCADA detections identify excessive or direct field-interface interrogation.

### Expected HMI Result

- Breaker state remains `CLOSED`.
- Feeder telemetry remains normal.
- Alarm banner activates for GENERAL_INTERROGATION reconnaissance.
- Recent RTU events show repeated `GENERAL_INTERROGATION` activity.
- SCADA detections show excessive or direct field-interface interrogation behavior.

### Expected Evidence

Use the evidence target for repeatable validation:

```bash
make evidence-general-interrogation
make validate-general-interrogation-evidence
```

Evidence is saved under:

```text
evidence/phase2-general-interrogation-abuse/
```

### Detection Rules Expected

RTU-side:

- `EXCESSIVE_GENERAL_INTERROGATION`
- `DIRECT_FIELD_INTERFACE_INTERROGATION`
- `CLAIMED_SOURCE_MISMATCH`
- `INTERROGATION_RATE_ANOMALY`

SCADA-side:

- `RTU_INTERROGATION_WITHOUT_LOCAL_POLLING_CONTEXT`
- propagated RTU interrogation detections
