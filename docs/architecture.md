# Current Architecture

The current implementation is a compact software-only electric utility OT cyber range. It models the control path, field-device state, HMI visibility, direct field-protocol abuse, reconnaissance-style interrogation, and detection evidence for a small simulated distribution feeder.

It is intentionally simplified and runs entirely inside a local Docker lab with synthetic services and telemetry. It is not a standards-compliant IEC 60870-5-104 implementation.

## High-Level Flow

```text
Browser HMI -> HTTP/JSON -> HMI Backend -> HTTP/JSON -> SCADA Master
SCADA Master -> TCP JSON-lines -> RTU Simulator
Attacker -----------------------> TCP JSON-lines -> RTU Simulator
```

The HMI never talks directly to the RTU. The normal authorized path for breaker operation is HMI to SCADA Master to RTU.

## Services

| Service | Interface | Responsibility |
| --- | --- | --- |
| `hmi` | Host `http://localhost:18081` | Serves the browser HMI and proxies `/api/*` calls to the SCADA Master. |
| `scada-master` | Docker-internal HTTP `8000` | Polls RTU telemetry, performs select-before-operate, stores command correlation records, exposes status/events to HMI. |
| `rtu-simulator` | Docker-internal TCP `2404` | Owns authoritative breaker state, generates telemetry, records RTU events, detects invalid field-control workflow. |
| `attacker` | Run-on-demand container | Sends direct TCP JSON-lines attack traffic to the RTU for the implemented abuse scenarios. |

## Field Protocol

The SCADA Master and attacker talk to the RTU using TCP JSON-lines. Each request is one JSON object followed by a newline; each response is one JSON object followed by a newline.

The message envelope includes IEC 104-inspired fields:

- `sequence`
- `timestamp`
- `cause_of_transmission`
- `originator_address`
- `common_address`
- `information_object_address`

It also includes workflow and evidence fields:

- `correlation_id`
- `session_id`
- `command_origin`
- `source.id`
- `source.role`
- `target.asset_id`
- `payload.select_token`

Client-provided identity fields are untrusted metadata. They are logged for evidence, but they are not treated as proof of authorization.

## RTU State

The RTU owns:

- breaker state: `OPEN` or `CLOSED`
- voltage, current, frequency, and load telemetry
- alarm state
- select-before-operate tokens
- recent RTU events
- sequence tracking by peer and claimed source

Breaker state affects telemetry:

- `CLOSED`: voltage normal, current/load nonzero, frequency near 50 Hz
- `OPEN`: downstream current/load near zero, frequency remains near 50 Hz

## Normal Breaker Workflow

```text
HMI POST /api/commands/breaker/open
SCADA creates correlation_id
SCADA sends SELECT_BREAKER
RTU returns select_token
SCADA sends EXECUTE_BREAKER with select_token and correlation_id
RTU updates breaker state
SCADA polls telemetry/events
HMI updates from SCADA API
```

Normal operation should produce `detections: []` for command responses and RTU `EXECUTE_BREAKER` events.

## Spoofed Direct RTU Attack Workflow

```text
Attacker connects directly to RTU
Attacker claims source.id=scada-master and source.role=SCADA_MASTER
Attacker sends EXECUTE_BREAKER OPEN without a valid select_token
RTU detects invalid workflow but executes in vulnerable mode
SCADA detects unknown correlation and unmatched breaker transition
HMI shows breaker OPEN, alarm, and detections
```

The detection is based on workflow evidence, select-token validation, SCADA correlation, sequence behavior, and peer hints. It does not depend on the attacker honestly identifying as `ATTACKER`.

## GENERAL_INTERROGATION Abuse Workflow

```text
Attacker connects directly to RTU
Attacker repeatedly sends GENERAL_INTERROGATION
RTU returns synthetic breaker, telemetry, and point-summary data
RTU detects excessive/direct field-interface interrogation
SCADA observes RTU interrogation events and surfaces detections
HMI shows reconnaissance/enumeration detections without breaker state change
```

This scenario models field-protocol reconnaissance/enumeration. It does not operate the breaker and does not add telemetry replay or protocol desynchronization behavior.

## Logs And Evidence

Runtime logs are written to:

- `logs/rtu.jsonl`
- `logs/scada.jsonl`
- `logs/detections.jsonl`

Curated validation evidence is generated under:

- `evidence/phase1-normal-scada-workflow/`
- `evidence/phase1-spoofed-direct-rtu-attack/`
- `evidence/phase2-general-interrogation-abuse/`
