# Threat Model

This threat model describes the Phase 1 local lab. It is scoped to deliberately vulnerable Docker services and synthetic telemetry.

## Assets

- Breaker state for `feeder-01-main-breaker`
- RTU telemetry values
- RTU event log
- SCADA command correlation records
- HMI operator controls
- JSON detection logs
- Curated evidence outputs

## Trust Boundaries

- Browser to HMI backend over HTTP
- HMI backend to SCADA Master over Docker-internal HTTP
- SCADA Master to RTU over TCP JSON-lines
- Attacker container to RTU over direct TCP JSON-lines

The important Phase 1 trust boundary is the RTU field protocol interface. The lab intentionally models a weak field-device interface that accepts unauthenticated or weakly validated control messages.

## Assumptions

- This is a local, authorized lab.
- The RTU field protocol is unauthenticated in Phase 1.
- `RTU_VULNERABLE_MODE=true` is the default.
- Client-provided fields such as `source.id`, `source.role`, `session_id`, and `command_origin` are untrusted metadata.
- Docker network peer information is useful as a hint but is not strong identity.
- The HMI never talks directly to the RTU.

## Primary Attack Path

An attacker connects directly to the RTU field protocol interface and sends `EXECUTE_BREAKER OPEN`.

The attacker claims:

```json
{
  "source": {
    "id": "scada-master",
    "role": "SCADA_MASTER"
  }
}
```

The command lacks a valid select-before-operate token and lacks a SCADA-issued command correlation record. In vulnerable mode, the RTU records detections but still executes the command.

## Impact

- Unauthorized breaker operation
- HMI state changes from `CLOSED` to `OPEN`
- Current/load drop near zero
- Operator alarm
- Event chronology includes spoofed source claims
- SCADA detects missing local workflow evidence

## Detection Signals

RTU-side signals:

- `COMMAND_WITHOUT_VALID_SELECT`
- `SEQUENCE_ANOMALY`
- `TIMESTAMP_ANOMALY`
- `CLAIMED_SOURCE_MISMATCH`
- `DIRECT_FIELD_INTERFACE_CONTROL`

SCADA-side signals:

- `UNKNOWN_CORRELATION_ID`
- `UNMATCHED_BREAKER_TRANSITION`
- `RTU_EVENT_WITHOUT_LOCAL_PENDING_COMMAND`
- `UNEXPECTED_BREAKER_STATE_AFTER_POLLING`

Detection should not rely only on `source.role`. The default attack claims `SCADA_MASTER`; detection still fires because workflow evidence is missing.

## Mitigations

These mitigations are documented for security analysis. They are not implemented in Phase 1:

- strong command authentication
- mutual authentication on field protocol links
- message signing
- replay protection
- strict select-before-operate enforcement
- SCADA command correlation enforcement
- network segmentation and allowlisting
- engineering workstation hardening
- event logging and monitoring
- time synchronization monitoring

## Limitations

- The RTU and SCADA Master are simplified Python services.
- The field protocol is IEC 104-inspired, not standards-compliant IEC 60870-5-104.
- Docker peer information is not equivalent to production network identity.
- There is no physical hardware, relay logic, or power-flow solver in Phase 1.
