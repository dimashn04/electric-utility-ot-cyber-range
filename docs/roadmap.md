# Roadmap

The roadmap describes possible future phases. These features are not implemented in Phase 1.

## Phase 1: IEC 104-Inspired SCADA Lab

Status: implemented.

- RTU simulator
- SCADA Master
- HMI dashboard
- attacker script
- JSON logs
- curated evidence generation
- normal workflow validation
- spoofed direct RTU attack validation

## Phase 2: IEC 104-Inspired Protocol Abuse Expansion

Potential additions:

- general interrogation abuse
- telemetry replay
- timestamp tampering
- sequence desynchronization
- unauthorized close command
- richer IEC 104-inspired ASDU-style fields
- clearer protocol parser tests

## Phase 3: Physics-Aware Validation

Potential additions:

- simple distribution feeder model
- voltage/current/load consistency checks
- plausible false data injection
- breaker/load impossible-state detection
- rate-of-change anomaly checks

## Phase 4: IEC 61850 Digital Substation Simulation

Potential additions:

- simulated IED roles
- MMS-style control concepts
- GOOSE-style event messaging
- SCL/ICD/CID/SCD documentation concepts
- substation HMI concepts

## Phase 5: AMI Simulator

Potential additions:

- simulated smart meters
- data concentrator
- head-end service
- MDMS-style API
- remote disconnect authorization flaw

## Phase 6: Fuzzing Harness

Potential additions:

- protocol parser fuzzing
- seed corpus
- crash triage
- minimized reproducers
- exploitability notes

## Phase 7: Detection Pack

Potential additions:

- PCAP-backed examples
- Suricata-like rules
- Sigma-like rules
- Wazuh-style rules
- Zeek-style logs

## Scope Discipline

Future phases should be added incrementally. Each phase should include a demo path, evidence artifacts, and validation checks before adding more surface area.
