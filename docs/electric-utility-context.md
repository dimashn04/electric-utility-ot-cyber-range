# Electric Utility Context

This project is an independent, software-only OT security research and learning lab. It uses synthetic services, synthetic telemetry, and local Docker components to explore electric utility cybersecurity concepts around SCADA, RTU control, HMI visibility, field-device trust boundaries, and detection engineering.

## Technical Context

Electric utility OT security often involves control and monitoring workflows across operator interfaces, SCADA masters, and field devices. Phase 1 focuses on a simplified distribution feeder scenario:

- HMI operator visibility
- SCADA command workflow
- RTU-owned field state
- breaker open/close control
- feeder telemetry
- direct field-protocol abuse
- detection of invalid control workflow
- evidence collection for normal and attack paths

The lab is intentionally small, but it preserves important security questions:

- Can the RTU distinguish a legitimate SCADA workflow from a direct field-protocol client?
- Are client-provided identity fields treated as untrusted metadata?
- Does the HMI show operational impact when field state changes?
- Can SCADA correlate RTU events with local command records?
- Can evidence prove the difference between normal workflow and attack behavior?

## Public Sector Context

Public electric-utility materials commonly discuss smart grid modernization, AMI, real-time monitoring, distribution automation, command-center operations, and critical-infrastructure cybersecurity. Indonesian public materials from PLN are included in this repository only as examples of these broader sector themes.

Those public references are contextual anchors. They are not dependencies, datasets, endorsements, or implementation sources unless explicitly stated.

See [Public References And Context](references.md) for links and source notes.

## Portfolio Signal

The Phase 1 lab demonstrates:

- understanding of HMI, SCADA, and RTU roles
- select-before-operate command workflow
- why client-provided source identity is weak evidence
- how a direct field-protocol client can bypass intended operator workflow
- how detection can correlate RTU events with SCADA command records
- how operational impact can be shown through HMI telemetry and breaker state

## Honest Limitations

- The protocol is IEC 104-inspired, not compliant IEC 60870-5-104.
- The services and telemetry are synthetic.
- There is no physical RTU, relay, PLC, IED, smart meter, or hardware-in-the-loop component.
- Phase 1 is designed for local education, portfolio demonstration, and detection reasoning.

## Safety Boundary

This project runs entirely inside a local Docker lab using synthetic services and telemetry. Do not use it against systems you do not own or have explicit authorization to test.
