# Atlas: The Deterministic Execution Security Standard (DESS)  
Version: v0.1-draft

> Founded and stewarded by Elytra Security.  
> Published under the Creative Commons Attribution-ShareAlike 4.0 International License (CC BY-SA 4.0).

---

## 0. Introduction

### 0.1 Problem context: AI mutating threats

Digital systems are entering an era in which **attackers can continuously mutate their tools, infrastructure, and tactics using AI**. Adversaries can:

- generate and evolve payloads in parallel using large language models and code assistants
- automatically adapt exploits, routes, and indicators of compromise to evade detection
- iteratively probe and refine attacks against defenses in tight feedback loops

Traditional security models that rely primarily on **recognising known bad artifacts** (signatures, indicators of compromise, static rules) are structurally misaligned with this environment. When code, infrastructure, and observable indicators can be regenerated on demand, defenders can no longer depend on **post-facto identification of bad things** as the primary protection strategy.

At the same time, modern software architectures have expanded the effective attack surface:

- pervasive use of dynamic runtimes (JavaScript, Python, Node, JVM, and others)
- complex dependency graphs and software supply chains
- distributed microservices, APIs, and multi cloud topologies
- integrated AI systems and agents with access to data and tools

In this context, **the ability to mutate is a cheap operation for attackers and a costly one for defenders**.

Atlas: The Deterministic Execution Security Standard (DESS) responds to this asymmetry by shifting the defensive emphasis from **detecting malicious artifacts** to **constraining and verifying execution**. Instead of asking “is this code or traffic malicious”, Atlas asks:

- “Is this execution path permitted by policy?”
- “Is this actor’s identity and provenance trustworthy?”
- “Is this behaviour consistent with the allowed, deterministic behaviour of this system?”

If the answer is not provably “yes”, execution **SHOULD NOT** be allowed.

---

### 0.2 Design philosophy

Atlas is built on four foundational ideas:

1. **Deterministic execution over probabilistic detection**  
   Security should be anchored in **clear, enforceable boundaries** about what may execute, where, and under which identities. Detection remains important, but it is secondary to **hard constraints** on behaviour.

2. **Provenance and identity over artifacts and routes**  
   Atlas treats **who produced this, under which process, and through which pipeline** as more important than the immediate appearance of binaries, scripts, or network paths. Execution trust derives from **verifiable provenance**, not from heuristic guesses.

3. **Behaviour first security over indicator first security**  
   Atlas emphasizes **runtime behaviour, policy violations, and systemic patterns** across identity, process, network, and data rather than isolated indicators. Indicators of compromise can change. Core malicious behaviours change much more slowly.

4. **Immutable evidence and accountability by design**  
   Atlas assumes that some attacks will succeed. Systems must therefore be built so that **critical events, decisions, and state changes are durably recorded**, tamper evident, and reconstructable across multiple independent planes such as applications, infrastructure, identity, and logs.

Atlas is intentionally:

- **vendor neutral**: it does not prescribe specific products
- **technology agnostic**: it can be implemented in on premises, cloud, and hybrid environments
- **complementary** to existing standards such as Zero Trust, NIST Cybersecurity Framework, MITRE ATT&CK and D3FEND, ISO 27001, and privacy regulations

Atlas focuses on **how to architect systems** so that these other frameworks can be implemented **in a deterministic, enforceable way** in the presence of AI accelerated adversaries.

---

### 0.3 Scope and applicability

Atlas DESS defines a set of **principles, architectural patterns, and prescriptive controls** for:

- enterprises of all sizes
- SaaS providers and cloud native platforms
- critical infrastructure operators
- government and public sector systems
- AI intensive systems and services

The standard is concerned with:

- how identities, runtimes, networks, data planes, and supply chains are designed and operated
- how execution is authorised, constrained, observed, and recorded
- how evidence is generated and preserved for investigations and assurance
- how AI, automation, and simulation can be used **by defenders** to strengthen posture

Atlas is **not** limited to a specific technology stack. Implementers **MAY** use any combination of languages, operating systems, and infrastructures, provided the resulting architecture satisfies the normative requirements of the standard.

---

### 0.4 Non goals

Atlas DESS explicitly does **not** attempt to:

- define new cryptographic primitives or algorithms
- replace existing legal, regulatory, or privacy frameworks
- re specify existing security control catalogues such as NIST SP 800 53, ISO 27001 Annex A, or CIS Controls
- provide product specific implementation guidance or endorsements

Instead, Atlas aims to provide:

- a **coherent architectural lens** through which existing controls and frameworks can be selected, prioritised, and implemented
- a **deterministic execution model** that can be applied consistently across heterogeneous systems
- a **shared vocabulary and set of expectations** for architects, defenders, regulators, and vendors

---

### 0.5 Definitions and terminology

For the purposes of this standard, the following terms are used with specific meanings:

- **Atlas**  
  The overall framework and body of guidance described in this document: *Atlas: The Deterministic Execution Security Standard (DESS)*.

- **Deterministic execution**  
  Execution of code or workflows in which the **allowed behaviour is explicitly defined and constrained** by policy, identity, and context, and where deviations from those constraints are treated as violations, regardless of apparent intent.

- **Trusted Computing Base (TCB)**  
  The minimal set of components (hardware, firmware, software, configurations, and processes) whose correct behaviour is **critical for enforcing Atlas policies**. Atlas seeks to minimise and harden this base.

- **Provenance**  
  Verifiable information about the origin, creation, modification, and movement of code, configurations, data, and artifacts such as build pipelines, code signing, software bills of materials, and deployment records.

- **Execution boundary**  
  A technical and policy defined boundary within which certain code may run and certain operations may be performed. Examples include an application sandbox, a database sidecar, a policy engine, or a constrained runtime.

- **Immutable evidence**  
  Logs, records, and cryptographically protected artifacts that, once written, **cannot be altered or removed without detection**, and that can be correlated across different planes of the system.

- **Normative language**  
  This specification uses the key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** as described in RFC 2119 and RFC 8174 to indicate requirement levels.

Further terms are defined contextually in later sections where needed.

---

## 1. Core principles of Atlas DESS

This section defines the core principles of Atlas: The Deterministic Execution Security Standard (DESS).  
These principles are **normative**. Implementations that claim conformance with Atlas **MUST** be able to demonstrate how each applicable principle is satisfied.

---

### 1.1 Minimise and harden the Trusted Computing Base

**Principle.**  
Atlas implementations **MUST** minimise the set of components whose correct behaviour is critical to enforcing security policies (the Trusted Computing Base, or TCB) and **MUST** apply stronger assurance, hardening, and monitoring to these components than to the rest of the system.

**Implications.**

At a minimum, the TCB typically includes:

- identity and access management components
- policy decision and enforcement points
- execution control mechanisms (for example, allowlists, sandboxes, sidecars)
- cryptographic key management and root-of-trust elements
- immutable logging and evidence stores

Implementers **SHOULD**:

- reduce the size and complexity of the TCB wherever possible
- avoid embedding critical enforcement logic deep inside large, rapidly changing codebases
- isolate TCB components from general application logic, both logically and physically (for example, separate processes, hosts, or trust zones)

---

### 1.2 Enforce deterministic execution boundaries

**Principle.**  
Atlas implementations **MUST** define and enforce explicit execution boundaries that describe **what is allowed to run, where, and under which identities**, and **MUST** treat execution outside these boundaries as a policy violation, regardless of apparent intent or content.

**Implications.**

Implementers **MUST**:

- define allowed execution paths for critical operations (for example, data access, configuration changes, deployment, and administrative actions)
- ensure that code and workflows can only execute within pre-defined, policy-constrained environments (for example, sandboxes, sidecars, or constrained runtimes)
- prevent arbitrary or ad hoc execution of code in high-value environments (for example, unrestricted shells on production systems, dynamic code evaluation in privileged contexts)

Implementers **SHOULD** prioritise **denial of execution** for unknown or unverifiable code over reliance on post-execution detection.

---

### 1.3 Make identity the primary perimeter

**Principle.**  
Atlas implementations **MUST** treat **identity, not network location, as the primary perimeter** for authorisation decisions. All execution and access decisions **MUST** be tied to authenticated, auditable actor identities (human, service, device, or workload).

**Implications.**

Implementers **MUST**:

- require strong, multi-factor, and context-aware authentication for human and non-human actors
- bind permissions and policies to identities and roles rather than to IP addresses, subnets, or static network locations
- ensure that tokens, credentials, and service identities are scoped, time-limited, and revocable

Implementers **SHOULD**:

- minimise the use of shared, anonymous, or “god mode” accounts
- apply stricter controls and logging to high-privilege identities and administrative operations

---

### 1.4 Anchor trust in provenance, not appearance

**Principle.**  
Atlas implementations **MUST** base execution trust on **provenance** (where code, configurations, models, and artifacts came from and how they were produced) rather than on superficial characteristics (file names, hashes, or signatures alone).

**Implications.**

Implementers **MUST**:

- establish verifiable build and deployment pipelines for software, configuration, and infrastructure-as-code
- maintain software bills of materials (SBOMs) and associated metadata for critical components
- use code signing or equivalent mechanisms to ensure that only artifacts produced by approved processes can be executed or deployed

Implementers **SHOULD**:

- reject or strongly isolate artifacts with unknown or unverifiable provenance
- treat deviations from expected provenance (for example, unexpected build systems, repositories, or toolchains) as material risk indicators

---

### 1.5 Separate control, data, and evidence planes

**Principle.**  
Atlas implementations **MUST** separate the **control plane**, **data plane**, and **evidence plane** so that compromise of one plane does not trivially compromise the others.

**Implications.**

- The **control plane** manages configuration, policies, and orchestration.
- The **data plane** handles operational traffic and workloads.
- The **evidence plane** records logs, events, and artefacts required for investigation and assurance.

Implementers **MUST**:

- ensure that operational workloads cannot directly tamper with or erase evidence
- avoid running high-privilege control plane components in the same trust zone as untrusted or external-facing workloads
- ensure that evidence generated by one plane is cross-checked or corroborated by others, where feasible

Implementers **SHOULD**:

- use independent trust anchors (for example, separate credentials, infrastructure, or providers) for the evidence plane
- log control-plane changes (for example, policy updates, configuration changes) into evidence stores by default

---

### 1.6 Use sidecars and constrained intermediaries for sensitive operations

**Principle.**  
Atlas implementations **SHOULD** use **sidecars and constrained intermediaries** to mediate access to sensitive resources (for example, databases, key management systems, or critical APIs), so that application runtimes never interact with those resources directly.

**Implications.**

Implementers **SHOULD**:

- terminate direct database access from general-purpose application code
- enforce access to sensitive systems through sidecars or gateways that implement validation, policy enforcement, and logging
- ensure that credentials for sensitive resources are held only by these intermediaries, not by application code

When sidecars or intermediaries form part of the TCB, they **MUST** be hardened and monitored accordingly.

---

### 1.7 Prioritise behaviour-first detection and correlation

**Principle.**  
Atlas implementations **MUST** prioritise detection based on **behaviour, policy violations, and correlated signals across planes**, rather than relying solely on static signatures or isolated indicators of compromise.

**Implications.**

Implementers **MUST**:

- collect and correlate signals from identity, endpoint, network, application, and evidence planes
- define and monitor for behaviours that are inherently high-risk (for example, unusual privilege escalations, unexpected lateral movement, manipulation of routes or logging configurations)
- treat attempts to bypass or tamper with enforcement or logging mechanisms as high-severity events, regardless of whether obvious “malware” is detected

Implementers **SHOULD**:

- maintain baselines of normal behaviour for critical systems and identities
- use AI and advanced analytics to surface anomalies, while keeping final enforcement and response decisions within deterministic, policy-driven boundaries

---

### 1.8 Design for immutable, reconstructable evidence

**Principle.**  
Atlas implementations **MUST** ensure that critical security-relevant events and state changes are recorded as **immutable, tamper-evident evidence** and that the system state can be reconstructed to a useful degree after an incident.

**Implications.**

Implementers **MUST**:

- write key events (for example, authentication, authorisation decisions, configuration changes, deployment events, sensitive data access, and policy updates) to append-only or tamper-evident stores
- retain evidence for a period consistent with legal, regulatory, and risk requirements
- protect evidence stores with strong access controls, separate from general operational access

Implementers **SHOULD**:

- use cryptographic mechanisms (for example, hashing, chaining, signing) to detect tampering with evidence
- design logging and evidence schemas to support later correlation, investigation, and reporting without extensive manual reconstruction

---

### 1.9 Use AI and automation symmetrically, with constraints

**Principle.**  
Atlas implementations **SHOULD** use AI, simulation, and automation to strengthen defensive posture (for example, through testing, red teaming, anomaly detection, or response), but **MUST** keep AI-driven actions within clearly defined, auditable, and reversible policy boundaries.

**Implications.**

Implementers **SHOULD**:

- use AI to generate and simulate attack variants against their own architectures
- continuously test enforcement points, sidecars, and policies against AI-generated probes
- use AI to assist human defenders in triage and investigation

Implementers **MUST NOT**:

- grant AI agents unconstrained access to sensitive systems, data, or tools without clear guardrails
- delegate irreversible or high-impact security actions (for example, mass revocation, destructive changes) to AI without human oversight and explicit policy

---

These principles are expanded and instantiated as specific architectural requirements and controls in subsequent sections of this specification.
## 2. Architectural pillars of Atlas DESS

Atlas defines security not as a single mechanism, but as a coordination framework across multiple independent planes. Each plane operates under deterministic execution boundaries and shared principles (Section 1), but they fulfil distinct roles.

An implementation claiming conformance with Atlas **MUST** establish and govern each applicable pillar defined in this section. The specific mechanisms may vary by environment, but the architectural separation and intent **MUST** be preserved.

---

### 2.1 Identity and Trust Plane

The Identity & Trust Plane governs how actors (human, service, workload, device) are authenticated, authorised, and tied to policy obligations.

Implementations **MUST**:

- bind execution and access to authenticated identities
- enforce least privilege and role constraints at all trust boundaries
- ensure replaceability and revocation of identities without system-wide disruption

Implementations **SHOULD**:

- use strong multi-factor authentication for human identities
- bind workload identities to attested pipelines and provenance
- treat identity escalation paths as highly sensitive control points

This plane is the primary enforcement anchor for all other planes.

---

### 2.2 Runtime & Execution Plane

The Runtime & Execution Plane governs how code runs, under what constraints, and within which boundaries.

Implementations **MUST**:

- define explicitly allowed execution contexts (e.g., sandboxes, sidecars, constrained runtimes)
- restrict execution outside predefined environments
- block or isolate dynamic code evaluation in high-trust contexts

Implementations **SHOULD**:

- segregate TCB components from general-purpose runtime environments
- enforce runtime allowlisting for critical workloads
- detect attempts to bypass execution boundaries as policy violations

This plane directly enables deterministic execution.

---

### 2.3 Network & Transport Plane

The Network & Transport Plane governs how actors communicate, request resources, and move laterally.

Implementations **MUST**:

- enforce identity-bound access, not location-bound (e.g., trust IAM over IP)
- treat network paths as derivable artifacts, not security primitives
- validate and constrain routing, service discovery, and peer communication

Implementations **SHOULD**:

- segment workloads into minimal trust zones
- enforce strong encryption in transit
- detect behavioural anomalies such as dynamic routing manipulation or covert channels

Network topology MUST be observable and policy-enforced, not emergent or self-mutating.

---

### 2.4 Data & State Plane

The Data & State Plane defines how data is accessed, stored, mutated, and protected across its lifecycle.

Implementations **MUST**:

- enforce deterministic paths for access to sensitive data
- separate data control (schemas, policies) from data operations (queries, writes)
- prevent direct access from untrusted runtimes to primary data stores

Implementations **SHOULD**:

- use constrained intermediaries (e.g., sidecars, data gateways)
- maintain lineage and provenance for critical data flows
- enforce immutability for high-integrity records

Data planes MUST support reconstruction of state after incidents.

---

### 2.5 Software Supply Chain & Provenance Plane

This plane governs the origin, transformation, and movement of code, artefacts, configurations, and models.

Implementations **MUST**:

- enforce trusted build and deployment pipelines
- validate provenance before execution or deployment
- detect and reject artefacts with unverifiable origins

Implementations **SHOULD**:

- embed SBOM metadata into build outputs
- sign artefacts at pipeline boundaries
- record provenance events into immutable evidence stores

This plane anchors “trust before run”.

---

### 2.6 Evidence & Observability Plane

This plane governs how systems record, retain, and protect security-relevant events.

Implementations **MUST**:

- generate immutable, append-only evidence correlated across planes
- record identity, execution, network, and data events with timestamps and proofs
- prevent workloads from modifying or erasing their own evidence

Implementations **SHOULD**:

- use cryptographic chaining or signing to verify integrity
- retain evidence for regulatory and investigative timelines
- maintain cross-plane reconciliation for high-impact events

This plane is foundational for incident response, audit, and assurance.

---

### 2.7 Control Plane

The Control Plane governs configuration, orchestration, policy, and administration.

Implementations **MUST**:

- isolate the control plane from the execution and data planes
- log all policy changes and privileged actions as evidence
- enforce strong identity controls for administrative functions

Implementations **SHOULD**:

- separate read, operate, and administer privileges
- validate configuration changes against deterministic policy constraints
- require explicit approvals or governance workflows for high-impact changes

The compromise of the control plane is treated as system-critical.

---

### 2.8 AI & Automation Plane

This plane governs how AI systems interact with protected environments.

Implementations **MUST**:

- apply deterministic policy boundaries to AI-driven execution
- restrict autonomous access to sensitive systems or irreversible actions
- log AI decisions and tool interactions into the evidence plane

Implementations **SHOULD**:

- use AI for defender-side simulation and red-teaming
- detect manipulation attempts targeting AI agents, models, or prompts
- establish feedback loops between behavioural detection and AI simulation

This plane operationalises AI symmetrically for defense.

---

### 2.9 Governance & Verification Plane

This plane enforces accountability, review, and assurance of system-wide behaviour.

Implementations **MUST**:

- define explicit responsibility and ownership for each plane
- implement cross-plane verification of state, identity, policy, and evidence
- review controls periodically against threat evolution

Implementations **SHOULD**:

- maintain public change logs or versioned governance documents
- incorporate independent verification or external audit
- establish escalation paths for architectural drift from deterministic principles

Governance binds the system to ongoing correctness, not just initial design.

