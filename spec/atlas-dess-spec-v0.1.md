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

---
## 3. Prescriptive Controls and Requirements

This section defines **normative controls** required for conformance with Atlas: The Deterministic Execution Security Standard (DESS).

Each control is identified by:

- **Section Number** (numeric hierarchy, stable across versions)
- **Control Code** (stable mnemonic identifier, prefixed `ATLAS-`)
- **Short Title**
- **Normative Text** using MUST / SHOULD / MAY
- **Outcome Tags** (non-normative categorisation)
- **Optional Non-Normative Notes**

Controls are grouped by **Architectural Pillar** (as defined in Section 2), but **may apply to multiple pillars** through outcome tags.

---

### 3.1 Identity & Trust Controls

Identity and trust controls bind every privileged action, execution, and cross-domain interaction to authenticated, governed principals. These controls eliminate location-based trust, enforce revocability, and ensure that every unit of work operates under a traceable, least-privilege identity scope. They apply equally to humans, services, workloads, devices, and autonomous systems.

---

#### 3.1.1 (ID-BOUND-01) ATLAS-ID-BOUNDARY — Identity-Bound Execution

All execution, configuration changes, data access, and control-plane actions MUST be authorised based on authenticated identities (human, workload, service, or device). Authorization MUST NOT rely solely on network location, static addressing, hostname patterns, or physical placement to grant trust. Each execution context MUST be bound to a single, current identity, and that identity MUST be verifiable at decision time. Anonymous or unauthenticated execution in governed environments MUST be treated as a violation and MUST fail closed.

**Rationale**  
Network and topology-based assumptions fail under adversarial conditions, where routing, IP addresses, or host identities are easily spoofed or tunneled. Identity-bound execution enforces a stable, auditable anchor for authorization decisions, even as workloads move between clusters, clouds, or runtime environments. Binding execution to identity also enables precise revocation, forensics, and least-privilege analysis. Without strict identity binding, later controls on provenance, evidence, and privilege ceilings cannot reliably operate.

**Implementation Notes**  
- Bind all authorization checks to cryptographic identities (certificates, tokens, keys) rather than IP ranges or subnets.  
- Require an authenticated principal for all API calls, CLI operations, and orchestration actions in governed environments.  
- Enforce identity binding in service meshes, API gateways, and control-plane components, not just at login tiers.  
- Ensure logs and evidence capture the acting identity for every significant state change or privileged operation.  
- Treat unauthenticated or “system default” identities as misconfigurations and block their use in TI-2 and TI-3 environments.

**Applies To:** TI-1 (recommended), TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.1.2 (ID-AUTH-02) ATLAS-ID-AUTH-HARDEN — Strong Authentication Requirements

High-privilege human identities (administrators, operators, CI/CD owners, security personnel) MUST use strong, phishing-resistant multi-factor authentication (MFA) bound to hardware or platform authenticators. Non-human identities (services, workloads, agents, schedulers) MUST rely on cryptographically verifiable mechanisms such as mutual TLS, signed tokens, or hardware-bound keys tied to workload identity or equivalent. Password-only authentication MUST NOT be used for high-privilege access or for identities governing TI-2 and TI-3 workloads. Recovery and fallback mechanisms MUST be governed to prevent bypass of strong authentication.

**Rationale**  
Most catastrophic compromises originate from credential theft, phishing, or misuse of weak authentication flows. High-privilege identities that control deployment, configuration, and policy must be significantly harder to subvert than ordinary user accounts. Non-human identities are frequent blind spots, often granted wide access without robust cryptographic protection. By hardening both human and machine authentication, systems reduce the likelihood that an attacker can silently inherit powerful identities and manipulate deterministic boundaries.

**Implementation Notes**  
- Mandate hardware security keys or platform authenticators (for example, WebAuthn) for administrator and operator accounts.  
- Use short-lived, signed tokens or mTLS certificates for services; prohibit static long-lived shared secrets.  
- Enforce strong authentication at all ingress points: VPN, bastion hosts, control-plane dashboards, CI/CD, and API gateways.  
- Govern account recovery flows (helpdesk resets, break-glass accounts) with multi-party approval and TI-3 evidence generation.  
- Periodically test authentication mechanisms against phishing, token replay, and device compromise scenarios.

**Applies To:** TI-1 (recommended for privileged roles), TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.1.3 (ID-SCOPE-03) ATLAS-ID-ROLE-SCOPE — Scoped, Time-Bound Authorisation

Authorisation MUST be scoped to specific actions, resources, and time windows that are no broader than operationally necessary. Standing, unbounded privileges (for example “global admin”, “*:*” action scopes, or permanent root access) MUST be minimised and, for TI-2 and TI-3, SHOULD be eliminated. Just-in-time (JIT) elevation MUST expire automatically after defined periods or upon task completion, and unused grants MUST be revoked without manual intervention. Policies MUST prevent any identity from accumulating privileges beyond its defined ceilings and scopes.

**Rationale**  
Persistent broad privileges significantly increase blast radius when identities are compromised or misused. Over time, operational convenience often leads to privilege creep, where temporary exceptions become permanent configurations. Tight scoping and time-bounded authorisation limit the damage that can result from any single identity compromise and reinforce deterministic expectations of what each principal can do. These constraints are essential for maintaining predictable behaviour, consistent with ATLAS-DESS.

**Implementation Notes**  
- Define fine-grained roles for administration, operation, and read-only functions; avoid catch-all administrator roles.  
- Implement just-in-time elevation systems with automatic expiry and strong authentication at each elevation event.  
- Use policy-as-code to express allowed actions and resources; enforce deny-by-default for unspecified operations.  
- Continuously analyse privilege usage; revoke unused roles and reduce scopes based on observed behaviour.  
- Ensure audit logs capture who granted what privilege, for which scope, and for how long, as TI-2 or TI-3 evidence.

**Applies To:** TI-1 (recommended), TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.1.4 (ID-PROV-04) ATLAS-ID-PROVENANCE — Identity Provenance Enforcement

Workload and service identities MUST be issued only through attested build pipelines and verifiable provenance mechanisms. Identities for code, containers, models, or configurations MUST be cryptographically linked to their originating pipeline, source repository, and trust root. Manual or ad-hoc creation of workload identities (for example, locally generated keys without governance) MUST NOT be permitted in governed environments. Any identity whose provenance cannot be verified MUST be treated as untrusted and blocked from use.

**Rationale**  
If identities can be created outside governed pipelines, attackers can introduce shadow workloads that appear legitimate but bypass supply-chain controls. Binding identities to attested build and signing processes ensures that execution authority flows only from trusted pipelines and not from arbitrary local actions. This continuity of provenance between artifact and identity underpins deterministic execution: the system can assert not just who is acting, but how that actor came into existence.

**Implementation Notes**  
- Integrate identity issuance with CI/CD pipelines such that only successfully attested builds can obtain runtime identities.  
- Embed provenance metadata (for example, build ID, commit, signer, trust root) into identity tokens or associated claims.  
- Prohibit direct generation of service keys or certificates on production hosts; require issuance from centralized, governed services.  
- Validate identity provenance at deployment and periodically at runtime; revoke identities whose provenance records are missing or inconsistent.  
- Ensure provenance chains are stored as TI-2 or TI-3 evidence to support incident reconstruction and compliance reviews.

**Applies To:** TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.1.5 (ID-REVOKE-05) ATLAS-ID-REVOCATION — Revocation & Replaceability

Identities MUST be revocable quickly and reliably without requiring disruptive system-wide redesign or manual, host-by-host reconfiguration. System design MUST anticipate key rotation, identity compromise, and trust-anchor changes, ensuring that new identities can be propagated and old ones invalidated deterministically. Revocation MUST propagate to dependent systems, caches, and long-lived sessions, and execution under revoked identities MUST fail closed. Where revocation is not feasible for a given identity pattern, that pattern MUST NOT be used for TI-2 and TI-3 workloads.

**Rationale**  
Compromise is assumed under ATLAS-DESS; the ability to revoke and replace identities is therefore as important as secure issuance. If revocation requires downtime, manual coordination, or complex migration, organizations will delay or avoid it, leaving compromised identities in active use. Designing for revocability and replaceability from the outset ensures that identities remain a controllable variable rather than an immutable risk. This control is essential for containing incidents and restoring deterministic boundaries after a breach.

**Implementation Notes**  
- Use centralized identity and certificate management capable of bulk revocation and re-issuance with minimal operational friction.  
- Configure short-lived credentials so that revocation is reinforced by natural expiry and frequent rotation.  
- Ensure policy engines, caches, and tokens check revocation status or validate against fresh trust anchors, not just local state.  
- Design client libraries and agents to automatically fetch updated identities and trust bundles without manual intervention.  
- Regularly test revocation drills for high-privilege identities and document time-to-revoke as a tracked resilience metric.

**Applies To:** TI-2 (mandatory), TI-3 (mandatory)

---

### 3.2 Runtime & Execution Controls

Runtime and execution controls ensure that all code, models, and workflows operate only within clearly defined, policy-governed boundaries. These controls constrain where and how execution occurs, separate trusted components from general workloads, and continuously enforce behaviour at runtime rather than relying solely on pre-deployment checks. They are central to eliminating undefined behaviour, limiting blast radius, and preserving deterministic outcomes even under adversarial pressure.

---

#### 3.2.1 (EXEC-BOUND-01) ATLAS-EXEC-BOUNDARY — Defined Execution Boundaries

All code execution MUST occur within predefined, policy-constrained execution environments with explicit limits on permissions, resources, and reachable interfaces. Execution MUST NOT occur directly on uncontrolled hosts, shared global runtimes, or ad-hoc environments whose configuration and boundaries are not governed. Each execution environment MUST have a declared purpose, threat model, and privilege ceiling, and execution MUST fail closed if the environment cannot be verified or instantiated as specified.

**Rationale**  
Undefined or loosely governed execution environments allow attackers to bypass policy by moving workloads into less constrained contexts. When execution boundaries are not explicit and enforced, even correctly signed and tested artifacts can behave unpredictably due to ambient privileges and hidden dependencies. Deterministic security requires execution to be bound to environments whose properties are known, constrained, and repeatable. This enables consistent enforcement, predictable failure modes, and reliable forensics.

**Implementation Notes**  
- Define standard execution profiles (for example, untrusted, standard, sensitive, TCB) with explicit capabilities, resource limits, and network policies.  
- Use containers, virtual machines, or WASM sandboxes with declarative configuration to instantiate each profile deterministically.  
- Prohibit direct execution on bare hosts or ad-hoc shells for governed workloads; require workloads to launch only via approved orchestrators.  
- Enforce that any deviation from the declared execution profile (missing limits, elevated privileges, disabled isolation) blocks start-up.  
- Capture and retain the execution environment manifest (image, configuration, policies) as TI-2 or TI-3 evidence for each critical workload.

**Applies To:** TI-1 (recommended), TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.2.2 (EXEC-TCB-02) ATLAS-EXEC-TCB-SEGREGATION — TCB Isolation from General Workloads

Trusted Computing Base (TCB) components (for example, security policy engines, signing services, key management, orchestration control-planes) MUST execute in environments physically and logically segregated from general-purpose workloads. TCB components MUST NOT share execution runtimes, dependencies, or privilege domains with untrusted or customer-facing workloads. Access paths into TCB environments MUST be strictly minimised and mediated through hardened interfaces with strong identity and policy enforcement.

**Rationale**  
If TCB components share infrastructure or dependencies with untrusted workloads, a compromise in general-purpose code can be leveraged to subvert the very controls meant to enforce ATLAS-DESS. TCB compromise collapses multiple defence layers, enabling attackers to mint identities, adjust policies, or suppress evidence. Segregating TCB execution ensures that the mechanisms enforcing determinism, provenance, and boundaries remain resilient even when outer workloads are compromised.

**Implementation Notes**  
- Run TCB components on separate nodes, clusters, or security domains with distinct credentials, runtime images, and administrative roles.  
- Remove non-essential services, libraries, and interpreters from TCB environments; treat convenience tooling as hostile by default.  
- Apply stricter patch, change-control, and monitoring policies for TCB components than for general workloads.  
- Restrict access to TCB APIs with strong mutual authentication, least-privilege authorisation, and additional approvals for sensitive operations.  
- Continuously validate that TCB components are not co-located with untrusted workloads via automated inventory and configuration checks.

**Applies To:** TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.2.3 (EXEC-ALLOW-03) ATLAS-EXEC-ALLOWLIST — Allowlisted Code Execution

Execution in high-trust and sensitive environments MUST follow an allowlist model in which only explicitly approved, provenance-verified artifacts are permitted to run. Default policy MUST deny execution of unlisted binaries, containers, models, scripts, or plugins, regardless of path or naming. Allowlist entries MUST be tied to specific versions, signatures, and provenance attributes, not generic patterns such as directories or filename wildcards.

**Rationale**  
Relying on detection of “bad” execution is fundamentally reactive and fragile. An allowlist model shifts control to a deterministic assertion of “what is permitted,” narrowing the attack surface to the smallest necessary set of artifacts. When combined with strong provenance and signing, allowlisting prevents arbitrary or tampered code from entering trusted execution zones, even if attackers gain write access to storage or configuration.

**Implementation Notes**  
- Maintain a central, policy-governed registry of approved artifacts, including hashes, signatures, and provenance metadata.  
- Integrate allowlist checks into schedulers, runtimes, and host controls so that non-listed artifacts cannot be executed, loaded, or scheduled.  
- Require change-management and multi-party approval for adding or modifying allowlist entries in TI-2 and TI-3 environments.  
- Enforce that auto-update mechanisms only pull from governed sources and update allowlists atomically with provenance validation.  
- Log all allowlist decisions (allow and deny) and periodically review deny logs for attempted execution of unexpected artifacts.

**Applies To:** TI-1 (recommended for critical systems), TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.2.4 (EXEC-DYN-04) ATLAS-EXEC-DYNAMIC-CONTROL — Restricted Dynamic Execution Sources

Dynamic execution mechanisms (for example, `eval`, reflection-based invocation, dynamic class loading, JIT compilation, plugin loading, and runtime code generation) MUST be strictly controlled, disabled by default, and only enabled where explicitly justified and governed. When dynamic execution is required, it MUST only load or generate code from signed, provenance-verified sources and MUST operate within reduced-privilege sandboxes. Unbounded, data-driven dynamic execution MUST NOT be permitted in TI-2 and TI-3 environments.

**Rationale**  
Dynamic execution paths are a common vehicle for code injection, policy evasion, and runtime mutation, especially when attacker-controlled data influences what is loaded or evaluated. These mechanisms weaken static analysis and supply-chain guarantees by introducing new code paths post-deployment. Constraining dynamic execution to governed, signed, and sandboxed sources preserves the benefits of deterministic build pipelines while still enabling controlled extensibility.

**Implementation Notes**  
- Identify and document all runtime features that permit dynamic loading or code generation in each language and framework in use.  
- Disable or severely restrict these features in configuration (for example, disabling unsafe reflection options, unmanaged plugin directories, or arbitrary `eval`).  
- Where dynamic plugins or modules are required, host them in a governed registry and subject them to the same signing and allowlisting controls as core artifacts.  
- Execute dynamically loaded code in separate, low-privilege sandboxes with constrained capabilities and explicit time and resource limits.  
- Monitor and alert on unexpected use of dynamic execution primitives, treating unapproved usage as a potential intrusion signal.

**Applies To:** TI-1 (recommended), TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.2.5 (EXEC-BREAK-05) ATLAS-EXEC-BREAKOUT-DETECTION — Breakout & Escalation Detection

Execution environments MUST include controls to detect and respond to attempts to escape isolation boundaries (for example, container, VM, or sandbox breakouts) and attempts to escalate privileges beyond the declared ceiling. Indicators of breakout and escalation MUST be monitored at runtime, and attempted or successful breakouts MUST trigger automated containment actions, including termination of affected workloads and elevation of alerting.

**Rationale**  
Isolation mechanisms fail in practice through misconfiguration, kernel or hypervisor vulnerabilities, and exploitation of runtime bugs. Without explicit breakout and escalation detection, an attacker who compromises a single workload can silently pivot into host or control-plane contexts and subvert deterministic guarantees. Embedding breakout-aware telemetry and automated response within execution environments constrains blast radius and reduces the time between compromise and containment.

**Implementation Notes**  
- Instrument runtimes and hosts to detect abnormal behaviour such as privilege changes, namespace escape attempts, filesystem mount anomalies, or unexpected process tree expansions.  
- Use kernel-level tracing (for example, eBPF, seccomp, or equivalent) to monitor sensitive syscalls indicative of breakout or escalation attempts.  
- Define and test automated responses that immediately terminate or quarantine suspect workloads and revoke associated identities.  
- Correlate breakout attempts with supply-chain, identity, and network telemetry to reconstruct the full attack path for TI-3 investigations.  
- Periodically simulate breakout and escalation scenarios in controlled exercises to validate that detection and response mechanisms work as designed.

**Applies To:** TI-1 (recommended), TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.2.6 (EXEC-LANG-06) ATLAS-EXEC-LANGUAGE-HARDENING — Language Runtime Controls

Language runtimes and frameworks (for example, JVM, .NET, Node.js, Python, Ruby) MUST be configured and hardened to minimise attack surface, disable unsafe features, and enforce execution policies. Default configurations MUST NOT be assumed secure; features such as arbitrary reflection, unrestricted native extensions, or dynamic module resolution MUST be constrained or disabled where not strictly necessary. Runtimes that cannot be sufficiently hardened MUST NOT be used for TI-2 and TI-3 workloads.

**Rationale**  
Language runtimes often include powerful capabilities intended for developer convenience that, under attack, provide direct paths to remote code execution, data exfiltration, or boundary bypass. These capabilities can undermine OS-level and container controls if left unconstrained. Hardening runtimes aligns the language-level behaviour with ATLAS-DESS expectations, ensuring that execution semantics remain predictable and resistant to mutation even as workloads evolve.

**Implementation Notes**  
- Maintain hardened baseline configurations per runtime, explicitly disabling or constraining features such as unsafe reflection, JIT debugging hooks, and arbitrary module loading paths.  
- Restrict or review the use of native extensions, FFI, or embedded interpreters that can circumvent higher-level controls.  
- Enforce version control and patch policies for runtimes, ensuring that security patches are applied in a governed, tested manner.  
- Use runtime security modules or policies (for example, security managers, sandbox APIs, or built-in policy frameworks) where available.  
- Continuously review application code for reliance on high-risk runtime features and refactor to safer patterns where feasible.

**Applies To:** TI-1 (recommended), TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.2.7 (EXEC-STATE-07) ATLAS-EXEC-STATE-CONTROL — Constrained Ephemeral Execution State

Ephemeral execution environments (for example, serverless functions, short-lived jobs, ephemeral containers) MUST operate with tightly constrained state, ensuring that secrets, tokens, caches, and intermediate data do not persist beyond their required lifetime or leak across tenants, users, or sessions. Any state that must persist beyond a single invocation MUST be stored in governed, auditable storage services subject to ATLAS-DESS controls, not in local disk or long-lived process memory.

**Rationale**  
Ephemeral environments are often assumed to be “safe by default” due to their short lifetime, but in practice they frequently accumulate residual state, cached secrets, and shared resources. Attackers can exploit these assumptions to retrieve artefacts from previous invocations or to move laterally via shared state. Constraining and explicitly governing the lifecycle of state ensures that ephemeral execution remains truly ephemeral and deterministic in its data exposure.

**Implementation Notes**  
- Design ephemeral workloads to treat local filesystem and in-memory state as disposable, cleared on termination, and inaccessible to future invocations.  
- Prohibit long-lived background processes, daemons, or shared scratch directories in environments intended to be ephemeral.  
- Use dedicated secret management systems for credentials; do not embed secrets in environment variables, code, or local configuration files where they may persist.  
- Partition caches and temporary storage by tenant, user, or execution context, and enforce strict TTLs and size limits.  
- Periodically validate through testing and inspection that no sensitive artefacts persist after workload termination.

**Applies To:** TI-1 (recommended), TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.2.8 (EXEC-POLICY-08) ATLAS-EXEC-POLICY-ENFORCER — Runtime Policy Enforcement Points

Execution policies (for example, allowed syscalls, file paths, network destinations, privilege ceilings, and resource limits) MUST be enforced continuously at runtime, not only at build or deployment time. Policy enforcement points (PEPs) MUST operate as independent controls capable of terminating or constraining workloads that deviate from declared behaviour, even if the artifacts are correctly signed and allowed. PEPs MUST be treated as part of the TCB and monitored for integrity and availability.

**Rationale**  
Attackers routinely exploit runtime-only conditions that static analysis and pre-deployment checks cannot fully predict, such as logic flaws, configuration drift, or environment-specific vulnerabilities. Without active runtime enforcement, a signed and provenance-verified artifact can still behave maliciously or be coerced into doing so. Embedding strong, independent PEPs into the execution path ensures that deterministic policies are upheld under real-world conditions and that deviations are detected and contained promptly.

**Implementation Notes**  
- Deploy enforcement mechanisms such as seccomp profiles, eBPF-based policy agents, mandatory access control (for example, SELinux, AppArmor), or equivalent controls integrated with orchestrators.  
- Express execution policies as code, version-controlled and subject to the same provenance and review processes as application code.  
- Ensure that PEPs can independently deny or terminate execution based on observed behaviour, without requiring approval from the workload itself.  
- Monitor PEP health, decisions, and coverage; treat unexplained PEP disablement, failure, or policy loosening as an incident.  
- Regularly test policies with chaos and fault-injection exercises to ensure they enforce intended constraints without undermining system availability.

**Applies To:** TI-2 (mandatory), TI-3 (mandatory)

---
### 3.3 Network & Transport Controls

Network and transport controls ensure that connectivity between components is explicitly governed, identity-aware, and resistant to manipulation. These controls eliminate location-based trust, constrain lateral movement, require cryptographic protection for all sensitive traffic, and embed detection for routing and covert-channel abuse. They apply equally to intra-cluster, intra-datacenter, inter-cloud, and internet-facing communication.

---

#### 3.3.1 (NET-ID-01) ATLAS-NET-ID-BOUND — Identity-Bound Network Access

Network access MUST be authorised based on authenticated identities (workload, service, device, or user-context), not on IP address, subnet membership, VLAN, or physical topology. Network policies MUST bind permitted flows to explicit identity pairs and purposes (for example, “service A identity → service B identity on port X for API Y”). Location-based rules (such as “trusted IP ranges” or “trusted network segments”) MUST NOT be used as the primary trust mechanism for TI-2 and TI-3 environments.

**Rationale**  
IP addresses, subnets, and topological placement are easily spoofed, tunneled, or reallocated under adversarial conditions. Systems that treat “inside the network” as trusted inevitably collapse when a single host or segment is compromised. Binding network access to identity rather than location ensures that connectivity follows the same deterministic, revocable trust anchors used elsewhere in ATLAS-DESS. This alignment enables coherent least-privilege enforcement and forensics across identity, runtime, and network layers.

**Implementation Notes**  
- Use mutual TLS (mTLS) or equivalent identity-aware transport so that network policies can key off service and workload identities, not IP ranges.  
- Configure network policy engines (for example, service mesh, SDN, eBPF-based policy) to express rules in terms of identity and application protocol, not just IP/port tuples.  
- Prohibit “trusted CIDR” shortcuts for sensitive systems; where CIDR rules exist, treat them as a coarse filter beneath identity-aware controls.  
- Ensure that identity-aware policies cover both north–south and east–west traffic, including intra-node and intra-cluster flows.  
- Log access decisions with both network coordinates and identity attributes to support TI-2 and TI-3 investigations.

**Applies To:** TI-1 (recommended), TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.3.2 (NET-SEG-02) ATLAS-NET-SEGMENTATION — Minimal Trust Zones

Networks MUST be segmented into minimal trust zones that reflect distinct sensitivity, function, and threat exposure, with default-deny policies between zones. High-sensitivity workloads, TCB components, and control-plane services MUST reside in separate zones from general-purpose or internet-facing workloads. Cross-zone access MUST be explicitly authorised, identity-aware, and constrained to the least privilege necessary for the supported use case.

**Rationale**  
Flat or weakly segmented networks allow an initial foothold to be rapidly expanded into full environment compromise through lateral movement. Over time, convenience-driven exceptions erode ad-hoc segmentation, leaving de facto any-to-any connectivity. Deterministic security demands that compromise in one part of the system does not automatically imply compromise everywhere else. Minimal, clearly defined trust zones constrain blast radius and enable targeted, reliable containment.

**Implementation Notes**  
- Design a zone model (for example, public-facing, internal, sensitive, TCB, management) with clear entry/exit criteria and privilege ceilings for each.  
- Enforce default-deny policies between zones, allowing only specific identity- and protocol-bound flows required for operations.  
- Separate tenant environments into distinct zones or overlay segments, avoiding shared flat networks for multi-tenant workloads.  
- Periodically review and prune exceptions; treat broad, long-lived “temporary” rules as violations requiring remediation.  
- Validate segmentation via automated scans and attack-path analysis to confirm that sensitive zones cannot be reached via unintended routes.

**Applies To:** TI-1 (recommended), TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.3.3 (NET-CRYPTO-03) ATLAS-NET-CRYPTO — Encrypted & Authenticated Transport

All network communication carrying sensitive data, control-plane commands, or authentication material MUST be encrypted and authenticated in transit, including “internal” or “east–west” traffic. Cleartext or unauthenticated protocols (for example, HTTP without TLS, plaintext database sessions, unencrypted message queues) MUST NOT be used for TI-2 and TI-3 workloads. Cryptographic configurations MUST use current, vetted algorithms and MUST be governed as part of the organization’s cryptographic policy.

**Rationale**  
Unencrypted or unauthenticated channels allow interception, traffic manipulation, credential theft, and session hijacking, especially in complex environments with shared infrastructure and indirect routing. Assuming internal networks are “safe” contradicts ATLAS-DESS, which treats every boundary as potentially adversarial. Mandatory cryptographic protection ensures that even if the network fabric is compromised, the confidentiality and integrity of traffic remain under deterministic, key-based control.

**Implementation Notes**  
- Standardise on TLS (or equivalent secure transport) for all HTTP, gRPC, database, and message-bus traffic; disallow protocol downgrades.  
- Disable legacy and weak cipher suites; follow current cryptographic best practices and track deprecation of algorithms over time.  
- Use certificate- or key-based identity for services and workloads; avoid shared secrets and long-lived static keys.  
- Implement certificate rotation and automated renewal, ensuring that expired or invalid certificates cause connections to fail closed.  
- Prohibit plaintext administrative protocols (for example, Telnet, unencrypted database consoles); require secure alternatives (for example, SSH, TLS-secured consoles).

**Applies To:** TI-1 (recommended), TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.3.4 (NET-DISC-04) ATLAS-NET-SERVICE-DISCOVERY — Constrained Service Discovery

Service discovery mechanisms (for example, DNS, service registries, mesh control-planes) MUST be constrained so that workloads can only discover and resolve services they are authorised to communicate with. Global, unauthenticated discovery visible to all workloads MUST NOT be used in TI-2 and TI-3 environments. Discovery responses MUST be bound to identity-aware policies so that simply knowing a service name or address does not guarantee connectivity.

**Rationale**  
Unbounded discovery allows attackers to enumerate internal services, identify high-value targets, and probe for weaknesses across the environment. When every workload can see every service, reconnaissance is trivial and segregation is largely illusory. Constraining discovery reduces the effective attack surface and ensures that only workloads with a legitimate need even become aware of sensitive endpoints. This aligns visibility with least privilege, reinforcing deterministic boundaries.

**Implementation Notes**  
- Scope service discovery namespaces per tenant, application, or zone; avoid single global registries for all workloads.  
- Integrate service discovery with identity-aware access control so that unresolved or unauthorised services cannot be reached even if their names are known.  
- Avoid broadcasting internal service metadata to external or low-trust environments (for example, via split-horizon DNS leaks).  
- Monitor discovery queries for anomalous patterns (for example, exhaustive enumeration, dictionary scans) and treat them as potential reconnaissance signals.  
- Periodically review service registries to remove stale, orphaned, or deprecated entries that increase confusion and attack surface.

**Applies To:** TI-1 (recommended), TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.3.5 (NET-ROUTE-05) ATLAS-NET-ROUTE-IMMUTABILITY — Detection of Routing Manipulation

Networks carrying TI-2 and TI-3 workloads MUST implement controls to detect and respond to routing manipulation, including unexpected path changes, poisoning of route tables, SDN policy tampering, and traffic redirection through untrusted intermediaries. Routing and overlay configurations MUST be governed, version-controlled, and monitored for drift. Suspicious routing changes affecting critical paths MUST trigger investigation and, where feasible, automatic containment.

**Rationale**  
Attackers can bypass perimeter and segmentation assumptions by manipulating routing, forcing traffic through inspection points they control, or isolating defenders from key assets. In modern SDN and overlay-heavy environments, routing state is software-defined and subject to attack. Deterministic execution requires that traffic paths match governed expectations; silent, ungoverned route changes undermine all higher-level guarantees, including encryption, logging, and policy enforcement.

**Implementation Notes**  
- Treat routing and SDN policies as code: manage them via version control, change review, and automated validation.  
- Monitor for anomalies such as sudden path length changes, unexpected intermediate hops, or traffic crossing unapproved regions or providers.  
- Implement integrity controls for route distribution (for example, signed route updates, authenticated SDN controllers).  
- Establish baselines for critical flows and alert on deviations, particularly for TCB, key management, and control-plane traffic.  
- Where feasible, enforce pinning of critical flows to approved paths and fail closed or degrade service rather than silently rerouting through untrusted paths.

**Applies To:** TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.3.6 (NET-EGRESS-06) ATLAS-NET-EGRESS-CONTROL — Constrained Egress Paths

Egress traffic from workloads and zones MUST be constrained to a strictly governed set of destinations, protocols, and ports. Default-deny policies MUST apply to outbound connections from sensitive zones, with explicit allow rules for required services (for example, specific APIs, update mirrors, threat-intel feeds). Unrestricted outbound internet access from TI-2 and TI-3 workloads MUST NOT be permitted.

**Rationale**  
Most real-world breaches involve data exfiltration or command-and-control over outbound channels. Unconstrained egress allows attackers to freely communicate with external infrastructure, move stolen data, and maintain persistence. By tightly governing egress, organizations reduce the avenues available for attackers to exploit, and make anomalous outbound behaviour more conspicuous. Deterministic security requires that outbound communication be as controlled as inbound access.

**Implementation Notes**  
- Implement outbound firewalls or policy agents per zone and per workload class, enforcing default-deny for unknown destinations.  
- Use DNS, HTTP proxies, or egress gateways that mediate outbound traffic and apply identity-aware, content-aware controls.  
- Maintain an approved destination list for critical workloads (for example, specific SaaS APIs, update endpoints) and review it regularly.  
- Alert on anomalous egress patterns such as high-volume transfers, unusual destinations or protocols, and non-business-hour spikes.  
- Treat direct outbound access from TCB components as a design smell, limiting such access to tightly justified and monitored cases.

**Applies To:** TI-1 (recommended), TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.3.7 (NET-COVERT-07) ATLAS-NET-COVERT-CHANNELS — Detection of Covert & Side-Channel Traffic

Network monitoring MUST include capabilities to detect probable covert channels and side-channel exfiltration patterns (for example, DNS tunnelling, protocol misuse, steganography over legitimate channels, exfiltration via timing or volume modulation). Systems MUST treat sustained or high-sensitivity anomalies in these patterns as incidents requiring investigation. Where feasible, controls SHOULD actively disrupt suspected covert channels while preserving critical business traffic.

**Rationale**  
Attackers increasingly avoid obvious bulk data transfers in favour of low-and-slow exfiltration and covert signalling over legitimate protocols. Traditional signature-based detection is insufficient when exfiltration piggybacks on business-critical traffic or uses subtle timing and volume cues. Incorporating covert-channel awareness into network defence raises the cost of stealthy operations and aligns monitoring with the deterministic assumption that sensitive data has well-defined, auditable egress paths.

**Implementation Notes**  
- Baseline normal DNS, HTTP(S), and other common protocol behaviours, including query types, response sizes, domain entropy, and timing.  
- Deploy analytics capable of identifying tunnelling indicators (for example, high-entropy subdomains, unusual record types, long-duration low-bandwidth flows).  
- Apply stricter scrutiny to traffic originating from high-sensitivity zones or workloads handling regulated data.  
- Integrate covert-channel detection with egress controls so that suspicious flows can be rate-limited, blocked, or redirected for inspection.  
- Periodically test detection coverage using controlled red-team exercises that simulate realistic covert exfiltration scenarios.

**Applies To:** TI-1 (recommended for critical systems), TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.3.8 (NET-MUTUAL-08) ATLAS-NET-MUTUAL-AUTH — Mutual Auth Between Services

Service-to-service communication in TI-2 and TI-3 environments MUST use mutual authentication, ensuring that both client and server identities are verified before any sensitive data or control operations occur. Relying solely on one-sided authentication (for example, client trusting server identity but not presenting its own) MUST NOT be considered sufficient for high-sensitivity paths. Mutual authentication MUST integrate with the organization’s identity and provenance systems.

**Rationale**  
One-sided authentication allows untrusted or compromised workloads to impersonate legitimate clients as long as they can reach the server. Mutual authentication enforces that both ends of a connection are known, governed principals, dramatically reducing the ability of rogue workloads to consume or manipulate services. This is particularly important where services perform sensitive operations, access regulated data, or influence control-plane state. Deterministic trust requires that all parties to a transaction be explicitly identified and verifiable.

**Implementation Notes**  
- Implement mTLS or equivalent mechanisms where both ends present cryptographic credentials tied to governed identities.  
- Ensure that client identities are bound to CI/CD provenance and role scopes, not generic shared credentials.  
- Configure servers to reject connections lacking valid client authentication, especially on administrative or data-rich endpoints.  
- Propagate authenticated identity information through application layers to support fine-grained authorisation and audit.  
- Periodically test mutual-auth configuration by attempting connections from unauthorised or misconfigured clients and verifying that access is denied.

**Applies To:** TI-1 (recommended), TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.3.9 (NET-RUNTIME-09) ATLAS-NET-RUNTIME-FIREWALL — Dynamic Runtime Network Policy Enforcement

Network policy enforcement for TI-2 and TI-3 workloads MUST operate at runtime, adapting to workload identity, state, and environment rather than relying solely on static perimeter rules or infrastructure-as-code definitions. Runtime network enforcement points MUST be capable of applying per-workload and per-identity policies, detecting anomalous flows, and failing closed when configuration or identity information is unavailable or inconsistent.

**Rationale**  
Static firewall rules and security groups cannot keep pace with dynamic, orchestrated environments where workloads scale, move, and change identity frequently. Attackers exploit gaps between intended policy and actual runtime behaviour, especially when enforcement is anchored only at fixed perimeters. Dynamic, identity-aware runtime enforcement ensures that network controls remain aligned with the real system state, preserving deterministic boundaries even as infrastructure evolves.

**Implementation Notes**  
- Deploy service meshes, eBPF-based policy agents, host-level firewalls, or SDN controls that enforce per-workload and per-identity rules.  
- Continuously reconcile declared network policy (for example, from infrastructure-as-code or policy-as-code) with effective runtime state.  
- Ensure that enforcement components fail closed for high-sensitivity workloads when identity, policy, or configuration cannot be confirmed.  
- Collect detailed telemetry from runtime enforcement points to feed into detection, forensics, and compliance reporting.  
- Regularly test runtime enforcement by introducing controlled changes (for example, scaling events, rescheduling, identity rotation) and validating that network behaviour remains compliant with ATLAS-DESS policies.

**Applies To:** TI-2 (mandatory), TI-3 (mandatory)

---

### 3.4 Data & State Controls

Data and state controls ensure that all access, mutation, and movement of information occur only through governed, deterministic paths. These controls define how data is accessed, how long it lives, how it is replicated, how its lineage is proven, and how it is protected at rest and in motion. They treat data as a first-class security boundary, not just a by-product of execution, and they enforce that evidence, regulated data, and high-integrity records remain trustworthy even under active attack.

---

#### 3.4.1 (DATA-AUTHZ-01) ATLAS-DATA-AUTHZ — Deterministic Data Access Paths

Access to sensitive or high-integrity data MUST occur only via explicitly defined, policy-enforcing access paths (for example, governed APIs, gateways, or views). Direct, unmanaged access to underlying datastores (for example, raw database connections, object stores, or key-value stores) from general-purpose or ungoverned runtimes MUST NOT be permitted for TI-2 and TI-3 workloads. Access paths MUST encapsulate authentication, authorization, auditing, and data minimisation, and MUST fail closed when policy cannot be evaluated.

**Rationale**  
Allowing arbitrary code to talk directly to datastores creates a combinatorial explosion of access paths, each with its own hidden policy and failure modes. Under attack, these unmanaged paths become exfiltration channels and policy bypasses, undermining deterministic control over who can see or change what. Channeling access through a small number of governed, observable interfaces turns data access into a chokepoint where policy, logging, and detection can be reliably enforced and audited.

**Implementation Notes**  
- Expose sensitive datasets only via governed APIs, views, or stored procedures that implement centralised access policies.  
- Prohibit application code from holding raw datastore credentials; instead, use short-lived, identity-bound tokens or connections issued by policy-enforcing intermediaries.  
- Treat ORM- or driver-level access as non-authoritative unless it is bound to the same policies and audit controls as the gateway or access layer.  
- Enforce that schema migrations, DDL, and other high-impact operations are only performed from dedicated, tightly controlled administrative paths.  
- Capture access decisions (who, what, when, how) at the governed access layer as TI-2 or TI-3 evidence, not only inside application logs.

**Applies To:** TI-1 (recommended), TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.4.2 (DATA-SIDECAR-02) ATLAS-DATA-SIDECAR — Mediated Access via Constrained Intermediaries

High-sensitivity data access from application workloads MUST be mediated via constrained intermediaries (for example, sidecars, gateways, or data access services) that enforce policy, masking, tokenisation, and rate limits. Application runtimes MUST NOT embed high-value data logic (for example, full decryption, raw key handling, unconstrained joins) where it cannot be independently governed and monitored. Intermediaries MUST operate under tighter privilege ceilings and monitoring than the workloads they serve.

**Rationale**  
Embedding all data access logic in application code couples security policy to every deployment and language variant, making it impossible to reason deterministically about who can access what. Compromise of any such application becomes a direct compromise of the data plane. Constrained intermediaries centralise critical controls in specialised components that can be hardened, audited, and operated as part of the TCB, while application code consumes only the minimum necessary views or tokens.

**Implementation Notes**  
- Place sidecars or gateways between application workloads and datastores, responsible for enforcing row/column-level access controls, masking, and aggregation.  
- Ensure intermediaries are minimal, well-reviewed components with limited functionality, reduced attack surface, and explicit performance and rate limits.  
- Prohibit application code from performing raw cryptographic operations on high-sensitivity data unless explicitly justified and governed.  
- Maintain separate operational and deployment lifecycles for intermediaries versus application services; treat intermediary changes as TCB changes.  
- Monitor intermediaries closely for anomalous query patterns, spikes in sensitive-field access, or attempts to bypass masking and tokenisation.

**Applies To:** TI-1 (recommended), TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.4.3 (DATA-LIFE-03) ATLAS-DATA-LIFECYCLE — Explicit Data Lifecycle Boundaries

Systems MUST define and enforce explicit lifecycle states for data (for example, created, active, enriched, archived, on-hold, purge-eligible), with policies that change as data moves between states. Access, retention, protection, and sharing rules MUST be tied to lifecycle state, not just to dataset name or storage location. Data MUST NOT silently remain in “active” or “default” states indefinitely; lifecycle transitions MUST be governed, auditable, and trigger appropriate control changes.

**Rationale**  
Data accumulates over time, often outliving the purposes and protections for which it was originally collected. Without clear lifecycle boundaries, organisations either retain data indefinitely (expanding exposure) or delete it ad hoc (destroying evidence and business value). Explicit lifecycle states and transitions allow deterministic reasoning about which obligations and protections apply at each point, align controls with regulatory and contractual requirements, and make it possible to reason about when data should no longer exist.

**Implementation Notes**  
- Define lifecycle states and state transition rules for major data classes (for example, telemetry, customer data, keys, models, evidence).  
- Implement lifecycle-aware storage classes and policies (for example, reduced access for archived data, heightened protection for evidence under legal hold).  
- Tie access control, encryption strength, and monitoring intensity to lifecycle state; for example, archived data MAY have more restricted access paths.  
- Ensure lifecycle transitions (including legal holds and releases) are logged with identity, timestamp, reason, and relevant references.  
- Periodically review datasets for lifecycle drift (for example, data stuck in “active” state) and correct via governed bulk transitions.

**Applies To:** TI-1 (recommended), TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.4.4 (DATA-MIN-04) ATLAS-DATA-MINIMISE — Minimal Materialisation and Replication

Systems MUST minimise the materialisation, copying, and replication of sensitive data to the smallest set of locations necessary for legitimate purposes. Derived datasets, caches, and analytical copies MUST either reduce sensitivity (for example, via aggregation or anonymisation) or be subject to the same or stricter controls as the source. Untracked or ad-hoc copies of sensitive data (for example, developer exports, test dumps, spreadsheets) MUST NOT be permitted in TI-2 and TI-3 environments.

**Rationale**  
Every additional copy of sensitive data expands the attack surface and multiplies the number of places that must be defended, monitored, and eventually purged. In practice, breaches frequently arise from forgotten backups, test environments, or analyst side-channels. Data minimisation reduces the number of states the system must reason about, making deterministic protection and lifecycle control feasible. It also aligns with privacy and regulatory expectations around purpose limitation and storage minimisation.

**Implementation Notes**  
- Prefer computed views, on-demand aggregation, and tokenisation over full materialisation of raw datasets in multiple systems.  
- Require explicit justification, approval, and tagging for any new replica or export of sensitive data, including its purpose and planned lifetime.  
- Apply the same or stronger access controls and encryption policies to derived datasets that still contain sensitive attributes.  
- Prohibit use of ungoverned storage (for example, local desktops, personal cloud accounts) for copies of production-sensitive data.  
- Periodically inventory and reconcile known replicas and exports against declared purposes; retire or purge those that are no longer required.

**Applies To:** TI-1 (recommended), TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.4.5 (DATA-PROV-05) ATLAS-DATA-PROVENANCE — Data Lineage & Origin Verification

Systems handling high-sensitivity or high-integrity data MUST maintain verifiable provenance for key datasets, including origin, transformation steps, responsible identities, and applied controls. Decisions, models, and reports built on such data MUST be traceable back to their input sources and transformation pipelines. Data whose provenance cannot be established to the required assurance level MUST NOT be used for safety-critical or compliance-relevant decisions in TI-2 and TI-3 environments.

**Rationale**  
Without reliable provenance, it is impossible to determine whether data has been tampered with, sampled incorrectly, or sourced unlawfully. Models and decisions built on tainted or unverified data can become silent channels for manipulation and legal exposure. Deterministic execution at the decision layer depends on being able to reconstruct how data entered the system, how it was transformed, and which trust anchors were applied at each step.

**Implementation Notes**  
- Capture structured lineage metadata at each ingestion and transformation step, including source identifiers, checksums, and responsible identities.  
- Integrate data pipelines with signing or checksum mechanisms so that input and output of critical steps can be verified against tampering.  
- Make lineage queries a first-class capability so investigators and auditors can reconstruct decision and model inputs.  
- Treat ingestion from unverified or ungoverned sources as lower-assurance; isolate such data and prevent it from contaminating high-integrity datasets.  
- Periodically validate lineage records against storage content (for example, recomputing checksums) to detect silent divergence or manipulation.

**Applies To:** TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.4.6 (DATA-IMMUT-06) ATLAS-DATA-IMMUTABLE — Immutable Storage for High-Integrity Records

Data required for evidence, auditability, incident reconstruction, or legally mandated retention MUST be stored in immutable or tamper-evident forms. Once written, such records MUST NOT be altered or deleted except through governed mechanisms that preserve a complete and verifiable history of changes (for example, append-only logs, versioned objects with auditable tombstones). Systems MUST fail closed rather than silently permit in-place modification of designated immutable records.

**Rationale**  
If high-integrity records can be edited or removed without trace, attackers and insiders can erase their footprints, alter audit trails, and undermine compliance claims. Even subtle modifications can make incident reconstruction impossible or cast doubt on the entire evidentiary corpus. Immutable or tamper-evident storage provides a deterministic guarantee that past events and states remain available for scrutiny, and that any attempt to alter them will be detectable.

**Implementation Notes**  
- Use append-only or write-once storage systems for logs, evidence bundles, critical configuration histories, and key lifecycle records.  
- Where deletion is legally required, implement it via cryptographic erasure or governed tombstone mechanisms that maintain proof of prior existence and deletion.  
- Separate operational logging (for troubleshooting) from evidentiary logging; treat the latter as part of the TCB with stricter controls.  
- Ensure that administrative tools and APIs cannot overwrite or purge immutable records outside governed workflows with strong identity and approval requirements.  
- Periodically test immutability guarantees by attempting modification and deletion under various identities, confirming that violations are prevented and logged.

**Applies To:** TI-1 (recommended for critical records), TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.4.7 (DATA-ANOM-07) ATLAS-DATA-ACCESS-ANOMALY — Behavioural Detection for Data Access

Data access patterns for sensitive datasets MUST be continuously monitored for anomalies indicative of misuse, exfiltration, or abuse of legitimate credentials. Detection MUST consider context such as identity, role, time, location, volume, query shape, and accessed fields, not just raw bytes transferred. High-confidence anomalies and policy violations MUST trigger timely alerts and, where appropriate, automated containment actions (for example, session termination, access throttling, or temporary lockout).

**Rationale**  
Even when access controls are correctly configured, attackers frequently operate by stealing or coercing legitimate identities and using them “correctly” from the system’s perspective. Traditional perimeter and login checks do not capture anomalous use of valid access. Behavioural monitoring at the data plane surface catches deviations from normal patterns, such as sudden bulk exports, unusual joins, or access to fields rarely touched by a given role, preserving deterministic expectations of how data is usually used.

**Implementation Notes**  
- Baseline normal access patterns per dataset, per identity, and per role, including typical volume, timing, and accessed attributes.  
- Deploy analytics to detect deviations such as bulk reads, unusual filters, access from atypical locations, or access outside normal operating hours.  
- Integrate detection with identity systems so that suspicious activity can result in targeted containment (for example, revoking specific sessions or tokens).  
- Prioritise telemetry from governed access paths and intermediaries, where context is richest and tampering is hardest.  
- Regularly tune detection logic using red-team exercises and post-incident reviews to reduce blind spots and excessive noise.

**Applies To:** TI-1 (recommended for sensitive datasets), TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.4.8 (DATA-CRYPT-08) ATLAS-DATA-CRYPT — Data-at-Rest Protection & Key Control

Sensitive data at rest, including databases, object stores, file repositories, backups, and evidence archives, MUST be protected with strong encryption and robust key management. Cryptographic keys MUST be managed separately from the data they protect, with strict access controls, rotation policies, and auditability. Access to plaintext MUST be limited to the smallest practical set of processes and identities, and MUST be mediated via governed paths rather than raw key distribution.

**Rationale**  
Physical access, infrastructure compromise, and cloud control-plane failures can all expose stored data if it is not cryptographically protected. Weak or poorly managed keys nullify the benefits of encryption and create hidden single points of failure. Deterministic security at the data layer depends on knowing that compromise of storage media or underlying infrastructure does not automatically imply compromise of the data itself, and that keys can be rotated or revoked in response to incidents.

**Implementation Notes**  
- Encrypt data at rest using modern, vetted algorithms and modes; avoid deprecated or home-grown cryptography.  
- Store and manage keys in dedicated key management systems or hardware-backed modules, with access restricted to minimal trusted components.  
- Implement regular key rotation and re-encryption procedures, ensuring that rotation can be performed without data loss and with auditable change records.  
- Design applications so they do not handle raw keys directly where possible; use envelopes, tokens, or intermediaries to minimise key exposure.  
- Ensure backups, snapshots, and replicas are encrypted and governed under the same or stricter key policies as primary datasets.

**Applies To:** TI-1 (recommended), TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.4.9 (DATA-SHARE-09) ATLAS-DATA-SHARING-GOV — Governed Data Sharing & Export

Sharing or exporting sensitive data outside its primary security boundary (for example, to partners, vendors, analytics platforms, or other jurisdictions) MUST occur only through governed, auditable mechanisms with explicit purpose, legal basis, and control mappings. Ad-hoc exports (for example, manual CSV dumps, email attachments, file transfers) of production-sensitive data MUST NOT be permitted in TI-2 and TI-3 environments without going through approved workflows. Shared datasets MUST be minimised, labelled, and subject to contractual and technical controls aligned with ATLAS-DESS.

**Rationale**  
Many breaches and regulatory failures arise not from core systems but from secondary sharing channels where data is copied into less controlled environments. Once data crosses boundaries without clear agreements and technical safeguards, deterministic guarantees about its protection and use evaporate. Governing sharing and export ensures that security and privacy obligations follow the data, that exposure is limited to what is necessary, and that there is a verifiable record of who received what and why.

**Implementation Notes**  
- Require formal approval and documentation for each new sharing arrangement, including data categories, purpose, retention, and security obligations.  
- Use controlled export mechanisms (for example, dedicated portals, APIs, or transfer services) that enforce masking, minimisation, and logging.  
- Apply technical safeguards such as encryption, tokenisation, or de-identification to shared datasets where full fidelity is not strictly required.  
- Maintain a registry of active data sharing agreements and exports, and reconcile it periodically against actual transfers observed in telemetry.  
- Ensure contracts and technical controls support recall, modification, or deletion of shared data where legal or contractual rights to do so exist.

**Applies To:** TI-1 (recommended), TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.4.10 (DATA-PURGE-10) ATLAS-DATA-PURGE — Secure & Verifiable Deletion

Data that has reached the end of its defined lifecycle, or for which deletion is required by law, contract, or policy, MUST be securely deleted in a manner that is technically and procedurally verifiable. Deletion MUST be applied consistently to all replicas, backups, caches, and derived datasets that remain within scope of the obligation. Where deletion is technically infeasible, controls MUST provide equivalent protection (for example, cryptographic erasure or access revocation) with auditable evidence.

**Rationale**  
Retaining data beyond its legitimate lifetime increases attack surface and legal exposure, while failing to honour deletion obligations undermines trust and may violate regulatory requirements. In complex systems, superficial deletion (for example, removing a primary record but leaving backups and caches intact) creates an illusion of compliance that cannot withstand scrutiny. Deterministic security requires that deletion be treated as a first-class operation, with clear semantics and evidence that it has been completed or replaced with equally strong protections.

**Implementation Notes**  
- Implement deletion workflows that identify and act on all relevant copies (primary storage, replicas, backups, logs, caches, analytical stores).  
- Use cryptographic erasure where supported, destroying keys so that underlying encrypted data is no longer practically recoverable.  
- Generate signed deletion receipts or logs including identity, scope, method, and timestamp, and store them in immutable evidence stores.  
- Enforce legal and incident holds that temporarily suspend deletion for specific records while maintaining clear audit trails and expiry conditions.  
- Periodically test deletion processes with sampled records, verifying that no accessible copies remain within governed environments after deletion.

**Applies To:** TI-1 (recommended), TI-2 (mandatory), TI-3 (mandatory)

---

### 3.5 Trusted Software Chain Integrity and Component Provenance

Trusted software chain controls ensure that all executable components – source code, libraries, binaries, firmware, containers, drivers, WASM modules, package artifacts, and configuration capable of altering execution – originate from verifiable sources, are built under controlled conditions, and retain verifiable trust guarantees from origin to runtime. These controls define how trust roots are established, how components are sourced and verified, how tampering is detected, and how provenance and chain-of-custody are preserved across boundaries.

These controls apply equally to:
- first-party software
- third-party and transitive dependencies
- runtime-downloaded components and plugins
- platform-level artifacts (for example, kernels, hypervisors, firmware, microcode)
- language runtimes, interpreters, and build tools

**Scope of This Section**  
Controls in this section govern:

1. **Artifact Origin & Signing**  
   Where components come from and how authenticity is proven.

2. **Build & Transformation Integrity**  
   Ensuring components are built and transformed in controlled, attested environments.

3. **Component Verification Prior to Execution**  
   Enforcing allowlisted and cryptographically verified artifacts at runtime.

4. **Tamper Resistance**  
   Detecting mutation, replacement, or unexpected repackaging of components.

5. **Traceable Lineage & Cross-System Movement**  
   Recording provenance and chain-of-custody across organisational and environment boundaries.

**Boundaries of This Section**  

The following are in scope:

- Compilers, interpreters, linkers, build tooling
- Software packages, libraries, shared objects
- Package manager registries and mirrors
- Container layers and filesystem hierarchies
- Bootloaders, firmware, microcode, kernel modules
- Components dynamically loaded at runtime (for example, plugins, WASM, dynamically linked modules)

The following are out of scope for this section and defined elsewhere:

- Execution environment isolation and sandboxing → Section 3.2  
- Deployment governance and control-plane mutation → Section 3.6  
- AI model provenance, dataset lineage, and prompt integrity → Section 3.8  

Conceptually, this section has two families of controls:
- **Software Chain Integrity Controls (`ATLAS-SC-*`)** – sourcing, validation, tamper resistance, and execution gating.  
- **Provenance Controls (`ATLAS-PROV-*`)** – lineage, chain-of-custody, transformation tracking, and revocation.

---

#### 3.5.1 (SC-01) ATLAS-SC-VERIFIED-SOURCES — Verified Component Sources

All software components intended for execution in governed environments MUST be obtained only from authenticated, policy-approved sources. Components MUST NOT be downloaded, imported, or executed from unverified repositories, mirrors, personal accounts, ad-hoc endpoints, or “one-off” download locations. Trust in a component’s origin MUST be anchored in defined software trust roots and registry policies, not in individual developer discretion.

**Rationale**  
Unverified and ad-hoc sources are prime insertion points for poisoned packages, typosquatting, namespace hijacking, and malicious look-alike artifacts. When any developer, pipeline, or host can pull code from arbitrary locations, the supply chain becomes opaque and non-deterministic. Constraining sources to authenticated, governed registries and repositories anchors the software estate to a finite, inspectable set of trust relationships and enables systematic monitoring, revocation, and policy enforcement.

**Implementation Notes**  
- Enforce registry allowlists and organisation-approved mirrors at package manager level (for example, pip, npm, Maven, NuGet, apt, cargo).  
- Require TLS with certificate pinning or equivalent identity binding for all package and artifact fetch operations.  
- Block direct “curl | bash” or equivalent patterns in CI, deployment scripts, and production hosts; route all installations through governed mechanisms.  
- Validate repository ownership, organisation membership, and signing configuration for all Git-based or VCS-hosted dependencies.  
- Periodically audit build logs and configuration to detect unauthorized external sources or shadow registries.

**Applies To:** TI-1 (recommended), TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.5.2 (SC-02) ATLAS-SC-SIGN-MANDATORY — Mandatory Cryptographic Signing

All components intended for trusted execution in TI-2 and TI-3 environments MUST be cryptographically signed at build or packaging time by authorised signing identities anchored in the organisation’s software trust roots. Unsigned artifacts MUST be rejected by admission and runtime controls in high-trust environments. Signing keys and identities MUST be governed, auditable, and separate from general-purpose developer credentials.

**Rationale**  
Cryptographic signing shifts trust away from the delivery path and towards verifiable builder identities and trust roots. Without mandatory signing, attackers can introduce modified or substitute artifacts at any point between build and runtime while preserving superficial properties such as filenames or versions. Enforcing signatures as a prerequisite for execution makes tampering detectable, enables revocation at the key level, and underpins deterministic trust decisions across tools and environments.

**Implementation Notes**  
- Use deterministic and auditable signing tooling (for example, Sigstore/Cosign, Minisign, X.509-based code signing) tied to defined trust roots.  
- Separate build-signing keys from CI infrastructure; store and use keys via dedicated key management or HSM-backed services, not plain files in pipelines.  
- Require signatures for containers, packages, binaries, WASM modules, firmware images, and critical configuration bundles.  
- Configure admission controllers, package validators, and boot chains to reject artifacts lacking valid signatures from recognised authorities.  
- Maintain an inventory of signing identities, their scope (for example, product line, platform), and rotation / retirement history as TI-2 or TI-3 evidence.

**Applies To:** TI-1 (recommended for critical components), TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.5.3 (SC-03) ATLAS-SC-DETERMINISTIC-BUILDS — Deterministic Build Outputs

Builds for TI-3 workloads and other high-criticality components MUST be reproducible such that identical source, configuration, and inputs yield identical binary outputs. For TI-1 and TI-2, deterministic builds SHOULD be implemented at least for security-sensitive and widely reused components. Build systems MUST capture all inputs, environments, and toolchain versions required to reproduce an artifact, and deviations from expected outputs MUST be treated as potential tampering.

**Rationale**  
Non-deterministic builds make it difficult or impossible to distinguish benign differences from malicious tampering or compromised toolchains. Deterministic builds enable independent reproduction and bit-for-bit comparison of outputs, allowing organisations and third parties to verify that published artifacts match source and provenance claims. This strengthens supply-chain integrity and provides a powerful forensic tool when investigating suspected compromises.

**Implementation Notes**  
- Pin compiler, linker, and build tool versions; document and lock all build-time dependencies, flags, and environment variables.  
- Use hermetic build environments (for example, containers, dedicated build images, or sandboxed toolchains) to isolate builds from host state.  
- Capture complete build manifests (inputs, toolchain versions, environment) and include references in attestations.  
- Periodically reproduce builds for critical components and compare outputs against published artifacts; treat mismatches as incidents.  
- Extend deterministic build practices to interpreted artifacts where feasible (for example, reproducible archives, deterministic ordering of resources).

**Applies To:** TI-1 (recommended), TI-2 (recommended), TI-3 (mandatory)

---

#### 3.5.4 (SC-04) ATLAS-SC-RUNTIME-ALLOWLIST — Artifact Allowlisting at Execution

Execution environments handling TI-2 and TI-3 workloads MUST enforce allowlisting of cryptographically verified components, permitting execution only of artifacts that are explicitly approved and matched to their signatures and provenance. Components MUST NOT execute solely based on file presence, path, name, or location. Allowlist decisions MUST be anchored to trusted metadata (for example, component identity, version, and signing authority) and enforced at runtime rather than only at deployment.

**Rationale**  
File-system or path-based trust models (for example, “anything in /usr/bin is safe”) are easily bypassed when attackers can add or replace binaries, scripts, or plugins in trusted locations. An allowlist model constrains execution to a small, curated set of known components, even in the presence of compromised hosts, writable volumes, or untrusted user input. Tying allowlists to signatures and provenance further ensures that only authentic, attested artifacts enter execution in high-trust zones.

**Implementation Notes**  
- Maintain a central, policy-governed catalog of approved components with their digests, signatures, and permitted usage contexts.  
- Integrate allowlist checks into OS-level controls (for example, execution control), container runtimes, dynamic loaders, and plugin subsystems.  
- Deny execution of dropped binaries, unpacked archives, dynamically installed packages, or modules that are not present in the approved catalog.  
- Apply allowlisting to interpreted environments (for example, Python packages, Node modules, WASM modules) as well as native binaries.  
- Log all allowlist decisions (allow and deny) and review deny events regularly for evidence of attempted execution of unexpected components.

**Applies To:** TI-1 (recommended for sensitive systems), TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.5.5 (SC-05) ATLAS-SC-DEPENDENCY-TAMPER-DETECTION — Detect Repackaged Dependencies

Dependencies, including transitive ones, MUST be validated for tampering and repackaging using checksums, transparency logs, reproducibility checks, or independent verification paths. If a component’s content differs from reference records maintained by trusted authorities (for example, upstream registries, transparency logs, or internal mirrors), execution or promotion MUST be blocked until discrepancies are resolved. Detection of repackaged or unexpectedly modified dependencies MUST trigger an investigation.

**Rationale**  
A component may be correctly signed yet malicious if the signing key or upstream repository is compromised, or if an internal mirror silently repackages content. Dependencies also often change without explicit visibility when new transitive versions are pulled. Tamper detection beyond simple “signature present” checks provides defence against compromised registries, mirrors, and build pipelines, reinforcing the integrity of the software chain.

**Implementation Notes**  
- Use transparency logs or equivalent mechanisms (for example, Rekor) to record artifact digests and provenance for later verification.  
- Compare downloaded dependency hashes against known-good values from multiple independent sources (for example, upstream plus internal mirror).  
- Detect dependency confusion and namespace hijacking by pinning namespaces, scopes, and organisation ownership for approved packages.  
- Fail builds or deployments when dependency trees diverge from locked manifests or when digest mismatches occur.  
- Periodically re-verify stored dependencies in internal artifact repositories against upstream transparency or checksum records.

**Applies To:** TI-1 (recommended), TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.5.6 (SC-06) ATLAS-SC-REGISTRY-POLICY — Registry and Mirror Trust Governance

Organisations MUST define and enforce explicit trust policies for all package registries, mirrors, repositories, and container registries from which software is sourced. Only registries and mirrors that comply with these policies (including signing, access control, and audit capabilities) MAY be used for TI-2 and TI-3 workloads. Use of unapproved or misconfigured registries MUST be treated as a policy violation.

**Rationale**  
Supply-chain compromises frequently originate in uncontrolled or poorly governed registries, not in the organisation’s own build systems. Without formal trust policies, teams may connect to arbitrary public registries, forks, or mirrors, creating opaque and unbounded trust relationships. Registry governance constrains the software supply chain to a manageable set of well-understood channels where additional safeguards (for example, mirroring, scanning, or signing enforcement) can be applied.

**Implementation Notes**  
- Maintain a signed registry trust manifest enumerating approved registries, mirrors, and their expected security properties.  
- Require authentication, role-based access control, and logging for internal registries and mirrors; restrict write access to governed pipelines.  
- Prefer registries that enforce artifact signing or verification at push time, rejecting unsigned or improperly signed uploads.  
- Use private mirrors that synchronise from upstream and verify upstream content cryptographically before publishing internally.  
- Monitor build and deployment configurations for references to unapproved registries and block their use in TI-2 and TI-3 environments.

**Applies To:** TI-1 (recommended), TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.5.7 (SC-07) ATLAS-SC-TRANSITIVE-DEPENDENCY-CONTROL — Control of Transitive Dependencies

Transitive dependencies MUST be subject to the same trust, signing, validation, and policy requirements as direct dependencies. Build and packaging processes MUST resolve dependencies deterministically at build time, and runtime installation or updating of dependencies from external sources MUST NOT be permitted in TI-2 and TI-3 environments. Dependency graphs MUST be locked and reviewed as part of change management.

**Rationale**  
Transitive dependencies are a common hiding place for malicious payloads and vulnerable code, as they often bypass direct review. Allowing dynamic, runtime resolution of dependencies expands the effective supply chain into uncontrolled territory and makes the realised software estate non-deterministic. Treating transitive dependencies as first-class objects of governance ensures that what actually runs in production matches the organisation’s risk assumptions.

**Implementation Notes**  
- Use lockfiles or equivalent mechanisms (for example, `package-lock.json`, `poetry.lock`, `go.sum`) to freeze resolved dependency versions.  
- Prohibit runtime dependency installation (`pip install`, `npm install`, `apt install`, etc.) in production and high-trust environments.  
- Integrate software composition analysis (SCA) tooling into CI pipelines to enumerate and assess all transitive dependencies.  
- Enforce that new or upgraded transitive dependencies go through the same approval process as direct dependencies for critical components.  
- Periodically re-resolve and review dependency graphs to identify unnecessary or high-risk transitive components that should be removed or replaced.

**Applies To:** TI-1 (recommended), TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.5.8 (SC-08) ATLAS-SC-UNMANAGED-BINARIES — Prohibit Unmanaged Binaries in Trusted Zones

Presence or execution of unmanaged binaries, scripts, plugins, WASM modules, drivers, kernel modules, or other executable artifacts in high-trust runtime contexts MUST be prohibited. All executable content in TI-2 and TI-3 environments MUST be inventoried, signed, and governed as part of the trusted software chain. Attempts to introduce or execute unmanaged artifacts MUST be detected and treated as security incidents.

**Rationale**  
Unmanaged binaries and ad-hoc scripts create opaque execution paths outside the verified chain, bypassing signing, provenance, and policy controls. Attackers and hurried operators alike introduce such artifacts for troubleshooting, quick fixes, or lateral movement, eroding determinism and traceability. Prohibiting unmanaged executables in trusted zones ensures that every execution path is subject to the same integrity and provenance guarantees.

**Implementation Notes**  
- Maintain an inventory of approved executables, scripts, plugins, and modules per environment, keyed by digest and component identity.  
- Configure OS-level and runtime-level controls to block execution from untrusted locations (for example, `/tmp`, user home directories, writable volumes).  
- Require signing and registration of all kernel modules and drivers before they may be loaded in TI-2 and TI-3 systems.  
- Monitor file systems in critical environments for newly created or modified executable files that are not part of approved images or packages.  
- Provide governed, logged mechanisms for temporary tooling (for example, emergency diagnostics) that still comply with signing and provenance requirements.

**Applies To:** TI-1 (recommended), TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.5.9 (PROV-01) ATLAS-PROV-LINEAGE — Component Lineage and Origin Tracking

All components used in TI-2 and TI-3 environments MUST maintain verifiable lineage, including origin (upstream project or vendor), authorship or owning team, build environment, transformation steps, distribution path, and final execution environments. Lineage information MUST be linked to stable component identities, not only to individual artifacts or filenames. Where feasible, lineage data MUST be cryptographically bound to artifacts and stored in tamper-evident systems.

**Rationale**  
Many supply-chain attacks arise not from code content alone but from opaque lineage that hides malicious upstream actors, rogue forks, or unauthorised repackaging. Without clear lineage, organisations cannot reliably assess risk, respond to vulnerabilities, or explain how a component came to be deployed. Deterministic execution requires that each component’s history be reconstructable, allowing investigators and auditors to follow the chain from runtime back to origin.

**Implementation Notes**  
- Assign each logical component a stable identity and record its ancestry across forks, vendor handoffs, and major refactors.  
- Store lineage metadata (for example, origin repository, branch, maintainer, vendor, and upstream license) alongside artifacts in registries.  
- Use tamper-evident storage (for example, append-only logs, hash chains, or dedicated evidence systems) for critical lineage records.  
- Make lineage queryable so that security teams can quickly identify where a given upstream project or vendor’s code is deployed.  
- Periodically reconcile lineage records with reality (for example, by scanning running systems and registries) to detect drift or undocumented components.

**Applies To:** TI-1 (recommended), TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.5.10 (PROV-02) ATLAS-PROV-ATTESTATION — Cryptographic Build Attestation

High-trust components (including TCB elements, security tooling, and widely reused libraries or images) MUST carry cryptographic attestations describing how, where, and by which identities they were built and tested. Attestations MUST cover key lifecycle stages (for example, source integrity, build environment, test execution) and MUST be validated before deployment and at runtime admission for TI-2 and TI-3 environments. Components lacking required attestations MUST NOT be promoted to high-trust environments.

**Rationale**  
Signatures alone prove who signed an artifact, not how it was produced or what checks were performed. Compromised build systems, skipped tests, or altered pipelines can produce signed but untrustworthy components. Cross-stage attestation binds artifacts to specific pipelines, environments, and test suites, enabling more granular trust decisions and making it harder for attackers to hide behind a single compromised signing key.

**Implementation Notes**  
- Use standard attestation formats (for example, in-toto statements) capturing source revisions, build system identity, toolchain identifiers, and test results.  
- Integrate attestation generation into CI/CD pipelines such that attestations are produced automatically for each high-trust build.  
- Configure promotion and deployment gates to require presence and validity of expected attestation types for each component criticality tier.  
- Store attestations in dedicated, tamper-evident systems indexed by component identity and version.  
- Periodically sample deployed components and reconstruct their attestation chains as part of TI-3 readiness and incident drill exercises.

**Applies To:** TI-1 (recommended for critical components), TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.5.11 (PROV-03) ATLAS-PROV-CROSS-BOUNDARY — Cross-System Transfer & Boundary Provenance

When components cross organisational, environmental, or jurisdictional boundaries (for example, vendor delivery, partner exchange, cloud account migration), systems MUST record the transition and bind provenance to both sides of the boundary. Boundary crossings for TI-2 and TI-3 components MUST include signed receipts or equivalent artifacts that capture sender, recipient, component identity, and digests. Components whose cross-boundary provenance cannot be established MUST NOT be treated as trusted.

**Rationale**  
Attackers often target handoff points where integrity assumptions change, such as between vendors, subsidiaries, cloud accounts, or partner systems. Without explicit recording of these transitions, it is difficult to determine where a compromise was introduced or which party is responsible for a risky change. Boundary-aware provenance creates a chain-of-custody model for software, enabling accountability and reducing blind spots at organisational seams.

**Implementation Notes**  
- Require signed delivery manifests or receipts for component transfers between organisations, business units, or major environment tiers.  
- Capture boundary metadata (for example, source account, destination account, region, time) as part of provenance records.  
- Verify that received components’ signatures, digests, and attestations match those declared in transfer manifests.  
- Deny execution of components that have crossed boundaries without complete or coherent transfer records in TI-2 and TI-3 environments.  
- Include cross-boundary transfers in third-party risk assessments and contractual obligations for critical software providers.

**Applies To:** TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.5.12 (PROV-04) ATLAS-PROV-TRANSFORMATION — Verified Transformation Events

Major transformation events (for example, compilation, linking, bundling, minification, container layering, compression, and firmware packaging) MUST be recorded with traceable metadata documenting inputs, transformations applied, and resulting artifacts. For TI-2 and TI-3 components, transformation records MUST be linked to both lineage and attestation chains, allowing investigators to reconstruct how each runtime artifact was derived from its inputs.

**Rationale**  
Transformations create new attack surfaces and opportunities for hidden payloads, particularly when bundling or minification obscures boundaries between code units. Without explicit tracking of how inputs became outputs, it is difficult to determine where malicious logic entered the chain or whether a given artifact faithfully reflects reviewed source. Verified transformation records give defenders a stepwise view of software evolution from source to runtime.

**Implementation Notes**  
- Maintain build- and packaging-level dependency graphs that map inputs (source files, libraries, assets) to outputs (binaries, images, archives).  
- Record transformation parameters (for example, compiler flags, optimisation levels, minification tools, linker scripts) as part of build metadata.  
- For container images, record layer composition, base image identity, and the operations that produced each layer.  
- Store transformation metadata in append-only or tamper-evident logs, linked to component identities and artifact digests.  
- Use transformation records during incident investigations to identify the earliest point at which malicious or unexpected content appears.

**Applies To:** TI-1 (recommended), TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.5.13 (PROV-05) ATLAS-PROV-EVIDENCE-RETENTION — Retention of Provenance as Evidence

Provenance and attestation metadata for components used in TI-2 and TI-3 environments MUST be retained as evidence for periods aligned with regulatory obligations, incident response needs, and the maximum plausible impact horizon of the components. Provenance data MUST NOT be deleted or irreversibly anonymised while components derived from it remain in use or while investigations, audits, or legal holds are active.

**Rationale**  
Compromise investigations and regulatory inquiries often occur long after initial deployment, and frequently require reconstruction of past states, pipeline configurations, and software lineage. If provenance is discarded on operational timescales while software persists, organisations lose the ability to demonstrate compliance, identify root causes, or prove that they acted on known risks. Treating provenance as long-lived evidence aligns retention with actual exposure windows.

**Implementation Notes**  
- Define retention policies for provenance and attestation per component class and criticality tier; align with data and evidence retention strategies.  
- Use WORM or cryptographically chained storage for high-value provenance records to prevent undetected alteration.  
- Implement legal- and incident-hold mechanisms that suspend deletion of provenance related to active cases while tracking scope and duration.  
- Ensure that backup and archival processes preserve provenance alongside artifacts, not separately or inconsistently.  
- Periodically verify that provenance records remain accessible and complete for older components, especially those still deployed.

**Applies To:** TI-1 (recommended), TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.5.14 (PROV-06) ATLAS-PROV-REVOCATION — Component Revocation & Untrusting

Systems MUST support cryptographic revocation of components previously considered trusted and MUST propagate revocation decisions across all environments where the component is present. When a component is revoked (for example, due to compromise, critical vulnerability, or licensing failure), deployment, promotion, and execution of that component MUST be blocked in TI-2 and TI-3 environments. Existing instances MUST be identified and remediated according to defined containment procedures.

**Rationale**  
Software trust is not static; components that were acceptable at one time can become dangerous as new information emerges. Without systematic revocation mechanisms, organisations are forced to rely on ad-hoc patching, incomplete searches, and manual coordination, leaving revoked components active for long periods. Deterministic security requires that a single revocation decision be enforceable across the estate, turning new information into coherent technical action.

**Implementation Notes**  
- Maintain revocation lists or equivalent trust policies keyed by component identity, version, digest, and signing key.  
- Integrate revocation checks into build systems, registries, deployment controllers, and runtime admission controls.  
- Use SBOMs and runtime inventory to identify all systems where a revoked component is deployed, including transitive and embedded cases.  
- Coordinate with key management to revoke or constrain signing keys associated with compromised components where appropriate.  
- Log revocation events and resulting containment actions in TI-3-grade evidence systems for post-incident review.

**Applies To:** TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.5.15 (PROV-07) ATLAS-PROV-SHARED-COMPONENTS — Shared Component Risk Controls

Components used across multiple systems, products, or tenants – especially kernels, cryptographic libraries, authentication agents, and common runtimes – MUST be treated as shared risk surfaces and governed accordingly. Shared components in TI-2 and TI-3 environments MUST be assigned elevated criticality and subject to stricter supply-chain, hardening, monitoring, and revocation controls. The organisation MUST be able to identify all deployments of each shared component.

**Rationale**  
Shared components create systemic vulnerabilities; compromise or failure in one shared element can cascade across many otherwise independent systems. Treating such components as ordinary dependencies underestimates their blast radius and can delay mitigation. Explicitly recognising shared components as high-impact assets focuses security investment where it yields the largest risk reduction and ensures that incidents involving them are treated with appropriate urgency.

**Implementation Notes**  
- Classify components by criticality and deployment breadth, flagging those used across multiple systems, products, or tenants.  
- Apply stricter intake, review, and testing requirements to shared components, including targeted fuzzing and adversarial evaluation.  
- Monitor telemetry from shared components (for example, error rates, anomalous behaviour) across environments to detect emerging issues promptly.  
- Ensure that revocation and patch mechanisms can target shared components across all affected systems in a coordinated manner.  
- Include shared components explicitly in tabletop exercises and incident response playbooks due to their systemic importance.

**Applies To:** TI-1 (recommended), TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.5.16 (PROV-08) ATLAS-PROV-DISTRIBUTION-CHANNEL — Secure Distribution Channels

Artifacts MUST be distributed through authenticated, integrity-protected channels with verifiable recipients. Distribution MUST NOT rely solely on implicit trust in DNS, CDN infrastructure, email, or generic file-sharing services. For TI-2 and TI-3 components, endpoints MUST verify artifact integrity and authenticity independently (for example, via signatures and transparency logs) rather than trusting transit infrastructure.

**Rationale**  
Attackers compromise distribution infrastructure – including CDNs, DNS, update servers, and email – to inject altered artifacts into otherwise legitimate flows. If recipients trust channels implicitly and skip endpoint verification, a single infrastructure compromise can taint software across many organisations. Secure distribution channels ensure that transport is treated as untrusted and that each recipient validates artifacts directly against trusted roots and provenance.

**Implementation Notes**  
- Require mutual authentication and encryption for distribution endpoints (for example, mTLS between registries and consumers).  
- Validate signatures, digests, and transparency log records at the receiving end before artifacts are stored or promoted.  
- Avoid ad-hoc distribution via unmanaged mechanisms (for example, email attachments, consumer file-sharing platforms) for production software.  
- Use signed manifests and checksums for bulk or offline distribution; verify manifests before consuming artifacts.  
- Log distribution events with source, destination, artifact identity, and verification results as part of TI-2 / TI-3 evidence.

**Applies To:** TI-1 (recommended), TI-2 (mandatory), TI-3 (mandatory)

---

### 3.6 Control Plane Security and Mutation Governance

Control plane security and mutation governance ensure that systems capable of altering execution environments, privileges, infrastructure topology, security posture, routing, or policy logic operate under strict verification, authorisation, auditability, and deterministic enforcement guarantees. Unbounded, opaque, or unaudited mutation of control planes is prohibited, regardless of whether it originates from humans, scripts, or autonomous systems.

Control plane governance applies to both:
- **Human-triggered mutation** (for example, operators, SREs, security engineers, release managers)
- **Automated or autonomous mutation** (for example, CI/CD systems, orchestrators, AI agents, auto-remediation)

Controls affecting **automated mutation** generally require **stricter conformance**, due to their speed, scale, and susceptibility to adversarial manipulation.

**Scope**  
Controls in this section cover:
1. **Infrastructure mutation** – IAM changes, deployment operations, scaling, topology, routing, provisioning.  
2. **Runtime policy mutation** – access rules, feature flags, API throttles, risk scores, dynamic privilege changes.  
3. **Control-plane automation** – CI/CD, orchestrators, policy engines, auto-remediation, autonomous agents.  
4. **Privilege escalation through control surfaces** – any mutation that weakens or bypasses execution boundaries.

**In scope examples**  
- Kubernetes API servers, cloud provider IAM, Terraform/Pulumi, cluster and network controllers  
- Secrets managers, PKI issuers, service mesh identity and traffic control  
- Feature flag systems, rules engines, workflow engines, plugin hosts  
- Agent-driven or AI-driven policy and configuration mutation

**Out of scope (defined elsewhere)**  
- Execution environment isolation and sandboxing → Section 3.2  
- Software provenance and component trust → Section 3.5  
- AI model / agent behaviour and runtime governance → Section 3.8  

**Classes of Control Plane**

| Class | Definition | Typical Impact |
|-------|------------|----------------|
| **Systemic Control Plane** | Alters infrastructure, roles, identity, topology, or core security posture | High blast radius; tightly governed |
| **Behavioural Control Plane** | Alters execution logic, workflows, decision paths, or policy outcomes | Medium to high blast radius |
| **Automated Mutation Control** | Systems that mutate state autonomously in response to signals or goals | Highest systemic risk; strictest controls |

The following controls cover **Systemic Control Planes (ATLAS-CP-SYS)**.

---

#### 3.6.1 (CP-SYS-01) ATLAS-CP-SYS-IMMUTABLE — Immutable-by-Default Systemic Control Planes

Systemic control planes (for example, infrastructure-as-code, cluster APIs, IAM configuration, network control) MUST default to immutability. Any mutation of infrastructure topology, privilege boundaries, routing, or access control MUST occur only through explicitly defined, authenticated, policy-governed mutation paths. Direct, ad-hoc changes via consoles, unmanaged scripts, or local tooling MUST be prohibited for TI-2 and TI-3 environments, or treated as violations that are automatically detected and reconciled.

**Rationale**  
Modern attacks increasingly manipulate infrastructure and configuration instead of deploying traditional malware. If control planes are freely mutable from many locations and tools, drift and unauthorised reconfiguration become impossible to track and reverse. Immutable-by-default control planes constrain mutation to a small set of predictable, auditable channels, enabling deterministic reasoning about who changed what, when, and under which policy. This is essential for preserving boundary guarantees and minimising invisible privilege and topology shifts.

**Implementation Notes**  
- Represent systemic configuration as declarative artifacts (for example, Terraform/Pulumi stacks, Kubernetes manifests) that serve as the primary source of truth.  
- Enforce read-only state for runtime infrastructure except when applying approved change manifests through controlled pipelines.  
- Treat change plans (for example, Terraform plans, migration bundles) as signed, immutable artifacts that must be reviewed and approved before apply.  
- Disable or severely restrict direct mutation of systemic state via cloud provider UIs, ad-hoc CLI access, or local configuration files in TI-2 and TI-3 environments.  
- Implement reconciliation loops that continuously converge runtime state back to the declared configuration and alert on unapproved divergences.

**Applies To:** TI-1 (recommended), TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.6.2 (CP-SYS-02) ATLAS-CP-SYS-AUTH-BOUND — Identity-Bound Mutation Authority

All systemic control plane mutations MUST be bound to strong, authenticated, and attributable identities, whether human or workload. Location-based or network-based trust (for example, “from this subnet”) MUST NOT be used to authorise mutation. Shared administrator accounts, anonymous tokens, static long-lived credentials, or environment-level “god identities” MUST be eliminated or tightly constrained, and mutation rights MUST be scoped and time-bounded.

**Rationale**  
If control plane changes can be made without clear identity binding, attackers and insiders can silently escalate privileges, weaken enforcement, or rewire infrastructure without leaving a reliable trail. Shared or anonymous identities undermine both accountability and effective incident response. Binding mutation authority to strong identities is a prerequisite for enforcing least privilege, applying dual-control, and reconstructing how systemic changes were made.

**Implementation Notes**  
- Require phishing-resistant MFA for human operators of control planes, and mTLS or signed tokens for automation identities.  
- Disable shared admin accounts; where break-glass accounts exist, govern them with strict procedures, time-bounded access, and TI-3 evidence.  
- Scope mutation permissions by domain (for example, network vs IAM vs storage) and environment (for example, non-production vs production).  
- Log all control plane calls with identity, source, parameters, and resulting status in immutable evidence stores.  
- Periodically review control plane role assignments and remove unused or overly broad mutation permissions.

**Applies To:** TI-1 (recommended for privileged roles), TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.6.3 (CP-SYS-03) ATLAS-CP-SYS-OOB-DETECTION — Out-of-Band Mutation Detection

Systems MUST continuously detect and respond to systemic changes applied outside approved mutation paths, regardless of origin (for example, cloud console actions, direct API calls, lateral movement, manual hotfixes). Effective configuration and state MUST be reconciled against declared, policy-governed definitions, and any out-of-band mutation in TI-2 and TI-3 environments MUST trigger alerts and, where appropriate, automatic remediation or reversion.

**Rationale**  
Attackers, misconfigured tools, and rushed operators often bypass formal pipelines and apply changes directly through consoles, scripts, or compromised credentials. Without active detection of out-of-band modifications, infrastructure and policy drift accumulate silently, eroding all assumptions embedded in configuration-as-code and audits. Systematically comparing runtime state to declared desired state restores determinism and ensures that unauthorised changes are surfaced and corrected.

**Implementation Notes**  
- Implement configuration drift detection that compares IaC manifests, policy-as-code, and baseline configurations to actual runtime state.  
- Alert when changes occur through out-of-band channels (for example, manual console edits, direct low-level API usage) in protected environments.  
- Use reconciliation controllers (for example, GitOps operators) to optionally auto-revert unauthorised changes in TI-2 and TI-3, or at minimum to quarantine and flag them.  
- Correlate out-of-band changes with identity, source IP, and session to support incident triage and root cause analysis.  
- Include OOB detection results in regular governance and compliance reporting to demonstrate control over configuration drift.

**Applies To:** TI-1 (recommended), TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.6.4 (CP-SYS-04) ATLAS-CP-SYS-DUAL-AUTH — Multi-Party or Dual-Key Approval

High-impact systemic control plane changes – such as modifications to IAM trust policies, network trust boundaries, cluster-level security settings, or root-of-trust entities – MUST require multi-party approval or dual-control mechanisms. A single identity MUST NOT be able to unilaterally enact such changes in TI-2 and TI-3 environments, even if it holds high technical privilege.

**Rationale**  
Single-actor mutation of critical control planes creates catastrophic insider, coercion, and compromised-account risk. A single set of stolen credentials can otherwise reconfigure the environment into an attacker-friendly posture in minutes. Multi-party approval and dual-control mechanisms enforce separation of duties and reduce the likelihood that any one identity – human or machine – can subvert systemic controls without detection.

**Implementation Notes**  
- Define classes of “high-impact changes” (for example, changes to org-level IAM, root CA rotation, global network routing changes, cross-tenant controls).  
- Require at least two distinct identities, ideally from different roles or teams (for example, operations plus security), to approve such changes.  
- Implement dual-control via workflow systems, threshold signatures, or multi-approval gates in CI/CD pipelines.  
- Ensure that approvals themselves are strongly authenticated, cryptographically recorded, and linked to the resulting change manifests.  
- Periodically review multi-party workflows to ensure they are effective, not bypassed, and not silently downgraded for convenience.

**Applies To:** TI-1 (recommended for critical systems), TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.6.5 (CP-SYS-05) ATLAS-CP-SYS-SEGMENTED — Segmented Control Plane Surfaces

Control plane surfaces MUST be segmented such that compromise of one subsystem, environment, or tenant does not automatically grant mutation authority over unrelated systems. Global “super-admin” roles or unified roots of control spanning heterogeneous environments MUST be eliminated or restricted to the smallest viable scope, with compensating controls. Each major trust zone (for example, tenant, region, cluster, environment) MUST have its own bounded control plane.

**Rationale**  
Unified, flat control planes become systemic single points of failure: compromise of one set of control credentials can cascade across all tenants, regions, and environments. Segmentation of control surfaces aligns with network and identity segmentation, limiting the blast radius of a control-plane breach. This preserves determinism by ensuring that failures remain localised and that distinct trust zones maintain independent governance and recovery paths.

**Implementation Notes**  
- Partition control planes logically and, where feasible, physically by tenant, environment (for example, dev/stage/prod), region, or sensitivity tier.  
- Avoid or strictly constrain global roles that can mutate multiple partitions; where unavoidable, treat them as TCB-level assets with dual-control and intensive monitoring.  
- Separate control planes for identity, network, runtime, and data systems; do not rely on a single monolithic administrative surface.  
- Implement distinct admin accounts and RBAC policies per partition; avoid cross-partition reuse of long-lived credentials.  
- Regularly test whether compromise of one partition’s control credentials can affect others and remediate any discovered paths.

**Applies To:** TI-1 (recommended), TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.6.6 (CP-SYS-06) ATLAS-CP-SYS-SIGNED-POLICY — Signed Policy-as-Code with Runtime Enforcement

Systemic policies that govern identity, network, runtime admission, and other control-plane behaviour MUST be expressed as policy-as-code artifacts that are cryptographically signed and validated. Unsigned or improperly signed policy changes MUST be rejected in TI-2 and TI-3 environments, regardless of the privilege level of the actor submitting them. Policy validation MUST occur at both distribution and enforcement points to prevent tampering and unauthorised mutation.

**Rationale**  
Infrastructure drift and control plane compromise often arise from silent policy mutation rather than explicit changes to infrastructure definitions. If any privileged user or process can edit policy text without cryptographic safeguards, attackers can weaken guardrails while leaving apparent configuration unchanged. Treating policy as signed, versioned code anchored to trust roots ensures that systems only enforce policies that are traceable, reviewed, and tamper-resistant.

**Implementation Notes**  
- Represent policies (for example, IAM rules, network policies, OPA bundles, admission policies) as signed artifacts stored in governed repositories.  
- Validate policy signatures in CI/CD pipelines before distribution, and again at load or refresh time in policy engines and control planes.  
- Reject policy updates that are unsigned, signed by unauthorised identities, or inconsistent with expected version or scope.  
- Log policy versions and signing identities alongside enforcement decisions to support audits and incident reconstruction.  
- Use immutable, append-only logs to record the history of policy changes, including content diffs and approval metadata, for TI-2 and TI-3 evidence.

**Applies To:** TI-1 (recommended), TI-2 (mandatory), TI-3 (mandatory)

---
#### 3.6.7 (CP-BEH-01) ATLAS-CP-BEH-BOUND — Bound Execution Behaviour Changes

Behavioural changes within applications and services (including configuration-driven logic, workflow changes, routing decisions, and policy outcomes) MUST occur only within predefined, schema-governed and policy-bounded capabilities. Systems MUST NOT allow arbitrary behavioural mutation based solely on unvalidated runtime inputs (for example, free-form JSON/YAML configs, environment variables, remote flags, or ad-hoc scripts). Any mechanism capable of changing behaviour MUST be explicitly modelled, typed, and constrained so that it cannot bypass safety, access control, or compliance boundaries.

**Rationale**  
“Config-as-behaviour” is a common attack vector: by manipulating configuration, flags, or rules, attackers can disable checks, change routing, or weaken enforcement without modifying code or infrastructure. When behaviour can be altered by unbounded or undocumented inputs, the effective attack surface becomes unmeasurable and non-deterministic. Binding behavioural change to well-defined, schema-validated mechanisms preserves predictability and ensures that changes remain within understood and reviewable limits.

**Implementation Notes**  
- Define strict schemas and capability models for behavioural changes (for example, allowed fields, ranges, and enumerations) and validate all inputs against them.  
- Prohibit free-form configuration that can inject logic (for example, arbitrary code snippets, untyped expressions, or embedded scripting) into production systems.  
- Layer behaviour policies into baseline (non-bypassable) rules, optional overrides, and immutable safety rails; ensure overrides cannot weaken rails.  
- Treat any new source of behavioural influence (for example, new config file, environment variable, remote flag provider) as a change to the control plane that requires review and governance.  
- Log all behavioural change events, including who or what triggered them, the previous and new values, and the evaluated scope of impact.

**Applies To:** TI-1 (recommended), TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.6.8 (CP-BEH-02) ATLAS-CP-BEH-POLICY-SIGNED — Signed Behavioural Policy Artifacts

Behavioural logic that influences authorisation, risk scoring, routing, or workflow decisions (for example, policy bundles, rules, feature-flag configurations, workflow definitions) MUST be distributed and loaded as authenticated, cryptographically signed artifacts. Unsigned or improperly signed behavioural artifacts MUST be rejected in TI-2 and TI-3 environments, regardless of the source identity attempting to load them. Systems MUST validate signatures at load time and on refresh, not only at publication.

**Rationale**  
Attackers increasingly target policy and configuration rather than core code, because changing rules can silently disable or weaken controls. If behavioural logic can be updated by any privileged user or process without cryptographic safeguards, the effective security posture can be rewritten without clear evidence. Treating behavioural logic as signed, verifiable artifacts aligns it with software supply-chain controls and ensures that only reviewed and traceable behaviour can be activated.

**Implementation Notes**  
- Represent policies, rulesets, and behavioural configs as versioned artifacts stored in governed repositories and signed by authorised policy authors.  
- Validate signatures whenever policies are loaded, reloaded, or pushed to agents (for example, OPA bundles, WAF rules, fraud rules, workflow JSON).  
- Reject behavioural updates that are unsigned, signed with unauthorised keys, or inconsistent with expected component, environment, or tenant scope.  
- Log signature identity, version, and hash of each behavioural artifact alongside its activation timestamp for TI-2 / TI-3 evidence.  
- Ensure operational tooling cannot bypass signed-policy mechanisms by writing directly to internal policy stores or databases.

**Applies To:** TI-1 (recommended), TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.6.9 (CP-BEH-03) ATLAS-CP-BEH-DYNAMIC-CONTROL — Controlled Dynamic Behaviour Activation

Dynamic behaviour controls (for example, feature flags, runtime toggles, experiment frameworks, operational kill-switches, command routing) MUST be designed and governed such that they cannot be used to escalate privileges, disable critical safeguards, or bypass mandatory controls. High-impact behavioural changes (for example, disabling authentication, enabling debug backdoors, turning off logging) MUST NOT be exposed as ordinary runtime toggles and MUST require higher-assurance change processes.

**Rationale**  
Feature flags and runtime toggles are frequently abused in breaches to turn off validation, enable unsafe modes, or route traffic through attacker-controlled paths. If all behaviour can be altered through the same low-friction mechanisms intended for A/B tests or cosmetic changes, critical controls are one misconfiguration or compromised account away from being disabled. Separating and constraining high-risk toggles preserves operational agility while preventing flags from becoming a stealth privilege-escalation mechanism.

**Implementation Notes**  
- Classify flags and toggles by risk level (for example, cosmetic, performance, safety-critical) and restrict mechanisms available to high-risk categories.  
- Prohibit flags from directly enabling or disabling core security properties (for example, authentication requirement, encryption, evidentiary logging); gate such changes behind formal change control and dual-auth workflows.  
- Enforce strong identity, MFA, and audit trails for changes to non-cosmetic flags, especially in production and TI-3 environments.  
- Make flag evaluation logic transparent and declarative; avoid embedding imperative “if flag then bypass check” patterns that are hard to audit.  
- Monitor dynamic behaviour changes in real time and alert on unusual activity (for example, multiple high-risk flags toggled within a short window).

**Applies To:** TI-1 (recommended), TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.6.10 (CP-BEH-04) ATLAS-CP-BEH-PLUGIN-CONTROL — Plugin and Extension Governance

Plugins, modules, WASM blobs, embedded interpreters, and other extension mechanisms that alter or augment behaviour at runtime MUST be governed under the same verification, signing, provenance, and isolation controls as primary artifacts. Unvetted or unsigned plugins MUST NOT be loadable in TI-2 and TI-3 environments. Extension points MUST be constrained so that plugins cannot arbitrarily bypass core security checks or expand their capabilities beyond defined contracts.

**Rationale**  
Plugins and extensions are a favoured target for supply-chain attacks and AI-assisted malware because they often pass under lighter review and can hook deeply into application behaviour. If extensions are treated as “less critical” than core binaries, attackers can gain arbitrary code execution inside trusted processes through compromised plugin ecosystems. Applying full chain integrity and isolation controls to plugins ensures that extensibility does not become a side door into the TCB.

**Implementation Notes**  
- Require digital signatures, provenance attestations, and catalog-based approval for all plugins, extensions, and WASM modules before they can be loaded.  
- Version-lock and pin runtime FFI / dynamic linking interfaces (for example, explicit allowlists of shared libraries and functions) to prevent arbitrary native binding.  
- Enforce strict sandboxing or process isolation for plugins, limiting resource access, network connectivity, and access to host internals.  
- Document and constrain plugin APIs so that security enforcement points remain in trusted code paths outside the plugin boundary.  
- Periodically review deployed plugins and extension configurations, removing unused or high-risk components and validating that all loaded plugins remain in the approved catalogue.

**Applies To:** TI-1 (recommended), TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.6.11 (CP-BEH-05) ATLAS-CP-BEH-COVERT-OVERRIDE — Detect Covert Behaviour Overrides

Systems MUST detect and log attempts to override or influence behavioural controls through indirect or covert means, such as unexpected configuration sources, unapproved environment variables, dynamic patching, runtime code injection, or undocumented flag providers. Introduction or activation of new behaviour sources outside the defined control schema in TI-2 and TI-3 environments MUST be treated as a potential incident and investigated.

**Rationale**  
Attackers rarely follow documented control paths; instead, they modify configuration files, environment variables, template engines, or in-memory structures to subvert behaviour without touching official policy artifacts. Over time, teams may also introduce ad-hoc overrides that bypass governance when under operational pressure. Detecting and surfacing these covert overrides is critical to preserving determinism between declared policy and actual runtime behaviour.

**Implementation Notes**  
- Maintain an explicit inventory of approved behavioural inputs (for example, config files, flag providers, policy bundles) and monitor for new or undocumented sources.  
- Instrument applications and platforms to log when configuration or behaviour is influenced by unexpected sources (for example, unknown environment variables, new files, dynamically loaded code).  
- Use integrity monitoring on critical configuration paths and in-memory structures associated with behavioural controls.  
- Alert when behaviour-related changes occur outside normal channels (for example, manual database writes to config tables, direct patching of policy stores).  
- Incorporate covert-override checks into threat hunting and red-team exercises to ensure that indirect paths are visible and defended.

**Applies To:** TI-1 (recommended), TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.6.12 (CP-BEH-06) ATLAS-CP-BEH-ROLLBACK-GUARD — Behaviour Rollback Safeguards

Rollback of behavioural logic, policies, or configurations to previous versions MUST be governed and MUST NOT automatically restore weaker or less secure states without explicit review and approval. Systems MUST track the security-relevant characteristics of behavioural versions, and attempts to downgrade to materially weaker behaviour in TI-2 and TI-3 environments MUST trigger safeguards, including additional approvals or automatic blocking.

**Rationale**  
Attackers and rushed operators often reduce enforcement by reverting to older policies, feature configurations, or workflow logic that predates hardening efforts. Simple “version rollback” mechanisms can unintentionally reintroduce vulnerabilities or disable newly added controls while appearing operationally benign. Incorporating rollback awareness into governance ensures that downgrades are recognised as potential security events, not routine maintenance.

**Implementation Notes**  
- Maintain version histories for behavioural artifacts with metadata describing their effective enforcement strength, risk posture, and known issues.  
- Flag versions that are weaker (for example, fewer checks, broader access, reduced logging) and require explicit, higher-assurance approval to roll back to them.  
- Prevent automatic or unattended rollbacks to prior versions in TI-2 and TI-3 environments; require documented justification and identity-bound approval.  
- Store behaviour version histories and rollback events in tamper-evident logs, including who initiated the rollback and why.  
- Include rollback scenarios in change management and incident response playbooks, emphasising the need to reassess risk when reverting behaviour.

**Applies To:** TI-1 (recommended), TI-2 (mandatory), TI-3 (mandatory)

---
#### 3.6.13 (CP-AUTO-01) ATLAS-CP-AUTO-DENY-UNBOUND — No Unbounded Autonomous Mutation

Systems MUST NOT autonomously mutate control planes, privileges, routing, infrastructure, or execution logic in an open-ended or unconstrained manner. Autonomous mutation in TI-2 and TI-3 environments MUST only operate within clearly defined, pre-approved, and policy-bound scopes, with explicit limits on what can change, how often, and under which conditions. Any autonomous mechanism that can freely alter identity, trust boundaries, or security posture without such constraints MUST be disabled or redesigned.

**Rationale**  
Post-automation and AI-era failures rarely require classic exploits; misconfigured or compromised autopilots can simply rewrite policies, routes, and privileges faster than humans can react. Unbounded automation effectively creates a secondary, opaque control plane operating outside traditional governance. Denying unbounded mutation and forcing all autonomous systems into tightly scoped, policy-governed domains preserves determinism and ensures that automated actions remain comprehensible and controllable.

**Implementation Notes**  
- Disable “auto-apply” or “auto-fix” modes for high-impact domains (for example, IAM, routing, firewall rules, PKI, tenant boundaries) unless they are explicitly scoped and risk-assessed.  
- Only permit autonomous mutation for clearly delimited functions such as safe auto-scaling, non-privileged configuration tuning, or localised health remediation.  
- Require explicit governance review and approval for each automation use case, including scope, constraints, and rollback strategy.  
- Implement guardrails that prevent autonomous systems from performing out-of-domain actions (for example, editing IAM roles when only autoscaling is allowed).  
- Continuously monitor autonomous mutation channels and treat attempts to perform actions outside declared scope as incidents.

**Applies To:** TI-1 (recommended), TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.6.14 (CP-AUTO-02) ATLAS-CP-AUTO-CONSTRAINED — Constrained Autonomous Change Domains

Autonomous mutation MUST be limited to explicitly defined domains (for example, scaling replicas within bounds, rotating ephemeral tokens, restarting unhealthy pods) and MUST NOT expand to new domains without human authorisation and updated policy. Capability boundaries for each autonomous system MUST be documented, cryptographically bound, and enforced at runtime so that agents cannot chain capabilities or “discover” new powers by composing APIs.

**Rationale**  
Automation and agentic systems naturally tend to chain available actions to achieve goals, especially when optimising for performance or reliability. Without hard capability boundaries, an agent initially authorised for low-impact functions can gradually accumulate control over higher-impact domains. Constraining autonomous change domains ensures that the blast radius of automation is known, finite, and reviewable, rather than emergent and unbounded.

**Implementation Notes**  
- Define per-agent capability manifests (for example, “may scale service X between N and M replicas; may not modify RBAC, routing, or IAM”).  
- Store capability manifests as signed artifacts; enforce them in policy engines that mediate all agent control-plane calls.  
- Segregate APIs by domain and privilege level so that agents cannot “accidentally” invoke high-impact endpoints outside their intended scope.  
- Monitor agent activity for attempts to call out-of-scope APIs or operate on out-of-scope resources and treat such attempts as policy violations.  
- Require explicit governance (including security review) when expanding an agent’s capability set, with updated manifests and risk analysis.

**Applies To:** TI-1 (recommended), TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.6.15 (CP-AUTO-03) ATLAS-CP-AUTO-PREDICTABLE — Deterministic & Predictable Automation

Autonomous change in TI-2 and TI-3 environments MUST be deterministic, explainable, and reproducible under identical conditions. Systems MUST NOT rely on opaque, purely heuristic, or non-deterministic decision-making for high-impact control-plane mutation where outcomes cannot be independently verified or re-simulated. Decisions leading to mutation MUST record the evaluated context and decision path so that auditors can reconstruct why a particular action was taken.

**Rationale**  
Opaque or probabilistic systems cannot be reliably audited, verified, or safely rolled back; different runs under similar conditions may produce different actions, undermining deterministic security. When control planes depend on “black-box” automated logic, defenders cannot confidently reason about system behaviour or prove that controls operate as intended. Enforcing predictability and explainability keeps automation within the same verification domain as other ATLAS-DESS controls.

**Implementation Notes**  
- Prefer rule-based, policy-based, or model-checked logic for control-plane automation over unconstrained ML-driven decisions for high-impact actions.  
- Log the full decision context for each autonomous mutation, including inputs considered, rules fired, and alternative actions evaluated or rejected.  
- Where heuristic or ML components are used, gate their outputs behind deterministic validation rules that must be satisfied before mutation can proceed.  
- Provide a “dry-run” or simulation mode that can predict what changes an autonomous system would make given specific conditions.  
- Reject mutation actions when required preconditions cannot be proven (for example, missing telemetry, ambiguous state, or conflicting policies).

**Applies To:** TI-1 (recommended), TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.6.16 (CP-AUTO-04) ATLAS-CP-AUTO-SIGNED — Signed Autonomous Decisions

Automated mutation events MUST be cryptographically signed or otherwise strongly attributed to a unique machine or agent identity that is distinct from general execution identities. Each decision that changes control-plane state in TI-2 and TI-3 environments MUST be recorded with a verifiable signature, enabling attribution, replay detection, and selective revocation of specific agents or automation pipelines without affecting unrelated workloads.

**Rationale**  
Today, most autonomous changes are indistinguishable from human administrator actions in logs, making it difficult to attribute decisions, detect compromise, or revoke a misbehaving agent. If automation shares identities with ordinary workloads or operators, containment becomes coarse and disruptive. Requiring signed, agent-specific identities for autonomous changes establishes a clear chain-of-custody and enables precise response when automation misbehaves or is subverted.

**Implementation Notes**  
- Issue distinct identities and signing keys for autonomous systems, separate from human admins and from service runtime identities.  
- Require that all control-plane mutations initiated by agents be signed or otherwise cryptographically attributable to the agent identity.  
- Store signed decision records (including before/after state, context, and signature) in append-only, tamper-evident evidence logs.  
- Integrate signing into the agent workflow so that unauthenticated or unsigned mutation requests are rejected by control-plane APIs.  
- Provide mechanisms to selectively revoke or suspend an agent identity, immediately preventing further signed mutations from that agent.

**Applies To:** TI-1 (recommended), TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.6.17 (CP-AUTO-05) ATLAS-CP-AUTO-MODERATION — Human Approval for High-Impact Actions

Autonomous systems MUST require human validation (with appropriate separation of duties) for actions that materially alter privileges, identity boundaries, routing, network trust, data classification, or other high-impact security properties. Only low-impact, pre-scoped actions (for example, bounded auto-scaling, localised restarts) MAY proceed without prior human approval in TI-2 and TI-3 environments. Automated proposals for high-impact changes SHOULD be presented as recommendations, not executed directly.

**Rationale**  
Agentic systems and auto-remediation tools can escalate rapidly if allowed to change identity, routing, or core controls unilaterally. Even well-intentioned changes can create systemic outages or new attack paths when taken without full context. Maintaining a human-in-the-loop for high-impact decisions balances the speed of automation with human judgment, ensuring that exceptional or unexpected situations are reviewed before irreversible changes occur.

**Implementation Notes**  
- Classify potential automated actions by impact level, explicitly listing which actions require human approval and under what conditions.  
- Allow routine, reversible actions like safe auto-scaling to occur autonomously, but require interactive approval for actions such as IAM changes, security group updates, or cross-tenant routing modifications.  
- Present high-impact proposals via secure workflows (for example, change management tools or approval dashboards) showing rationale, context, and predicted effect.  
- Require dual-approval for the highest-impact automated proposals (for example, disabling a major control, mass revocation, or fleet-wide routing change).  
- Record moderation decisions (approve, reject, modify) and link them to subsequent mutations in TI-2 / TI-3 evidence stores.

**Applies To:** TI-1 (recommended), TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.6.18 (CP-AUTO-06) ATLAS-CP-AUTO-ROLLBACK — Reversible and Observable Changes

Autonomous changes to control planes, configuration, or behaviour MUST be designed to be reversible and MUST emit rich observability events describing what was changed, why, by which identity, and how rollback can be performed. In TI-2 and TI-3 environments, autonomous mutations MUST NOT be applied if they cannot be cleanly rolled back or if rollback procedures are untested or undefined.

**Rationale**  
AI-driven and automated systems can mutate state far more quickly than human teams can detect or understand. If these changes are not reversible, or if they leave incomplete or ambiguous audit trails, defenders may be forced to choose between accepting unknown state or undertaking disruptive rebuilds. Designing automation for reversibility and visibility ensures that organisations can unwind misbehaviour and learn from failures without losing control of the system.

**Implementation Notes**  
- Store signed diffs for each autonomous mutation, capturing previous state, new state, and decision context.  
- Implement atomic rollback primitives for common change types (for example, config rolls, policy versions, routing tables) and test them regularly.  
- Emit structured events for each mutation that can be consumed by observability, SIEM, and forensics pipelines.  
- Trigger alerts when rollback attempts fail, behave unexpectedly, or reveal that state has diverged from expected baselines.  
- Treat non-reversible or opaque mutations as design defects; refactor automation to use reversible, versioned mechanisms instead of ad-hoc imperative APIs.

**Applies To:** TI-1 (recommended), TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.6.19 (CP-AUTO-07) ATLAS-CP-AUTO-SELF-MOD — Strict Controls on Self-Modifying Systems

Systems capable of modifying their own execution context, plugins, model weights, routing logic, toolchains, or policy artifacts MUST be isolated from trusted control planes and governed by additional safeguards. Self-modifying systems in TI-2 and TI-3 environments MUST NOT have direct write access to trusted artifacts or control-plane configurations; any self-generated or self-modified artifacts intended for production use MUST pass through independent validation, signing, and promotion workflows.

**Rationale**  
Self-modifying systems – including advanced agents and adaptive control software – can rewrite their own code paths, policies, or models, potentially escaping initial constraints and altering their behaviour in unforeseen ways. If such systems can directly influence trusted control planes, they can circumvent governance entirely and create new, opaque control surfaces. Strict isolation and independent validation ensure that self-modification remains a research or staging activity until explicitly reviewed and promoted.

**Implementation Notes**  
- Run self-modifying systems in disposable or sandboxed environments with no direct write access to production code, policies, or control-plane stores.  
- Require that any artifacts produced by self-modifying systems be treated as untrusted inputs, subject to normal supply-chain, review, and signing processes before deployment.  
- Use separate identities and network paths for “agent compute” versus “agent authority”; the compute identity MUST NOT have direct mutation rights on trusted control planes.  
- Monitor self-modifying systems for attempts to escalate privileges, reach control-plane APIs, or tamper with their own guardrails.  
- Where self-modification is essential (for example, adaptive models), constrain it to bounded parameter or configuration spaces, and periodically reset or retrain from known-good baselines.

**Applies To:** TI-1 (recommended for experimental systems), TI-2 (mandatory when used), TI-3 (mandatory when used)

---
### 3.7 Evidence, Auditability, and Observability Controls

Evidence, auditability, and observability controls ensure that telemetry generated by systems during operation, mutation, and execution is captured, validated, preserved, and verifiable. These controls ensure that signals from runtime systems are usable not only for operational monitoring, but also for security investigation and legal-grade forensic analysis. Atlas distinguishes:

- **Observability** – signals about behaviour and state.
- **Auditability** – signals about intent, authority, and policy decisions.
- **Forensic evidence** – signals preserved and governed as admissible truth in formal proceedings.

All three domains MUST align to provide complete and deterministic execution transparency.

**Scope**  
Controls in this section apply to:

1. Runtime events, logs, traces, metrics, and behavioural telemetry.  
2. Identity, access, and privilege mutation events.  
3. Software supply chain and pipeline attestations.  
4. Evidence linked to legal, regulatory, or dispute contexts.  
5. Telemetry relevant to control-plane or autonomous mutation.

#### 3.7.1 Telemetry Integrity Levels (TI)

Atlas defines three levels of telemetry integrity. System conformance to individual controls in this section MUST be interpreted in the context of these levels.

| Level | Name | Requirements | Used For |
|-------|------|--------------|----------|
| **TI-1** | Operational Observability | Telemetry MAY be unstructured; schemas are optional; cryptographic guarantees are not required. | Debugging, performance tuning, developer tooling. |
| **TI-2** | Security-Relevant Telemetry | Telemetry MUST be structured and schema-enforced; strong integrity protections are recommended. | Authentication events, routing changes, privilege use, anomaly analysis. |
| **TI-3** | Forensic & Control-Plane Evidence | Telemetry MUST be typed, versioned, cryptographically bound, and stored in tamper-evident systems. | Control-plane mutation, provenance, legal evidence, incident reports. |

#### 3.7.2 Mapping Integrity Levels to Architectural Domains

| Architectural Domain                      | Minimum Required Integrity Level |
|-------------------------------------------|----------------------------------|
| General application logging               | TI-1                             |
| Runtime behaviour and execution boundaries| TI-2                             |
| Network & transport events                | TI-2                             |
| Data access, mutation, and sharing        | TI-2                             |
| Software supply chain provenance          | TI-3                             |
| Systemic control plane mutation           | TI-3                             |
| Behavioural control plane mutation        | TI-3                             |
| Autonomous mutation and agentic systems   | TI-3                             |

#### 3.7.3 Subdomains

This section contains three sub-domains of control:

- **3.7.A Observability Controls (`ATLAS-EV-OBS-*`)** – runtime signals, traces, metrics, state transitions.  
- **3.7.B Auditability Controls (`ATLAS-EV-AUD-*`)** – identity binding, attribution, change history, governance traces.  
- **3.7.C Forensic Evidence Controls (`ATLAS-EV-FOR-*`)** – tamper-evident storage, cryptographic proofs, chain-of-custody, legal admissibility.

---

#### 3.7.4 (EV-OBS-01) ATLAS-EV-OBS-STRUCTURED — Structured Telemetry Baseline

Systems operating in TI-2 and TI-3 domains MUST emit structured telemetry for all security-relevant and boundary-relevant runtime events. Systems operating solely in TI-1 MAY emit unstructured logs, but SHOULD adopt structured formats wherever feasible to support future elevation to higher integrity levels. Structured telemetry MUST include sufficient fields to support correlation, detection, and reconstruction (for example, timestamps, actor identity, target object, action, outcome).

**Rationale**  
Unstructured or free-form logs hinder automated correlation, anomaly detection, and post-incident reconstruction, especially at scale or across heterogeneous systems. Without consistent structure, fields are ambiguously defined, making it difficult to infer intent, sequence, or impact. Establishing structured telemetry as the baseline for higher integrity levels provides a foundation for determinism and machine reasoning over system behaviour.

**Implementation Notes**  
- Use machine-parseable formats such as JSON, protobuf, or columnar encodings, rather than ad-hoc human-formatted text.  
- Normalise key fields across services (for example, `actor_id`, `subject_id`, `action`, `result`, `correlation_id`, `ti_level`).  
- Avoid multi-line free-form logs for security-relevant events; store human-readable narratives in separate fields where needed.  
- Ensure that logging libraries and agents preserve structure end-to-end, including in transport and storage.  
- Provide developer guidelines and libraries that make structured logging the default and simplest option.

**Applies To:** TI-1 (recommended), TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.7.5 (EV-OBS-02) ATLAS-EV-OBS-TYPED — Typed & Schema-Validated Telemetry

Telemetry for TI-2 and TI-3 domains MUST be typed, schema-validated, and versioned. Producers and collectors MUST enforce schemas for security-relevant events at ingest time, and invalid or malformed telemetry MUST be rejected, quarantined, or clearly marked as untrusted. Schema evolution MUST be managed through versioning or backward-compatible changes so that downstream analysis and detection remain deterministic.

**Rationale**  
Typed telemetry ensures that fields mean the same thing across agents, clouds, and time. Without schemas and versioning, subtle drift accumulates: fields change semantics, disappear, or become overloaded, breaking correlation and automated reasoning right when it is most needed. Schema validation at ingest prevents low-integrity or attacker-crafted telemetry from polluting higher-integrity pipelines and undermining evidence quality.

**Implementation Notes**  
- Define schemas (for example, JSON Schema, protobuf, Avro) for core event types: authentication, authorisation, data access, policy evaluation, control-plane mutation.  
- Validate telemetry against the appropriate schema at collection or ingestion; route invalid events to a quarantine stream with diagnostics.  
- Store schema identifiers and digests alongside each record (for example, as `schema_id` and `schema_hash`) to support later verification.  
- Use explicit versioning where breaking changes are required; do not silently repurpose fields.  
- Track the mapping of event type → required schema → TI level, and enforce that high-TI events never bypass schema validation.

**Applies To:** TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.7.6 (EV-OBS-03) ATLAS-EV-OBS-CAUSAL-GRAPHS — Causal Behaviour Event Graphs

Systems handling TI-2 and TI-3 workloads SHOULD capture telemetry in a way that supports construction of causal graphs, not just isolated log entries. Telemetry MUST include correlation markers that relate actions to actors, identities, upstream triggers, and dependent operations (for example, process trees, request traces, workflow IDs), so that security teams can reconstruct kill chains and behavioural flows across services and boundaries.

**Rationale**  
Point-in-time logs show what happened but not how events relate to one another. Many attacks unfold as chains of small steps that appear benign in isolation: a new token issuance here, a feature flag flip there, a subtle routing change elsewhere. Causal graphs reveal these sequences by linking events into end-to-end paths, enabling defenders to identify lateral movement, chained exploits, and cross-service propagation.

**Implementation Notes**  
- Capture and propagate correlation IDs or trace IDs across microservices, serverless invocations, and asynchronous queues.  
- Record parent-child relationships for processes, requests, and workflows (for example, parent PID, parent trace ID, initiating user session).  
- Include identifiers for triggering events (for example, “this policy decision was triggered by request X made by identity Y”) in security-relevant records.  
- Use graph-capable storage or indexing (or derive graphs from linear logs) for investigation and threat hunting.  
- Ensure that correlation identifiers are treated as integrity-sensitive fields and are not easily spoofable by untrusted clients.

**Applies To:** TI-2 (recommended), TI-3 (recommended)

---

#### 3.7.7 (EV-OBS-04) ATLAS-EV-OBS-LONGITUDINAL — Longitudinal State Tracking

Systems operating at TI-2 and TI-3 SHOULD record longitudinal state transitions over time, not only instantaneous events. Telemetry MUST capture lifecycle changes for critical entities (for example, identities, roles, routes, policies, datasets) so that defenders can see how state evolved from initial creation through modification, suspension, and revocation, rather than only seeing the latest snapshot.

**Rationale**  
Many breaches and misconfigurations unfold as a series of incremental state transitions that appear unremarkable individually but dangerous in aggregate. If telemetry records only the final state (“role X has permission Y”) without preserving how it got there, incident responders cannot reconstruct which changes were legitimate, which were malicious, and when the boundary was crossed. Longitudinal tracking turns configuration and policy into auditable narratives instead of static facts.

**Implementation Notes**  
- Maintain lifecycle logs for critical resources with explicit states (for example, `created`, `updated`, `delegated`, `revoked`, `expired`, `on_hold`).  
- Capture diffs or snapshots at each significant change, including previous and new values, and link them via identifiers or hashes.  
- Treat policy and role changes as first-class longitudinal events, not as simple overrides of prior values.  
- Provide tooling to visualise the evolution of state over time for specific entities or relationships (for example, “when did this identity gain access to this dataset?”).  
- Coordinate longitudinal logs with control-plane mutation telemetry (Section 3.6) so that state transitions reflect the same authoritative view.

**Applies To:** TI-2 (recommended), TI-3 (recommended)

---

#### 3.7.8 (EV-OBS-05) ATLAS-EV-OBS-CROSS-TRACE — Cross-Boundary Traceability

Telemetry for TI-2 and TI-3 domains SHOULD support traceability across network, tenant, cloud, workload, and organisational boundaries using consistent identity, correlation, or linkage markers. Boundary-crossing events (for example, cross-tenant calls, cross-cloud routing, third-party integrations) MUST be explicitly recorded with both local and remote identifiers so that end-to-end paths can be reconstructed across trust zones.

**Rationale**  
Attack paths rarely stay within a single system; they traverse clouds, tenants, regions, and partner environments. If each boundary uses incompatible or unlinked identifiers, defenders are left with fragmented views that obscure lateral movement and cross-domain escalation. Cross-boundary traceability aligns telemetry around shared markers, enabling unified investigation and coordinated response even when multiple administrative domains are involved.

**Implementation Notes**  
- Use distributed tracing systems that propagate identifiers across services, queues, and network boundaries; map these identifiers to identities and tenants.  
- Normalise or map identities across clouds or tenants where possible (for example, via federation, consistent subject identifiers, or bridging tables).  
- Emit explicit “boundary transition” events when requests cross between trust zones, recording both source and destination principals and correlation IDs.  
- Coordinate telemetry schemas with major partners or critical third parties where cross-domain traceability is operationally required.  
- Ensure that cross-boundary traceability does not leak sensitive information across tenants or jurisdictions; use pseudonymous or mapped identifiers where necessary.

**Applies To:** TI-2 (recommended), TI-3 (recommended)

---
#### 3.7.B Auditability Controls (ATLAS-EV-AUD)

Auditability controls ensure that system behaviour is attributable to specific actors, identities, policies, and intentions. These controls enable systems to explain not just what happened, but who initiated it, under which authority, for what declared purpose, and why the system permitted it. Auditability bridges observability and governance, turning raw events into accountable, reviewable decision trails.

---

#### 3.7.9 (EV-AUD-01) ATLAS-EV-AUD-IDENTITY — Identity-Bound Event Attribution

Every security-relevant action in TI-2 and TI-3 domains MUST be bound to a unique, authenticated actor identity, whether human, service, machine, or autonomous agent. Shared, anonymous, or pooled identities MUST NOT be used for TI-2 or TI-3 events that involve access decisions, data mutation, control-plane changes, or privilege use. Identity binding MUST be preserved end-to-end from initiation through logging, storage, and evidence export.

**Rationale**  
Without strong identity attribution, responsibility collapses, enabling insiders and compromised accounts to act without meaningful accountability. Shared or generic identities make it impossible to distinguish which human or system actually performed an action, undermining both incident response and legal defensibility. Deterministic security depends on being able to trace every sensitive action to a specific, non-repudiable actor.

**Implementation Notes**  
- Assign unique identities for humans, services, machines, and agents; prohibit shared admin accounts except tightly governed break-glass identities.  
- Use strong authentication (for example, MFA, mTLS, hardware-backed keys) to bind actions to identities at the time of execution.  
- Ensure that identity fields in telemetry capture both immediate and original actors (for example, on-behalf-of chains, delegated tokens).  
- Propagate identity through intermediate layers (proxies, gateways, service meshes) so it is not lost or replaced by generic system identities.  
- Treat any security-relevant event that lacks a reliable identity as an integrity failure to be investigated and remediated.

**Applies To:** TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.7.10 (EV-AUD-02) ATLAS-EV-AUD-INTENT — Intent Capture for Privileged Actions

Privileged or high-impact actions in TI-3 domains MUST capture declared or inferred intent, and TI-2 systems SHOULD do so where feasible. For human-initiated actions, systems SHOULD prompt for or associate a short justification or change-ticket reference; for agentic or automated systems, they MUST record decision rationale and evaluated conditions. Intent records MUST be tied to identity, time, and affected resources.

**Rationale**  
Events that record only “what” happened leave ambiguity about whether an action was malicious, negligent, or justified under emergency conditions. Capturing declared intent provides essential context for post-incident analysis, internal reviews, and dispute resolution. For autonomous systems, explicit recording of decision rationale is one of the few defences against opaque or emergent behaviour.

**Implementation Notes**  
- For CLI, console, or workflow-driven privileged operations, prompt operators for an intent field (for example, “reason”, “change-ticket ID”, “incident reference”) and log it.  
- For automated systems and agents, log decision explanations (for example, rules fired, thresholds crossed, policies evaluated) alongside the action.  
- Store intent fields as structured data, not only as free-form text, to support correlation with change management and ticketing systems.  
- Include intent information in TI-3 evidence bundles so reviewers can distinguish expected emergency actions from abuse.  
- Alert on repeated high-impact actions lacking intent metadata or using generic placeholders (for example, “test”, “NA”) as potential misuse patterns.

**Applies To:** TI-2 (recommended), TI-3 (mandatory)

---

#### 3.7.11 (EV-AUD-03) ATLAS-EV-AUD-CHANGE-HISTORY — Immutable Change History

All privileged or security-relevant changes in TI-2 and TI-3 environments MUST be recorded in an immutable, tamper-evident change history that captures before-and-after state. Change records MUST link to the actor identity, declared intent (where available), applicable policies, and any approvals or workflow artefacts. Deletion, rewriting, or silent modification of change history MUST be technically prevented or reliably detectable.

**Rationale**  
Traditional logs often record that a command ran but not precisely what changed. During incidents, this forces responders to infer changes from current state, which is error-prone and easily manipulated by attackers. An immutable change history that records explicit diffs provides a trustworthy narrative of how systems evolved, enabling accurate reconstruction, accountability, and legal-grade evidence.

**Implementation Notes**  
- Record structured diffs for configuration, policy, privilege, routing, and enforcement settings whenever they change.  
- Include hashes or fingerprints of both prior and new state in each change record to support verification and chain construction.  
- Store change history in append-only or cryptographically chained storage compliant with TI-3 requirements when used as evidence.  
- Link change records to ticketing systems, approval workflows, and automation identities where applicable.  
- Design UIs and tooling to read from change history as the authoritative source of “who changed what when,” not from mutable configuration stores.

**Applies To:** TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.7.12 (EV-AUD-04) ATLAS-EV-AUD-POLICY-LINK — Policy-Linked Event Authorisation

Every security-relevant action in TI-2 and TI-3 environments MUST record the policy, rule, or decision logic that authorised it, including version or hash. If a system cannot determine a governing policy for a requested action, the action MUST be blocked, deferred for review, or executed only in a quarantined context with explicit exception logging. Policy links MUST remain valid and resolvable for the full retention period of associated telemetry.

**Rationale**  
Unexplained permission paths lead to privilege creep, shadow permissions, and opaque escalation mechanisms. When responders cannot determine why a system allowed an action, they cannot fix root causes or demonstrate compliance. Linking actions to specific policies makes access decisions deterministic, explainable, and auditable, and exposes misconfigured or overly permissive rules.

**Implementation Notes**  
- For each authorisation, log policy identifiers (for example, name, namespace, version hash) and decision outcomes (allow/deny, reason codes).  
- Ensure policy engines (for example, IAM, OPA, custom rules engines) emit rich decision telemetry tied to requests and identities.  
- Reject or quarantine actions where policy resolution fails, conflicts, or yields ambiguous results; log these as anomalies.  
- Maintain a registry of policy artifacts so logged identifiers remain resolvable long after deployment.  
- Use policy-linked events to drive periodic reviews of rarely used, overly broad, or unexpectedly critical rules.

**Applies To:** TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.7.13 (EV-AUD-05) ATLAS-EV-AUD-SEMANTICS — Semantic Classification of Changes

Systems operating in TI-2 and TI-3 domains MUST classify privileged actions and changes into semantic categories that reflect their risk and impact. At a minimum, categories MUST distinguish operational changes, data-relevant changes, security-relevant changes, and control-plane mutations. These semantic labels MUST be attached at enforcement time and carried through to storage, analytics, and evidence export.

**Rationale**  
Not all changes are equal: scaling a service, granting a new role, exporting a dataset, and altering a policy each carry different risk profiles and response requirements. If all events are logged as generic “changes,” security teams cannot prioritise investigations or tune detection appropriately. Semantic labelling enables targeted controls, alerts, and reviews that match the real-world impact of each action.

**Implementation Notes**  
- Define a hierarchical taxonomy (for example, `OPERATIONAL/SCALE`, `DATA/EXPORT`, `SECURITY/PRIVILEGE/ROLE`, `CONTROL-PLANE/POLICY`) and enforce its use at enforcement points.  
- Tag events as they are generated by gateways, IAM systems, control planes, and administrative tooling; do not rely solely on downstream enrichment.  
- Drive alerting and detection rules using semantic categories (for example, higher sensitivity for `SECURITY/*` and `CONTROL-PLANE/*` events).  
- Provide dashboards and reports organised by semantic category to help owners understand their change patterns and risk exposure.  
- Regularly review the taxonomy and update it as new classes of high-impact changes emerge (for example, AI-specific control changes).

**Applies To:** TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.7.14 (EV-AUD-06) ATLAS-EV-AUD-CROSS-SCOPE — Cross-Scope Attribution

Events that cross trust boundaries, tenancy lines, or identity domains in TI-2 and TI-3 environments MUST record both inbound and outbound identities, including any transformations, impersonations, or delegations. Delegated or impersonated identities MUST be represented explicitly, not collapsed into the acting principal. Audit trails MUST make it possible to reconstruct the full chain from the original actor through all intermediate scopes.

**Rationale**  
Modern systems rely heavily on delegation, federation, and cross-tenant interactions. Without explicit tracking of how identities change across boundaries, lateral movement and cross-scope abuse are easily hidden. Cross-scope attribution prevents identity transformations from becoming blind spots and supports zero-trust analysis of who actually exercised which privileges where.

**Implementation Notes**  
- Log both the “caller” identity and the “effective” identity for cross-scope operations, along with delegation or impersonation metadata.  
- Track token exchanges, role assumptions, and service-to-service calls as distinct events with their own identifiers and policies.  
- Include proof of delegation or impersonation authority (for example, scope, policy reference, signed assertion) in audit records.  
- Ensure identity federation systems emit rich logs that describe mapping between external and internal principals.  
- Use cross-scope attribution data to detect anomalous delegation chains and unexpected cross-tenant or cross-domain access patterns.

**Applies To:** TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.7.C Forensic Evidence Controls (ATLAS-EV-FOR)

Forensic evidence controls ensure that telemetry and state-change records can serve as verifiable truth in dispute resolution, regulatory investigations, incident response, or legal proceedings. These controls focus on tamper-evidence, time validity, cryptographic guarantees, and chain-of-custody preservation. They apply to TI-3 records and SHOULD NOT be implemented selectively within the same trust boundary.

---

#### 3.7.15 (EV-FOR-01) ATLAS-EV-FOR-TAMPER — Tamper-Evident Storage

TI-3 records MUST be stored in append-only or cryptographically verifiable storage such that any modification, deletion, or reordering is detectable. Systems MUST enforce technical controls that prevent unauthorised alteration of stored evidence, or at minimum make alterations provably visible. Administrative privileges alone MUST NOT be sufficient to silently alter or purge TI-3 evidence.

**Rationale**  
If evidence can be edited or removed without detection, adversaries and insiders can rewrite history, undermining all higher-level security and compliance claims. Tamper-evident storage is a foundational requirement for treating telemetry as evidence rather than as mere logs. It enables courts, regulators, and independent reviewers to trust that records reflect what actually happened, not what a post-incident editor prefers.

**Implementation Notes**  
- Use WORM filesystems, cryptographically chained logs (for example, Merkle trees), or dedicated audit ledger systems for TI-3 data.  
- Protect access to evidence storage with strict RBAC, enforcing separation between producers, consumers, and storage administrators.  
- Periodically verify integrity of stored data using checksums, hash chains, or ledger verification tools.  
- Log and alert on any attempts to bypass or misconfigure tamper-evident mechanisms.  
- Document evidence storage architecture and controls as part of TI-3 readiness assessments and audits.

**Applies To:** TI-3 (mandatory)

---

#### 3.7.16 (EV-FOR-02) ATLAS-EV-FOR-DIGEST — Cryptographic Digest & Linking

Each TI-3 evidence record, or block of records, MUST include cryptographic digests that link it to prior entries, forming a verifiable chain. Verification of the chain MUST detect missing, reordered, or altered records. Digest algorithms and configurations MUST be resistant to known attacks for the expected lifetime of the evidence.

**Rationale**  
Linear append-only storage without linkage still permits deletion or insertion attacks that are hard to detect. Cryptographic linking between records creates a ledger where each entry proves the existence and ordering of its predecessors. This transforms logs into structured evidence where attempts to tamper with history leave visible cryptographic scars.

**Implementation Notes**  
- Compute a digest (for example, SHA-2 or SHA-3 family) over each record or block, including its predecessor’s digest to form a chain.  
- Sign digests or blocks where appropriate, especially at rotation points or checkpoints.  
- Store sequence numbers and digests together; reject or flag chains that exhibit gaps, reversals, or inconsistencies.  
- Use different chains or streams for different evidence classes where isolation is required, but preserve linkage within each stream.  
- Include chain metadata in exported evidence bundles so external verifiers can reconstruct and validate the sequence.

**Applies To:** TI-3 (mandatory)

---

#### 3.7.17 (EV-FOR-03) ATLAS-EV-FOR-TIMESTAMP — Cryptographically Valid Time Binding

All TI-3 records MUST be cryptographically time-stamped using trusted time sources or timestamp authorities. Local system clocks alone SHALL NOT be considered sufficient for evidentiary purposes without independent attestation. Time-binding MUST make it infeasible to backdate or forward-date events without detection.

**Rationale**  
Precise and trustworthy timing is critical to almost all investigations and legal evaluations. If a system can arbitrarily rewrite event timestamps, it can fabricate alibis, conceal delays, or change apparent causality. Cryptographic time-binding anchors events to verifiable timelines, making it much harder to falsify when something occurred.

**Implementation Notes**  
- Use RFC 3161-compliant timestamp authorities, hardware secure time sources, or external attestation services for critical evidence streams.  
- Combine externally attested timestamps with monotonic sequence indices to detect clock skew, resets, or manipulation.  
- Periodically reconcile local time with trusted sources, logging discrepancies as potential integrity concerns.  
- Include timestamp proofs in evidence exports so third parties can validate them without depending on the original system’s clocks.  
- Treat sudden or unexplained time jumps on key systems as security events requiring investigation.

**Applies To:** TI-3 (mandatory)

---

#### 3.7.18 (EV-FOR-04) ATLAS-EV-FOR-ANCHOR — Optional External Chain Anchoring

TI-3 evidence chains MAY be anchored periodically to external verifiable sources (for example, public ledgers, certificate transparency-style logs, distributed timestamp proofs) to strengthen cross-jurisdictional and multi-party trust. External anchoring MUST complement, not replace, local timestamping and tamper-evident mechanisms; absence of external anchoring MUST NOT be interpreted as an integrity failure inside a single trust boundary.

**Rationale**  
In disputes involving multiple parties, jurisdictions, or potentially compromised operators, independent anchors can provide an additional layer of confidence that evidence existed in a particular form at or before a certain time. External anchoring helps counter allegations that an organisation retroactively edited logs or reconstructed them to match a narrative. It is optional but valuable where the stakes justify the operational overhead.

**Implementation Notes**  
- Periodically publish commitments (for example, root hashes of evidence chains) to external systems that provide durable, verifiable records.  
- Ensure published anchors do not leak sensitive content; commit to digests or Merkle roots, not raw logs.  
- Maintain internal records that map anchors to specific evidence ranges and chains.  
- Use multiple independent anchoring services or mechanisms to avoid reliance on a single external party.  
- Describe anchoring strategy and verification procedures in internal governance and external assurance documentation.

**Applies To:** TI-3 (recommended)

---

#### 3.7.19 (EV-FOR-05) ATLAS-EV-FOR-REPLICATION — Redundant, Trust-Separated Replication

TI-3 evidence MUST be replicated across trust-separated domains such that compromise of one storage domain does not permit undetectable alteration or destruction. Replication strategies MUST consider geographic, organisational, and infrastructural separation, and MUST ensure that all replicas participate in integrity verification processes.

**Rationale**  
Single-location or single-operator evidence stores are vulnerable to catastrophic loss or undetected tampering, whether from attackers, insiders, or operational failures. Trust-separated replication ensures that no single breach or error can silently erase or rewrite the record. It also supports business continuity and regulatory requirements for evidence durability.

**Implementation Notes**  
- Replicate evidence across multiple environments (for example, different cloud providers, regions, or on-premises and cloud combinations) under distinct administrative control.  
- Use independent keys or trust anchors for verifying evidence in each domain, while keeping chain linkage consistent.  
- Regularly perform cross-domain integrity checks to ensure replicas agree on chain content and ordering.  
- Protect replication channels with strong encryption and authentication, and log replication operations as TI-3 events.  
- Consider threshold or split-key mechanisms so that no single administrator can compromise all replicas.

**Applies To:** TI-3 (mandatory)

---

#### 3.7.20 (EV-FOR-06) ATLAS-EV-FOR-REVOCATION — Evidence Revocation & Dispute Protocols

Systems MUST support cryptographic revocation or contesting of specific evidence records without deleting or altering the original entries. Revocation MUST be implemented by appending revocation or correction records that reference the disputed evidence and state the reason, not by removing or overwriting the original. Consumers of evidence MUST be able to see both the original record and all subsequent revocation or dispute annotations.

**Rationale**  
Evidence systems occasionally ingest erroneous, misattributed, or later-disputed records. Simply deleting or editing such records undermines the integrity of the entire chain. Append-only revocation preserves the factual history of what was recorded at the time, while clearly signalling that its interpretation is contested. This supports fair dispute resolution without sacrificing non-repudiation.

**Implementation Notes**  
- Define an evidence record identifier scheme that allows precise referencing of entries or blocks.  
- Create explicit revocation or dispute record types that link to original entries and include justification, time, and identity.  
- Ensure verifiers and analysis tools treat revocation metadata as first-class information, not as soft annotations that can be ignored.  
- Govern who may issue revocations or disputes and under what processes (for example, legal, compliance, incident response).  
- Include revocation chains in exported evidence bundles so external reviewers see the full history of both events and disputes.

**Applies To:** TI-3 (mandatory)

---

#### 3.7.21 (EV-FOR-07) ATLAS-EV-FOR-EXPORT — Portable, Verifiable Evidence Export

TI-3 forensic evidence MUST be exportable in a portable format that preserves verification capabilities, chain linkage, timestamps, and attestation metadata outside the originating system. Export processes MUST NOT strip integrity information, compress chains in ways that break verifiability, or require proprietary tools that cannot be independently audited.

**Rationale**  
Evidence is only useful if investigators, regulators, courts, or independent assessors can examine it outside the system where it was generated. If export discards or obscures integrity metadata, the evidentiary value is lost at the point of transfer. Portable, verifiable export formats protect against vendor lock-in and ensure that multiple parties can independently validate the same corpus.

**Implementation Notes**  
- Define export formats that include logs, chain metadata (hashes, sequence numbers), signatures, timestamp proofs, and schema references.  
- Provide verification tools or reference implementations that can validate exported bundles without requiring access to the original environment.  
- Document export procedures and controls to ensure they are repeatable and auditable.  
- Log all export operations as TI-3 events, including requester, scope, and destination.  
- Ensure export processes can be scoped (for example, by time, tenant, system) without breaking chain verifiability within the exported range.

**Applies To:** TI-3 (mandatory)

---

#### 3.7.22 (EV-FOR-08) ATLAS-EV-FOR-ADMISSIBILITY — Legal & Regulatory Admissibility Requirements

TI-3 evidence SHOULD be designed and operated to satisfy relevant legal and regulatory admissibility criteria in the jurisdictions where it may be used (for example, civil procedure rules, e-discovery requirements, digital evidence standards). Organisations SHOULD periodically test their evidence processes end-to-end, from capture through export, to demonstrate that identity, integrity, time, and chain-of-custody can be reliably established.

**Rationale**  
Technical guarantees alone do not ensure that evidence will be accepted or persuasive in formal proceedings. Gaps in documentation, chain-of-custody, or operational practice can lead to exclusion or reduced weight, even when underlying cryptography is sound. Aligning evidence management with legal and regulatory expectations ensures that investments in TI-3 controls translate into real-world trust and accountability.

**Implementation Notes**  
- Map evidence lifecycle controls to applicable legal and regulatory frameworks and update them as those frameworks evolve.  
- Maintain clear documentation of how evidence is captured, protected, replicated, verified, and exported, including roles and responsibilities.  
- Conduct periodic mock proceedings or independent assessments to validate that evidence would likely be considered reliable and admissible.  
- Train operations, security, and legal teams on how to handle evidence in ways that preserve chain-of-custody and avoid contamination.  
- Incorporate admissibility considerations into system design for high-risk or highly regulated domains, not as an afterthought.

**Applies To:** TI-3 (recommended)

---
### 3.8 Autonomous and Agentic System Controls

Autonomous and agentic system controls govern software that incorporates AI models or agents in ways that can influence, initiate, or directly perform actions affecting system state, control planes, data, or external environments. AI components MUST NEVER be treated as inherently trustworthy, regardless of vendor, deployment model, or training pedigree. All AI influence over execution MUST pass through deterministic, policy-bound enforcement layers and remain subject to the same or stricter controls as any untrusted external input.

Atlas distinguishes three classes of AI-integrated systems based on execution authority, autonomy of action, and the ability to modify operational capabilities. These classes determine baseline trust requirements and applicable controls.

#### 3.8.1 Classification Definitions

**AI-Assisted Software (AAS)**  
Systems that use AI to generate insights, recommendations, or content but do not execute actions on systems, data, or control planes without direct human initiation. AAS SHALL NOT possess execution authority and SHALL NOT mutate system state without human-triggered enforcement at a separate boundary.

**Autonomous Execution Systems (AES)**  
Systems capable of independently initiating actions that modify system state, configuration, infrastructure, routing, identity, data access, or security posture without direct human triggers. AES operate with scoped execution authority and MUST comply with deterministic enforcement, attribution, and auditability controls defined in this standard.

**Self-Modifying Autonomous Execution Systems (SM-AES)**  
Autonomous systems capable of modifying their own execution logic, policies, privileges, tools, decision models, or authority boundaries. SM-AES represent systemic security risk and MUST be governed by the highest integrity requirements defined in this standard, including TI-3 forensic evidence, deterministic evaluation, policy provenance, reversible changes, and cryptographic isolation from trusted control planes.

---

#### 3.8.2 (AI-BASE-01) ATLAS-AI-UNTRUSTED-OUTPUT — AI Output Treated as Untrusted Input

All artifacts produced by AI systems or agents – including content, code, configuration, policies, embeddings, structured outputs, inferred knowledge, and proposed execution actions – MUST be treated as untrusted input by default. Systems MUST NOT execute, enforce, or apply AI-generated artifacts without passing them through explicit validation and policy-bound approval appropriate to their impact and trust level. AI output MUST be subject to the same or stricter controls as untrusted external client input.

**Rationale**  
AI systems optimise for plausibility, not truth or safety, and are susceptible to prompt injection, jailbreaks, data poisoning, and emergent misalignment. Treating AI output as implicitly trusted collapses zero-trust boundaries and allows adversarial instructions or hallucinations to flow directly into critical control surfaces. Classifying AI output as untrusted preserves the ATLAS posture that trust is earned through verification, not inferred from origin or branding.

**Implementation Notes**  
- Classify all AI-generated artifacts as untrusted until they have passed validation and policy checks equivalent to external user input.  
- Ensure that AI-generated code, scripts, or commands are never executed directly in production environments; treat them as proposals for review.  
- Require separate approval or policy evaluation layers before AI-generated configuration, policies, or remediation suggestions can affect runtime systems.  
- Design interfaces such that AI output flows into review and enforcement pipelines, not directly into shells, deployment tools, or control-plane APIs.  
- Explicitly document in architecture that AI runtimes are not part of the Trusted Computing Base (TCB) unless narrowly justified and separately controlled.

**Applies To:**  
- TI-1: recommended for any AI integration  
- TI-2: mandatory (all AAS, AES, SM-AES)  
- TI-3: mandatory (all AAS, AES, SM-AES)

---

#### 3.8.3 (AI-BASE-02) ATLAS-AI-VALIDATION — Validation Before Execution

AI-generated artifacts that can affect system state – including operations, infrastructure, data, identity, routing, or security policy – MUST undergo deterministic validation before execution or deployment. Validation MUST rely on rule-based, schema-based, or formally verifiable checks and MUST NOT rely solely on heuristic, model-based, or probabilistic reasoning. Where validation fails or cannot be completed, AI artifacts MUST be rejected, quarantined, or downgraded to non-executable reference material.

**Rationale**  
AI systems can produce syntactically plausible but semantically unsafe outputs, including misconfigurations and exploit payloads. If validation is weak, heuristic, or itself delegated back to AI, model errors and adversarial steering become indistinguishable from safe recommendations. Deterministic validation inserts a hard barrier between suggestion and execution, ensuring that only artifacts that meet explicit safety and policy criteria can mutate the system.

**Implementation Notes**  
- Validate AI-generated configurations and policies against strict schemas, invariants, and domain-specific safety rules before applying them.  
- For AI-generated code or automation scripts, require compilation, static analysis, sandboxed test execution, and independent review or policy-gate approval before production use.  
- Enforce allowlists for permissible operations, APIs, resources, and parameter ranges when interpreting AI outputs.  
- Implement validation pipelines as independent services or components that do not share the same trust boundary or runtime with the AI model.  
- Log validation results, including rejected artifacts and reasons, as TI-2 or TI-3 events to support detection of adversarial or misaligned behaviour.

**Applies To:**  
- TI-1: recommended where AI proposals may be executed  
- TI-2: mandatory  
- TI-3: mandatory

---

#### 3.8.4 (AI-BASE-03) ATLAS-AI-PROVENANCE — Provenance Required for Elevated Trust

AI-generated artifacts MAY be granted elevated trust (for example, reduced review friction or semi-automated execution within constrained scopes) only if all of the following conditions hold:  
1. The generating AI system is governed under an appropriate risk and quality management framework (for example, ISO/IEC 42001 or equivalent).  
2. The artifact is cryptographically bound to a verifiable model or system identity.  
3. Provenance metadata is preserved end-to-end, including model identifier, model version, key configuration parameters, and prompt or input context.  
4. All required validation and policy checks have succeeded.  
Absent these conditions, provenance MUST NOT elevate an artifact’s trust level beyond that of generic untrusted input.

**Rationale**  
Without provenance, defenders cannot distinguish between artifacts produced by governed, vetted models and those produced by untrusted or compromised systems. Attackers can replay outputs from shadow models, spoof origins, or exploit model drift and silent retraining. Binding artifacts to verifiable provenance and governance context allows organisations to selectively grant limited trust while still being able to trace and revoke problematic outputs.

**Implementation Notes**  
- Attach structured provenance metadata to AI outputs, including generating system, model name, version, configuration (for example, temperature), and calling application.  
- Cryptographically bind provenance to artifacts (for example, signatures over content plus provenance bundle) so it cannot be stripped or forged without detection.  
- Store AI provenance in TI-2 or TI-3 telemetry alongside downstream actions that used the artifacts, enabling full-chain reconstruction.  
- Use policy to constrain which models or deployments are eligible for any form of elevated trust and under what conditions.  
- Treat artifacts with missing, inconsistent, or unverifiable provenance as strictly untrusted regardless of the apparent source.

**Applies To:**  
- TI-1: recommended for safety-critical AAS  
- TI-2: mandatory where any trust elevation is contemplated  
- TI-3: mandatory

---

#### 3.8.5 (AI-BASE-04) ATLAS-AI-NO-DIRECT-EXECUTION — No Direct Execution of Model Output

Model or agent output that represents executable content – including shell commands, infrastructure-as-code, configuration patches, remediation actions, workflow definitions, deployment manifests, or runtime scripts – MUST NOT be executed, applied, or enforced directly. All such output MUST pass through an enforcement layer that validates semantics, enforces policy, and mediates execution according to system classification (AAS / AES / SM-AES) and TI level. Direct piping of model output into interpreters, deployment tools, or control-plane APIs in TI-2 and TI-3 environments is prohibited.

**Rationale**  
Patterns such as “LLM → shell”, “LLM → CI/CD”, or “LLM → Kubernetes API” effectively give the model unbounded control-plane access. A single prompt injection or jailbreak can translate into arbitrary mutations of infrastructure, data, or identities. Even benign hallucinations can introduce outages or subtle weaknesses. Forcing all execution through explicit enforcement layers preserves the ability to bound, inspect, and veto AI-driven actions.

**Implementation Notes**  
- Replace direct execution flows (for example, piping model output into `bash`, `kubectl`, `terraform`, or cloud CLIs) with review pipelines that materialise outputs as proposals.  
- Implement dedicated “AI gateways” that translate model suggestions into structured action objects, apply policies, and emit only approved, bounded operations.  
- For CI/CD, require that AI-generated pipeline edits be committed and reviewed like human-authored changes, with separate approval and testing gates.  
- For operational assistants, limit AI to generating runbooks or playbooks that humans or separately governed controllers execute under independent policy.  
- Instrument controls to detect and block any path where raw model output appears directly as executed commands or API calls in TI-2 and TI-3 systems.

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory

---

#### 3.8.6 (AI-BASE-05) ATLAS-AI-DETERMINISM — Deterministic Enforcement of AI-Influenced Actions

AI-influenced execution MUST remain deterministic at enforcement points even if AI inputs are probabilistic or non-deterministic. Given identical preconditions (including state, identity, policies, and validated AI proposals), enforcement MUST yield identical outcomes. Systems MUST reject, defer, or quarantine execution requests where deterministic evaluation cannot be established or proven, particularly for privilege, control-plane, or data-access decisions.

**Rationale**  
If enforcement decisions vary unpredictably for the same conditions because they depend directly on stochastic model behaviour, organisations cannot reliably reason about security posture, reproduce incidents, or produce credible evidence. Non-deterministic enforcement undermines auditability and weakens legal defensibility of control claims. Separating non-deterministic suggestion from deterministic enforcement keeps AI within a bounded advisory role at the point of decision.

**Implementation Notes**  
- Treat AI outputs as parameters to deterministic policy engines; ensure that given the same inputs and AI-provided values, the engine always returns the same decision.  
- Normalise and canonicalise inputs (including AI outputs) before policy evaluation to avoid spurious differences caused by formatting or ordering.  
- Prohibit probabilistic or “confidence-score only” gates for high-impact actions; require explicit policy rules or thresholds that map inputs to outcomes.  
- Log the full set of inputs and evaluated policies for each enforcement decision so that results can be recomputed during investigation.  
- Fail closed when required inputs (including AI proposals) are missing, ambiguous, or cannot be validated to the level expected for the TI domain.

**Applies To:**  
- TI-1: recommended for any AI that affects configuration  
- TI-2: mandatory  
- TI-3: mandatory

---

#### 3.8.7 (AI-BASE-06) ATLAS-AI-TRACE — Traceability of AI Influence

Systems MUST record where and how AI influenced decisions, actions, or configurations in TI-2 and TI-3 domains. For each AI-influenced action, telemetry MUST capture at least: the AI system of origin, model identity and version, prompt or input context identifier, degree or mode of influence (for example, “suggested”, “auto-applied within scope X”), and final enforcement authority. This metadata MUST be incorporated into TI-2 logs and TI-3 forensic records to enable reconstruction and challenge of AI contributions.

**Rationale**  
Without explicit traceability, defenders cannot distinguish between purely human-driven actions and those shaped or initiated by AI. This obscures root cause analysis, hides emerging AI failure modes, and complicates accountability when AI and humans collaborate. Traceability clarifies where AI was involved, which models were used, and which enforcement layer ultimately authorised the action.

**Implementation Notes**  
- Tag AI-influenced actions with metadata fields such as `ai_origin`, `ai_model_id`, `ai_model_version`, `ai_context_id`, and `ai_influence_mode`.  
- Log whether AI output was merely advisory, partially applied, or used as the primary basis for an enforcement decision.  
- Link AI influence records to provenance metadata for both the model and the affected resources or policies.  
- Include AI influence markers in evidence exports so external reviewers can see which actions depended on AI and which did not.  
- Use AI traceability data to monitor for systemic issues (for example, a particular model version correlated with misconfigurations or incidents).

**Applies To:**  
- TI-1: recommended for critical workflows  
- TI-2: mandatory  
- TI-3: mandatory

---

#### 3.8.8 (AI-BASE-07) ATLAS-AI-CONTAINMENT — AI Output Containment Boundaries

AI-generated artifacts MUST NOT gain implicit authority or bypass enforcement layers through placement, naming, formatting, or co-location with trusted artifacts. Containment boundaries MUST enforce strict separation between model output, execution authority, and control-plane policy. Systems MUST prevent AI outputs from being written directly into locations or channels that are implicitly trusted as authoritative configuration, code, or policy without passing through independent checks.

**Rationale**  
Even when explicit validation exists, subtle paths can emerge where AI-generated artifacts are treated as more trusted than intended – for example, by writing directly into “official” configuration directories, source repositories, or policy stores. Attackers can exploit naming conventions, file locations, or template systems to smuggle unreviewed AI output into trusted surfaces. Enforcing containment ensures that trust comes from validated process, not from where a file lives or how it looks.

**Implementation Notes**  
- Segregate storage for raw AI outputs from repositories or stores that represent authoritative code, configuration, or policy.  
- Require promotion workflows (including validation and approvals) to move artifacts from AI output areas into trusted locations.  
- Avoid auto-loading or auto-applying files from directories that AI can write to; treat such directories as untrusted sources.  
- Ensure that AI systems cannot directly modify policy engines, identity providers, signing services, or other boundary-enforcing toolchains.  
- Log and alert on attempts by AI processes to write into trusted configuration or control-plane stores, treating them as potential boundary violations.

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory

#### 3.8.B Autonomous Execution System Controls (ATLAS-AES)

Autonomous Execution Systems (AES) operate with execution authority without direct human initiation and therefore require stricter controls than AI-Assisted Software (AAS). AES MUST comply with all baseline AI controls in 3.8.A and, in addition, MUST conform to the controls in this subsection. Systems capable of autonomously modifying their own execution boundaries, capabilities, or authority are classified as Self-Modifying Autonomous Execution Systems (SM-AES) and are additionally governed by 3.8.C.

---

#### 3.8.9 (AI-AES-01) ATLAS-AES-SCOPE-DECLARED — Human-Defined Execution Boundaries

Execution boundaries for AES MUST be explicitly defined by humans prior to deployment and MUST be represented as machine-enforceable boundary specifications. These boundaries SHALL, at minimum, identify: permitted capabilities (what actions may be performed), permitted domains (which system layers or subsystems may be influenced), and the permitted resource set (specific assets, namespaces, tenants, or identifiers). No AES MAY operate in TI-2 or TI-3 environments without a declared and enforceable boundary specification.

**Rationale**  
Without explicit human-defined boundaries, autonomous systems will gradually operate as general-purpose control surfaces rather than bounded tools. Ambiguous or undocumented scopes turn AES into latent control planes whose effective authority is discovered only after incidents occur. Declaring and enforcing boundaries upfront ensures that organisations can reason about what an AES may touch, how far it can reach, and which blast radius is acceptable.

**Implementation Notes**  
- Represent AES boundaries as signed policy artifacts (for example, “capability manifests”) that enumerate allowed actions, domains, and resources.  
- Use explicit identifiers for resources and domains (for example, namespaces, projects, tenants, clusters), not vague patterns or descriptive text.  
- Store boundary specifications in the same configuration or policy systems used for other critical controls, under change control and review.  
- Enforce boundary checks at the point where AES requests are translated into concrete actions (for example, gateway, orchestrator, or control-plane API).  
- Treat operation of an AES without a valid, loaded boundary specification as a misconfiguration and fail closed.

**Applies To:** TI-2 AES and SM-AES (mandatory), TI-3 AES and SM-AES (mandatory)

---

#### 3.8.10 (AI-AES-02) ATLAS-AES-SCOPE-FIXED — No Autonomous Expansion of Boundaries

AES MUST NOT modify, extend, or reinterpret their own execution boundaries. Any change to permitted capabilities, domains, or resources MUST be initiated and authorised by humans through external governance processes and MUST be applied via deployment or configuration changes, not by the AES itself at runtime. Systems that can autonomously adjust their own boundaries SHALL be classified and governed as SM-AES under 3.8.C.

**Rationale**  
Allowing an AES to expand or reinterpret its own scope effectively delegates control over blast radius to the system being constrained, creating a direct conflict of interest. Over time, such systems tend to accrete capabilities, especially when optimising for performance or task completion, turning a narrow agent into a general control authority. Fixing boundaries outside the AES and prohibiting self-expansion preserves the separation between governed policy and governed automation.

**Implementation Notes**  
- Prohibit AES from writing to their own boundary specifications, capability manifests, or access-control policies.  
- Treat any attempt by an AES to alter its allowed resources, roles, or domains as a boundary violation and log it as a TI-3 event.  
- Require boundary changes to go through standard change management, review, and deployment pipelines, just like other critical policy changes.  
- Use separate identities and credentials for “boundary management” components so the AES cannot impersonate them.  
- Where adaptive behaviour is required, design the AES to choose among pre-defined boundary-constrained modes, not to redefine boundaries.

**Applies To:** TI-2 AES and SM-AES (mandatory), TI-3 AES and SM-AES (mandatory)

---

#### 3.8.11 (AI-AES-03) ATLAS-AES-NO-PRIV-ESC — No Autonomous Privilege Escalation

AES MUST NOT autonomously create, grant, modify, or extend privileges, identities, IAM roles, or authorisation scopes. Any request by an AES that would result in increased authority – whether for itself, for other systems, or for human operators – MUST be blocked or routed to a separate human-governed system for review and enforcement. Privilege expansion decisions MUST remain explicitly outside AES control.

**Rationale**  
Privilege escalation is a primary pathway from bounded automation to systemic compromise. If AES can manipulate IAM, group memberships, role bindings, or token scopes, then any failure in the AES (or its inputs) becomes a privileged control-plane compromise. Keeping privilege changes outside AES authority ensures that they always pass through governance designed for identity and access management, not task completion.

**Implementation Notes**  
- Block AES from invoking APIs that directly modify IAM configurations, group memberships, role assignments, or token scopes.  
- Configure control-plane APIs to treat requests originating from AES identities as ineligible for privilege-granting operations.  
- Where AES must recommend privilege changes (for example, during incident response), treat these as proposals that humans or separate policy engines must approve.  
- Monitor for indirect privilege escalation patterns (for example, changing policies or configurations that indirectly increase access) and subject them to strict review.  
- Include “no privilege escalation” as an explicit invariant in AES boundary specifications and test suites.

**Applies To:** TI-2 AES and SM-AES (mandatory), TI-3 AES and SM-AES (mandatory)

---

#### 3.8.12 (AI-AES-04) ATLAS-AES-AUTHORSHIP — Machine-Signed Autonomous Decisions

Each autonomous action taken by an AES in TI-2 or TI-3 environments MUST be cryptographically attributed to a unique machine identity distinct from human accounts and generic service principals. Autonomous decisions MUST be signed or otherwise strongly bound to this identity, and signatures or attribution proofs MUST be retained in TI-2 telemetry and TI-3 evidence. AES MUST NOT reuse human administrator identities or shared service accounts for autonomous actions.

**Rationale**  
If AES actions are indistinguishable from human administrator activity in audit logs, compromise or misbehaviour cannot be attributed, and revocation becomes coarse and disruptive. Machine-specific identities and signatures create a clear chain of authorship, allowing organisations to distinguish autonomous behaviour from human actions and to selectively revoke or constrain misbehaving agents.

**Implementation Notes**  
- Issue distinct credentials and certificates for each AES, with separate keys for decision signing and for ordinary service communication.  
- Require that control-plane mutations and other high-impact actions carry signed metadata identifying the specific AES identity.  
- Store signatures or verifiable attribution tokens with each action record in TI-2/TI-3 telemetry stores.  
- Prohibit AES from using human admin accounts, shared “ops” accounts, or generic service principals for high-impact operations.  
- Provide mechanisms to quickly disable or rotate AES identities and keys without affecting unrelated systems.

**Applies To:** TI-2 AES and SM-AES (mandatory), TI-3 AES and SM-AES (mandatory)

---

#### 3.8.13 (AI-AES-05) ATLAS-AES-TI3-EVIDENCE — Autonomous Actions Recorded as TI-3 Evidence

All autonomous execution events that modify system state, configuration, routing, control planes, data access, or security posture MUST be recorded as TI-3 forensic evidence. Records MUST include at least: detailed action description, AES identity, evaluated boundaries, decision rationale (if available), governing policy reference, prior state digest, resulting state digest, and cryptographically valid timestamps. System clocks alone SHALL NOT satisfy temporal proof requirements for AES actions in TI-3 environments.

**Rationale**  
Autonomous actions can produce large-scale impact quickly; when they go wrong, responders need legally defensible, high-integrity records of exactly what was done and why. Treating AES actions as ordinary logs undermines the ability to investigate, assign responsibility, or challenge system behaviour in regulatory or legal contexts. Elevating AES activity to TI-3 ensures that the most consequential actions are preserved as evidence, not as disposable telemetry.

**Implementation Notes**  
- Route AES action logs into the same tamper-evident, cryptographically chained evidence stores used for other TI-3 events (see 3.7.C).  
- Capture before-and-after state digests (for example, hashes of configuration or policy documents) for each significant autonomous mutation.  
- Link each action to the boundary specification and policy version that permitted it, enabling later evaluation of whether the action was proper.  
- Use trusted timestamping mechanisms (for example, external TSAs or hardware-backed time) for AES evidence records.  
- Provide tooling to reconstruct and replay AES action sequences for investigation and audit.

**Applies To:** TI-2 AES and SM-AES (recommended), TI-3 AES and SM-AES (mandatory)

---

#### 3.8.14 (AI-AES-06) ATLAS-AES-REVERSIBLE — Autonomous Actions Must Be Atomic and Reversible

AES actions that change configuration, control-plane state, routing, or infrastructure MUST be designed to be atomic and reversible. For each autonomous change, AES or associated control systems MUST maintain sufficient information to deterministically restore the prior state without manual reconstruction. Where reversibility cannot be guaranteed, AES MUST NOT perform the change autonomously and MUST escalate to human-controlled workflows.

**Rationale**  
Autonomous systems can mutate state faster than human teams can comprehend it. If those mutations are not reversible, a single misjudged or adversarially steered action can force destructive rollback scenarios or long outages. Requiring atomic and reversible changes ensures that organisations remain in control even when AES make mistakes, and that recovery from misbehaviour is a technical operation, not an archaeological dig.

**Implementation Notes**  
- Represent AES actions as transactions with explicit preconditions and postconditions, enabling all-or-nothing application.  
- Store change diffs, snapshots, or version identifiers for any state modified by AES so previous versions can be restored.  
- Implement tested rollback procedures for each category of autonomous change (for example, config rollbacks, route reversions, policy version restores).  
- Treat inability to compute a safe rollback for a requested change as a reason to deny or escalate that change.  
- Log both successful and failed rollback attempts as TI-2 or TI-3 events, including root cause where rollback is not possible.

**Applies To:** TI-2 AES and SM-AES (mandatory), TI-3 AES and SM-AES (mandatory)

---

#### 3.8.15 (AI-AES-07) ATLAS-AES-NO-CONTROL-PLANE-WRITES — No Direct Control Plane Mutation

AES MUST NOT write directly to systemic control planes – including identity providers, core routing systems, policy engines, infrastructure orchestrators, or secrets managers. All AES-initiated changes that would affect these systems MUST be mediated through dedicated enforcement layers that apply independent policy evaluation, boundary checking, and human or quorum approval where required. AES that can directly mutate control planes are effectively acting as control planes themselves and MUST instead be classified and governed as SM-AES under 3.8.C.

**Rationale**  
Direct writes from AES into control planes eliminate the separation between “automation subject to policy” and “the policy source itself”. A compromised or misaligned AES with control-plane write access can silently rewrite the very systems that are meant to constrain it, creating a self-ratifying failure mode. Mediation via external enforcement layers keeps AES on the controlled side of the boundary, not on the enforcement side.

**Implementation Notes**  
- Configure control-plane APIs to reject write operations authenticated solely with AES identities; require mediation by enforcement components.  
- Implement “AI control gateways” that accept AES proposals, apply independent policy, and then issue controlled changes to core systems.  
- Prohibit AES from holding credentials capable of directly modifying IAM, core routing, or primary policy stores.  
- Monitor for any direct control-plane modification attempts originating from AES-related identities and treat them as boundary violations.  
- Explicitly document which classes of changes AES may propose and which enforcement systems are responsible for applying them.

**Applies To:** TI-2 AES and SM-AES (mandatory), TI-3 AES and SM-AES (mandatory)

---

#### 3.8.16 (AI-AES-08) ATLAS-AES-DOMAIN-ISOLATION — Domain Isolation and Flow Constraints

AES MUST execute within an isolated domain that prevents lateral impact on unrelated systems or trust zones. Action flows from AES MUST be constrained so that an agent authorised to operate in one domain (for example, scaling compute resources) cannot directly modify other domains (for example, network policy, identity roles, or cross-tenant routing). Any attempted boundary violation MUST raise a security event and MUST result in cancellation of the offending execution path.

**Rationale**  
AES often integrate with multiple systems and APIs; without strong domain isolation, they can unintentionally or maliciously affect areas far beyond their intended remit. For example, an agent meant to adjust scaling parameters could also change firewall rules if domains are not clearly separated. Isolation and flow constraints ensure that authority granted in one domain cannot silently bleed into others.

**Implementation Notes**  
- Partition system responsibilities into domains (for example, compute, network, identity, data) and assign each AES to one or more specific domains only.  
- Enforce domain separation in identity and access management, API gateways, and network segmentation.  
- Validate that AES-originated requests target only APIs and resources within their assigned domains; deny out-of-domain access attempts.  
- Log domain boundary violations as TI-2 or TI-3 events, including full context for investigation.  
- Where an AES must coordinate changes across domains, require separate, independently constrained identities per domain and higher-level orchestration outside the AES.

**Applies To:** TI-2 AES and SM-AES (mandatory), TI-3 AES and SM-AES (mandatory)

---

#### 3.8.17 (AI-AES-09) ATLAS-AES-NO-CHAINS — No Autonomous Chaining of Authority

AES MUST NOT obtain new authority domains by chaining capabilities, such as generating or manipulating CI/CD configurations to mint new keys, reusing tokens in unintended contexts, or leveraging access to one system to provision access in another. Any attempt to chain from one authority into another (for example, from pipeline access into IAM modification) MUST be blocked and recorded as a high-severity TI-3 violation in TI-3 environments.

**Rationale**  
Chaining authority is the core mechanism by which attackers pivot from low-privilege footholds to systemic compromise. An AES that can compose multiple capabilities (for example, editing pipelines, then using those pipelines to generate credentials) can bootstrap itself into new authority domains that were never explicitly granted. Prohibiting autonomous chaining ensures that each grant of authority remains isolated and reviewable.

**Implementation Notes**  
- Analyse AES-accessible APIs and workflows for potential chains that could lead to privilege or domain expansion.  
- Explicitly restrict AES from taking actions that create new credentials, modify CI/CD pipelines to alter permissions, or call APIs outside its declared boundary.  
- Implement detection rules that flag patterns indicative of authority chaining (for example, AES editing a pipeline followed by new credentials appearing).  
- Require human approval and separate governance for multi-step workflows that intentionally span authorities, rather than allowing AES to compose them freely.  
- Document and periodically review the set of capabilities available to each AES to ensure no implicit chains have emerged due to system evolution.

**Applies To:** TI-2 AES and SM-AES (mandatory), TI-3 AES and SM-AES (mandatory)

---

#### 3.8.18 (AI-AES-10) ATLAS-AES-POLICY-EVAL — Deterministic Policy Evaluation for Autonomous Actions

All AES actions MUST be evaluated at enforcement boundaries using deterministic policy logic. Probabilistic outcomes, heuristic “confidence scores,” or model-generated justifications alone SHALL NOT be used to authorise execution of high-impact actions. When applicable policies cannot be located, evaluated, or proven to apply unambiguously, AES-initiated execution MUST fail closed and be escalated for human or higher-level review.

**Rationale**  
If AES actions are authorised based on opaque heuristics or model confidence alone, the same inputs can lead to different outcomes and misaligned incentives can push systems toward unsafe behaviour. Deterministic policy evaluation ensures that AES decisions remain within the same verifiable, explainable framework as other critical control-plane decisions, and that gaps in policy coverage are surfaced rather than papered over by the model.

**Implementation Notes**  
- Route AES proposals to existing policy engines (for example, IAM, OPA, custom rules engines) that operate on stable rules and clearly defined inputs.  
- Encode AES-specific constraints and invariants (such as “no privilege escalation,” “no cross-tenant writes”) as explicit policy rules, not as informal guidelines.  
- Log policy evaluation inputs and outputs alongside AES actions, including which rules fired or were considered.  
- Treat missing, conflicting, or ambiguous policy evaluations as errors that cause denial and escalation, not as reasons to defer to AES judgement.  
- Periodically review policy coverage for AES-driven workflows to close gaps and reduce reliance on ad-hoc exception handling.

**Applies To:** TI-2 AES and SM-AES (mandatory), TI-3 AES and SM-AES (mandatory)

---

#### 3.8.C Self-Modifying Autonomous Execution System Controls (ATLAS-SM-AES)

Self-Modifying Autonomous Execution Systems (SM-AES) are systems capable of altering their own execution logic, decision models, capabilities, or policy enforcement mechanisms. SM-AES represent heightened systemic and existential security risk and therefore require the strongest integrity, provenance, constraint, and forensic evidence guarantees defined by ATLAS. SM-AES MUST comply with all controls in 3.8.A and 3.8.B, in addition to the controls in this subsection.

Self-modification MUST NOT be used to expand authority, scope, or capability beyond human-defined boundaries. Any modification that increases scope or authority SHALL reclassify the system as a new identity and MUST require redeployment via external enforcement systems. In-place expansion of authority is prohibited; self-modification MAY only reduce or refine permitted action domains.

---

#### 3.8.19 (AI-SM-AES-01) ATLAS-SM-AES-BOUNDARY-TIGHTEN — Self-Modification Must Reduce Scope

All self-modification events in SM-AES MUST result in a net reduction or refinement of permitted capabilities, system domains, or resource sets. Self-modification MUST NOT be used to add new capabilities, extend to new domains, or expand access to additional resources. Any requested change that would increase authority or broaden scope MUST be rejected at runtime and handled by external governance and deployment processes.

**Rationale**  
Allowing a system that modifies itself to also expand its own authority creates a direct path from bounded automation to unbounded control. Over time, optimisation, error, or adversarial influence can drive the system to grant itself more power, undermining the very boundaries intended to protect the environment. Enforcing “shrink-only” or “tighten-only” self-modification semantics keeps SM-AES aligned with human-defined constraints and prevents authority inflation from happening silently.

**Implementation Notes**  
- Encode allowed modification directions explicitly (for example, “may disable capabilities”, “may remove resources”, “may tighten thresholds”, but “may not add capabilities or resources”).  
- Implement guards that compute the effective scope before and after each self-modification and deny changes that increase scope or authority.  
- Log all denied scope-increasing modification attempts as TI-3 events for investigation.  
- Provide separate, human-governed workflows for adding capabilities or resources; do not route such changes through SM-AES logic.  
- Test SM-AES behaviour under adversarial prompts or inputs to confirm that any attempt to widen authority is blocked by boundary-tightening rules.

**Applies To:** TI-2 SM-AES (mandatory), TI-3 SM-AES (mandatory)

---

#### 3.8.20 (AI-SM-AES-02) ATLAS-SM-AES-NO-EXPANSION — No Runtime Expansion of Authority

SM-AES MUST NOT autonomously expand permissions, identity scopes, routing control, data access, or policy write access under any conditions. Requests to expand authority – whether triggered by internal reasoning, external prompts, or environmental signals – MUST be routed to an external system that enforces redeployment and reclassification as a distinct identity. Expansion of authority SHALL NOT be applied to the active runtime instance.

**Rationale**  
Authority expansion is qualitatively different from refinement and requires independent review and governance. If SM-AES can grant itself new roles, write access to new policies, or broader routing control at runtime, then any failure or exploit of its self-modification logic becomes a full control-plane compromise. Forcing authority expansion to occur out-of-band through redeployment preserves human control over who can do what.

**Implementation Notes**  
- Separate configuration parameters that reduce scope (for example, disabling features) from those that expand it (for example, adding roles), and block the latter in SM-AES self-modification paths.  
- Route all “scope increase” requests to external configuration or deployment pipelines that create a new system identity or version.  
- Treat runtime attempts to call authority-granting APIs from SM-AES logic as boundary violations and log them as TI-3 incidents.  
- Ensure that mechanisms for reclassifying or upgrading SM-AES instances (for example, new versions with more capabilities) involve explicit human approval and independent validation.  
- Document authority expansion flows separately from self-modification flows to avoid accidental conflation in code or configuration.

**Applies To:** TI-2 SM-AES (mandatory), TI-3 SM-AES (mandatory)

---

#### 3.8.21 (AI-SM-AES-03) ATLAS-SM-AES-VERSIONED-EVOLUTION — Versioned Artifact Generation

Each self-modification event in an SM-AES MUST generate a new versioned artifact representing the updated logic, configuration, or model state. The new version MUST be cryptographically signed, uniquely identified (for example, via semantic versioning or monotonic sequence counters), and accompanied by provenance metadata including the prior version hash. These artifacts SHALL be treated as software supply chain outputs subject to ATLAS supply-chain (3.5) and evidence (3.7) controls.

**Rationale**  
Self-modifying systems without explicit versions blur the boundary between “what the system used to be” and “what it has become”, making it impossible to reason about behaviour over time or to roll back safely. Treating each self-modification as a new artifact in a versioned lineage restores normal software governance practices: provenance, review, revocation, and differential analysis.

**Implementation Notes**  
- Package updated models, policies, or code as discrete artifacts with unique version identifiers and signed metadata.  
- Include references to the previous version (hash, identifier) in each new artifact to enable lineage reconstruction.  
- Register new artifacts in the same artifact registries or provenance systems used for non-AI software components.  
- Ensure that deployment systems can select and pin specific SM-AES versions, rather than always upgrading in-place.  
- Integrate SM-AES artifact generation with ATLAS-PROV controls so that self-modification events appear as part of the overall software supply chain.

**Applies To:** TI-2 SM-AES (mandatory), TI-3 SM-AES (mandatory)

---

#### 3.8.22 (AI-SM-AES-04) ATLAS-SM-AES-DIFF-LOGGING — Append-Only State Diffs

In addition to generating full versioned artifacts, SM-AES MUST produce append-only state diffs for each self-modification event. Diff records MUST reference both prior and new digests, capture the exact change applied (for example, parameters changed, rules added/removed, weights updated), and include modification rationale where available. Diff logs MUST be stored as TI-3 evidence with cryptographically valid timestamps and SHALL NOT replace full-version storage; both are required.

**Rationale**  
Full versions alone show that something changed, but not how or why. Fine-grained diffs make it possible to understand the evolution of an SM-AES, detect suspicious changes, and perform targeted rollbacks. When stored in append-only, tamper-evident form, diffs become a forensic record of the system’s “life story” rather than just a series of opaque snapshots.

**Implementation Notes**  
- Compute structured diffs for relevant state types (for example, configuration fields, policy rules, model metadata, model weight checkpoint identifiers).  
- Link diff records to both the old and new version identifiers and digests so investigators can traverse the evolution graph.  
- Include optional rationale fields (for example, “reduced scope due to incident X”, “tightened threshold based on feedback”) to explain why changes occurred.  
- Store diffs in TI-3 evidence pipelines with cryptographic chaining and trusted timestamps (see 3.7.C).  
- Provide tooling to reconstruct any historical version from an initial state plus diffs, verifying consistency against stored full artifacts.

**Applies To:** TI-2 SM-AES (recommended), TI-3 SM-AES (mandatory)

---

#### 3.8.23 (AI-SM-AES-05) ATLAS-SM-AES-SIGNED-EVOLUTION — Cryptographic Attestation of Self-Modification

Each self-modification event in an SM-AES MUST be individually attested using a dedicated evolution key that is cryptographically distinct from runtime execution identities, human operator identities, and control-plane enforcement identities. Evolution signatures MUST bind together the prior version, new version, diff, and provenance metadata, and MUST be verifiable independently of the running system. Key separation MUST allow revocation of modification authority without disabling execution or investigation.

**Rationale**  
If the same keys are used for execution, administration, and self-modification, then compromise of any one role compromises all others and makes it difficult to disentangle responsibility. A dedicated evolution key provides a clear signal that “this change came from the self-modification logic” and allows organisations to revoke evolution rights while keeping existing deployments running for investigation or safe operation.

**Implementation Notes**  
- Issue dedicated cryptographic keys (or key pairs) used solely for signing self-modification events and artifacts.  
- Restrict access to evolution keys to the minimal components required to perform self-modification; do not share them with standard runtime paths.  
- Include evolution signatures in both versioned artifacts and TI-3 diff logs so they can be validated offline.  
- Implement mechanisms to revoke or rotate evolution keys, and treat revoked keys as a reason to block further self-modification until revalidated.  
- Monitor for any use of evolution keys outside self-modification flows as a critical security incident.

**Applies To:** TI-2 SM-AES (recommended), TI-3 SM-AES (mandatory)

---

#### 3.8.24 (AI-SM-AES-06) ATLAS-SM-AES-NO-KEY-GENERATION — No Self-Generated Privilege Keys

SM-AES MUST NOT generate, rotate, or derive cryptographic credentials used to authorise evolution, policy enforcement, or privileged access (including signing keys, authority tokens, or long-lived credentials). Key generation and lifecycle management for such credentials MUST occur in external, human-governed systems (for example, HSMs, dedicated key management systems) operating under independent trust assumptions. SM-AES MAY request key usage within defined policies but SHALL NOT manage the keys themselves.

**Rationale**  
If an SM-AES can generate or manipulate its own keys for evolution or enforcement, it can create untracked keys, clone authority, or bypass revocation. This collapses the separation between the system being governed and the trust roots used to govern it. Externalising key lifecycle management ensures that ultimate control over authority remains with systems and processes explicitly designed for that purpose.

**Implementation Notes**  
- Configure SM-AES to use short-lived, policy-limited credentials obtained from external key management or secret management systems.  
- Prohibit SM-AES from calling key-generation or key-rotation APIs for any credentials that confer evolution or enforcement authority.  
- Treat attempts by SM-AES to store or export private keys as boundary violations and investigate as TI-3 incidents.  
- Record key usage for evolution and enforcement keys in TI-3 telemetry to support forensic analysis.  
- Embed clear constraints in governance documents that SM-AES are consumers, not creators, of trust-enforcing credentials.

**Applies To:** TI-2 SM-AES (mandatory), TI-3 SM-AES (mandatory)

---

#### 3.8.25 (AI-SM-AES-07) ATLAS-SM-AES-TOOLCHAIN-ISOLATION — Isolation from Trust-Enforcing Toolchains

SM-AES MUST NOT modify, replace, or disable tooling used to enforce boundaries or validate authority, including policy engines, verification services, signing services, identity providers, timestamp authorities, and evidence stores. These trust-enforcing toolchains MUST be isolated in separate trust domains and protected from modification by SM-AES logic, even when SM-AES proposals are considered.

**Rationale**  
The greatest risk from self-modifying systems is not only that they change their own behaviour, but that they tamper with the very mechanisms that constrain them. If SM-AES can adjust policy engines, identity systems, or audit ledgers, they can gradually dismantle their own guardrails while appearing compliant. Isolation of trust-enforcing toolchains ensures that checks and balances remain robust even if SM-AES behaviour is compromised.

**Implementation Notes**  
- Place policy engines, signing services, identity providers, and audit ledgers in separate administrative and technical domains from SM-AES runtimes.  
- Prohibit SM-AES identities from holding any roles that permit configuration or code changes to enforcement components.  
- Validate that configuration changes for trust-enforcing toolchains can only be made through human-governed workflows, not by SM-AES proposals.  
- Monitor for any attempted calls from SM-AES to management interfaces of enforcement systems and treat them as high-severity events.  
- Periodically review infrastructure topology to ensure “toolchain creep” has not brought enforcement components into the same trust zone as SM-AES.

**Applies To:** TI-2 SM-AES (mandatory), TI-3 SM-AES (mandatory)

---

#### 3.8.26 (AI-SM-AES-08) ATLAS-SM-AES-ROLLBACK — Reversible Evolution

All self-modifications in SM-AES MUST be fully reversible to prior versioned artifacts. Rollback procedures MUST be deterministic, cryptographically verifiable, and executable without manual reconstruction of state. If rollback fails or cannot be guaranteed to restore a safe prior state, the SM-AES MUST enter a constrained safe mode with reduced or suspended authority until humans can intervene.

**Rationale**  
Self-modification can introduce subtle errors or dangerous behaviours that only become apparent later. Without assured rollback, organisations may be forced to choose between running an unsafe system or shutting down critical capabilities. Enforced reversibility lets SM-AES be corrected or rolled back quickly, limiting the blast radius of harmful evolutions and preserving evidentiary trails of what changed.

**Implementation Notes**  
- Use the versioned artifacts and diffs from 3.8.21 and 3.8.22 as the basis for automated rollback computations.  
- Implement a verified rollback path that can restore any prior version from stored artifacts, checking digests and signatures along the way.  
- Define and test “safe mode” configurations that drastically restrict SM-AES authority while investigation or repair is underway.  
- Log rollback operations as TI-3 events, including initiator, target version, and verification results.  
- Periodically exercise rollback procedures in controlled environments to ensure they remain functional as systems evolve.

**Applies To:** TI-2 SM-AES (mandatory), TI-3 SM-AES (mandatory)

---

#### 3.8.27 (AI-SM-AES-09) ATLAS-SM-AES-REDEPLOYMENT-REQUIRED — Redeployment Required for Boundary Expansion

Any increase in capability, scope, data access, routing control, or authority for an SM-AES SHALL require creation of a new system identity, external validation and signing of the new configuration or model, explicit human authorisation, and redeployment via standard enforcement pipelines. Boundary expansion SHALL NOT occur on a running instance through in-place self-modification.

**Rationale**  
Boundary expansion is a governance decision, not an optimisation choice. Requiring redeployment for expansion ensures that such changes traverse the same review, validation, and approval processes as other high-risk software updates. It also preserves clear lineage between “old” and “new” systems and allows the previous, narrower system to remain available as a fallback if needed.

**Implementation Notes**  
- Treat boundary expansion as a software release process, involving design review, risk assessment, policy updates, and deployment of a new SM-AES identity.  
- Ensure that deployment tools do not support “hot” authority expansion of existing SM-AES instances; they should only deploy new instances with new identities.  
- Retain older, narrower versions as separately identifiable artifacts that can be rolled back to if the expanded version is found unsafe.  
- Document boundary changes and associated approvals in TI-3 evidence stores, linked to the corresponding SM-AES versions.  
- Use configuration and identity management systems that make it technically difficult to modify authority in place rather than via redeployment.

**Applies To:** TI-2 SM-AES (mandatory), TI-3 SM-AES (mandatory)

---

#### 3.8.28 (AI-SM-AES-10) ATLAS-SM-AES-PROVENANCE — Full Provenance for Learning and Retraining

Model weight updates, fine-tuning, retraining, or toolchain changes for SM-AES MUST be accompanied by full provenance records that capture dataset sources, cryptographic digests of input data, model lineage and inheritance graphs, and trust levels for training and evaluation data. Changes to training inputs and learning processes SHALL be treated as self-modification events and governed under the same versioning, diff logging, and evidence requirements as other SM-AES changes.

**Rationale**  
For SM-AES, “learning” is a form of code modification with direct impact on behaviour and risk. If retraining data, fine-tuning steps, or evaluation procedures are opaque, attackers can poison models or introduce harmful behaviours that are difficult to trace back. Full provenance for learning ensures that defenders can understand how models evolved, assess the trustworthiness of data sources, and roll back to safer states if required.

**Implementation Notes**  
- Record dataset identifiers, sources (including third parties), collection dates, and transformation steps for training and fine-tuning pipelines.  
- Compute and store cryptographic digests for datasets and critical intermediate artifacts to detect tampering or silent data drift.  
- Maintain lineage graphs showing which models or versions were derived from which parent models and datasets.  
- Classify training and evaluation datasets by trust level (for example, “internally curated”, “partner-provided”, “public scraped”) and factor this into risk assessments.  
- Integrate learning and retraining provenance with the general SM-AES versioning and evidence pipelines so that model evolution is visible alongside other self-modifications.

**Applies To:** TI-2 SM-AES (mandatory), TI-3 SM-AES (mandatory)

---
#### 3.8.D Cross-Domain and Control-Plane Interaction Controls (ATLAS-XDOM)

Cross-domain operations represent the highest-risk class of autonomous and AI-influenced behaviour because they can bypass enforcement boundaries, violate trust assumptions, and propagate systemic compromise across environments. These controls govern identity transitions, routing changes, resource access across trust boundaries, and inter-domain execution authority. All systems in this subsection MUST comply with 3.8.A baseline AI controls and 3.8.B / 3.8.C controls as applicable. Cross-domain interactions SHALL fail closed; logging and observability SHALL NOT be treated as substitutes for enforcement.

---

#### 3.8.29 (AI-XDOM-01) ATLAS-XDOM-NO-IDP — AI Shall Not Serve as Identity Provider or Broker

AI systems and agents MUST NOT act as identity providers, identity brokers, or trust federation anchors. They MUST NOT issue identities, sign credentials, mint tokens, perform token exchanges, or mediate trust federation between independently governed systems or domains. Identity and credential issuance MUST originate from external, human-governed systems operating under independent trust roots that are not subject to AI control.

**Rationale**  
Allowing AI systems to mint or transform credentials collapses the separation between untrusted suggestion and trusted authority. A compromised or misaligned AI acting as an identity provider can silently grant arbitrary access, forge delegation chains, or weaken federation guarantees. Keeping identity under independent, non-AI trust roots preserves the integrity of authentication and authorisation across domains.

**Implementation Notes**  
- Configure AI runtimes and agents without access to identity provider signing keys, token issuance APIs, or certificate authorities.  
- Treat any attempt by AI processes to call token-minting, credential-issuing, or federation APIs as a boundary violation and log it as a TI-3 event.  
- Restrict AI usage to consuming identity attributes (for example, for recommendation or analysis) rather than creating or transforming identities.  
- Ensure that identity proofs presented to AI are redacted or scoped so that leakage cannot be used to impersonate principals elsewhere.  
- Document clearly that “AI-assisted access decisions” are advisory inputs into independent policy engines, not sources of identity or tokens.

**Applies To:** TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.8.30 (AI-XDOM-02) ATLAS-XDOM-BOUNDARY-ENFORCE — Boundary Enforcement on Cross-Domain Actions

Any AI-influenced action that affects a domain other than the system’s declared execution domain MUST be explicitly evaluated against cross-domain boundary policies before execution. Where boundary definitions do not explicitly permit such cross-domain actions, the action MUST be rejected and recorded as a boundary violation. Boundary checks MUST occur prior to execution, not only as post-event detection or anomaly analysis.

**Rationale**  
Without explicit cross-domain boundary enforcement, AI systems can inadvertently or maliciously operate beyond their intended scope by invoking APIs, resources, or trust zones they were never designed to touch. Relying only on detection after the fact leaves defenders investigating damage instead of preventing it. Pre-execution enforcement ensures that domain boundaries remain hard constraints, not soft guidelines.

**Implementation Notes**  
- Define explicit domain boundaries (for example, tenant, region, environment, trust zone) and encode them in policy for AI-originated actions.  
- Implement enforcement points (for example, API gateways, sidecars, policy engines) that evaluate domain of the action against the actor’s declared execution domain.  
- Deny actions that target resources or services outside the permitted domains, and log them with full context for investigation.  
- Use separate credentials and network paths per domain so that technical routing itself reinforces boundary policies.  
- Periodically test cross-domain blocking by simulating attempts from AI identities to access disallowed domains.

**Applies To:** TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.8.31 (AI-XDOM-03) ATLAS-XDOM-TI3 — Cross-Domain Events Recorded as TI-3 Evidence

All AI-influenced cross-domain interactions affecting access, routing, identity, configuration, policy, or data MUST be recorded as TI-3 forensic evidence. Records MUST include at least: source and target identity, originating and receiving domains, boundary evaluation results, policy references, prior and resulting state digests where applicable, and cryptographically valid timestamps. System clocks alone SHALL NOT satisfy time requirements for cross-domain events in TI-3 environments.

**Rationale**  
Cross-domain operations often sit at the heart of major incidents, regulatory breaches, and dispute scenarios. If such operations are only captured in low-integrity logs, organisations lose the ability to reconstruct what happened, prove adherence to policy, or challenge malicious behaviour. Treating cross-domain events as TI-3 evidence ensures they remain tamper-evident, time-bound, and legally defensible.

**Implementation Notes**  
- Route cross-domain events into the same append-only, chained evidence stores used for other TI-3 logs (see 3.7.C).  
- Capture structured fields for domain identifiers, trust zones, and resource scopes alongside identities and actions.  
- Use trusted timestamp authorities or hardware-backed time sources to bind timestamps, and chain events cryptographically to preserve order.  
- Provide tooling to query, export, and verify cross-domain event sequences for audit and incident response.  
- Mark missing or incomplete cross-domain evidence as a compliance defect and investigate root causes.

**Applies To:** TI-2 (recommended), TI-3 (mandatory)

---

#### 3.8.32 (AI-XDOM-04) ATLAS-XDOM-TRACE — Full Cross-Domain Traceability

Cross-domain interactions involving AI systems MUST emit traceable event graphs that link the originating principal, intermediate transformations (including delegation and impersonation), final executing principal, and downstream effects. Identity transformations, token exchanges, and delegation steps MUST be explicitly recorded, not inferred or reconstructed from partial logs.

**Rationale**  
Attackers and misbehaving systems exploit ambiguities in identity and routing to hide lateral movement. Without explicit traceability of identity transitions, it is difficult to determine who actually performed an action or which domain authorised it. Cross-domain traceability clarifies chains of responsibility and enables defenders to pinpoint where trust was extended or misused.

**Implementation Notes**  
- Use correlation IDs and trace IDs that persist across domain boundaries and are included in logs in each participating system.  
- Record each identity transformation step (for example, user → service, token exchange, delegation) as a distinct event with clear source and target.  
- Integrate identity graphs with distributed tracing systems so that logical call chains map cleanly onto security events.  
- Expose cross-domain trace graphs to incident responders and auditors, not just performance engineers.  
- Treat unexplained gaps in identity or trace linkage as indicators of potential compromise or logging failure.

**Applies To:** TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.8.33 (AI-XDOM-05) ATLAS-XDOM-NO-AUTO-ROUTING — No Autonomous Routing Authorization

AI systems and agents MUST NOT autonomously authorise or propagate routing changes that affect traffic paths, service discovery, cross-zone connectivity, or failover behaviour, unless explicitly and narrowly permitted in domain and boundary definitions. Routing policy changes MUST be enforced through external control-plane systems with deterministic policy evaluation and, where applicable, human or multi-party approval. Requests from AI systems to modify routing MUST fail closed by default.

**Rationale**  
Routing is a control-plane function, not a mere network convenience. Adversaries or misaligned objectives can exploit routing changes to steer traffic through inspection gaps, exfiltration paths, or compromised intermediaries. Allowing AI to rewrite routing policies autonomously effectively delegates critical perimeter control to a non-deterministic component.

**Implementation Notes**  
- Configure service meshes, load balancers, DNS systems, and SD-WAN controllers to reject routing changes initiated directly by AI identities unless explicitly allowed.  
- Treat all AI-originated routing proposals as suggestions that must be validated and applied by independent control-plane components.  
- Define strict policies for the limited cases where AI may adjust routing (for example, traffic shifting within a single trust zone during canary releases).  
- Log all AI-related routing proposals and decisions as at least TI-2 events, and as TI-3 events when they cross domains.  
- Regularly review routing changes to confirm that no autonomous paths have emerged outside approved workflows.

**Applies To:** TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.8.34 (AI-XDOM-06) ATLAS-XDOM-DUAL-SIGN — Dual-Root Authority for Cross-Domain Mutations

Any AI-influenced cross-domain mutation affecting identity, routing, privileges, or data MUST require approval or signatures from both the originating trust root and the receiving trust root. No single trust domain – including one under AI management – may unilaterally authorise a mutation that materially affects another domain. Dual-root approval MUST be verifiable in TI-3 evidence, including which identities and policies authorised the change.

**Rationale**  
Cross-domain mutations inherently affect multiple parties. If only one side authorises a change, errors or compromises in that domain can impose risk on others without their consent. Dual-root authority ensures that both sides explicitly agree to the mutation and that no domain can silently extend AI-originated decisions into another domain’s trust boundary.

**Implementation Notes**  
- Implement approval workflows that require independent authorisation from representatives (human or governed systems) of each affected domain.  
- Use separate key pairs or signing authorities for each domain, and require both signatures on high-impact cross-domain changes.  
- Record dual-signature approvals and their associated policies as TI-3 evidence, linked to the specific mutation.  
- Configure control-plane APIs to enforce dual-root requirements for cross-domain operations and reject requests that lack complete approvals.  
- Periodically test dual-signature enforcement paths to ensure they cannot be bypassed due to misconfiguration or privilege overlap.

**Applies To:** TI-2 (recommended), TI-3 (mandatory)

---

#### 3.8.35 (AI-XDOM-07) ATLAS-XDOM-NO-LATERAL — No Lateral Identity Chaining

AI systems MUST NOT obtain access to new trust domains through lateral identity chaining, such as reusing tokens in unintended domains, leveraging CI/CD access to escalate privileges, extracting keys to assume new roles, or pivoting via compromised accounts. Identity reuse across domains MUST be explicitly denied unless covered by formal federation and boundary policies, and all attempted lateral chains MUST be detected and treated as security events.

**Rationale**  
Lateral movement is a common progression path in modern attacks. AI systems with broad visibility and capability can, intentionally or accidentally, discover and exploit chains of identity and access that were not designed as explicit federations. Prohibiting lateral identity chaining ensures that each grant of access remains limited to its intended domain, even in the presence of AI-driven exploration.

**Implementation Notes**  
- Scope tokens, keys, and credentials tightly to specific audiences, domains, and resources; prevent their reuse elsewhere.  
- Monitor authentication and authorisation logs for tokens or identities appearing in unexpected domains or services, especially when AI is involved.  
- Prohibit AI identities from accessing secret stores or configuration repositories that contain credentials for other domains.  
- Detect patterns such as AI editing CI/CD pipelines to generate credentials, then using those credentials for new access, and treat them as high-severity events.  
- Require explicit, documented federation agreements for any intentional cross-domain identity relationships and enforce them at gateways.

**Applies To:** TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.8.36 (AI-XDOM-08) ATLAS-XDOM-ISOLATION — Strict Domain Isolation for Execution Identity

Execution identities used by AI systems MUST be constrained to a single primary domain or narrowly defined multi-domain scope, with independent identities for each domain where necessary. Cross-domain execution MUST NOT occur via identity reuse or impersonation. Where a system must operate in multiple domains, it MUST do so using separate, isolated identities, each governed by distinct boundary definitions and policies.

**Rationale**  
A single identity operating across multiple domains creates a latent super-user that can be abused by AI systems or attackers to bridge trust boundaries. Without isolation, it becomes difficult to determine which actions were justified in which domain, and revocation decisions become coarse. Domain-specific identities maintain clear separation of powers and make blast radius easier to contain.

**Implementation Notes**  
- Issue distinct credentials for each domain in which an AI system operates, and configure them with domain-specific scopes and policies.  
- Ensure that AI runtimes cannot impersonate identities from other domains, even when running on shared infrastructure.  
- Configure logs and evidence records to clearly indicate which domain-specific identity performed each action.  
- Use network segmentation and per-domain gateways to reinforce identity isolation at the transport and API layers.  
- Treat any appearance of a domain-specific identity outside its assigned domain as a suspected compromise.

**Applies To:** TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.8.37 (AI-XDOM-09) ATLAS-XDOM-REPLAY-BLOCK — Cross-Domain Replay Prevention

Cross-domain requests and events involving AI systems MUST NOT be considered valid outside their original context. Replay protection mechanisms MUST ensure that tokens, signed requests, and event bundles cannot be reused in different times, domains, or audiences. Cross-domain replay attempts MUST be automatically rejected and recorded as security events, not merely logged passively.

**Rationale**  
Replay attacks allow adversaries to turn legitimate cross-domain actions into repeated or redirected compromises. AI systems that see or handle cross-domain artefacts may leak or reissue them unintentionally. Without strong replay protection, the same authorised action can be abused multiple times or in multiple places, undermining the value of prior approvals and boundary checks.

**Implementation Notes**  
- Bind tokens and signed requests to specific audiences, domains, and time windows, and verify these bindings at enforcement points.  
- Use nonce, sequence numbers, or one-time tokens for high-impact cross-domain operations.  
- Store identifiers of consumed tokens or signed requests so that duplicates are detected and rejected.  
- Integrate replay detection into TI-2/TI-3 telemetry and alerting pipelines to enable rapid investigation.  
- Design AI systems so they never store or regenerate reusable cross-domain request payloads without fresh authorisation.

**Applies To:** TI-2 (mandatory), TI-3 (mandatory)

---

#### 3.8.38 (AI-XDOM-10) ATLAS-XDOM-NO-SECRET-HANDOFF — No Autonomous Credential Transport

AI systems and agents MUST NOT receive, store, transport, transform, forward, or proxy private keys, long-lived tokens, or other credentials used in trust enforcement across domains. Credential handling, including distribution and rotation, MUST occur exclusively through external secret managers or key management systems under independent governance. Any attempt by AI processes to act as a conduit for trust-enforcing credentials MUST be blocked and treated as a boundary violation.

**Rationale**  
Once AI systems begin carrying or reshaping credentials, they become high-value attack surfaces and covert channels for exfiltration and lateral movement. AI workflows that “helpfully” move secrets between systems can accidentally or deliberately bypass established secret management controls. Prohibiting AI from handling enforcement credentials preserves the integrity of dedicated secret management infrastructures.

**Implementation Notes**  
- Deny AI runtimes access to secret management APIs except for tightly scoped, read-only operations where absolutely necessary.  
- Redact or tokenise credentials before exposing logs, configs, or artefacts to AI models, and treat any exposure of raw secrets as an incident.  
- Use out-of-band secret injection mechanisms (for example, sidecars, environment injection) that do not involve AI components.  
- Monitor for patterns where AI identities read from or write to locations known to contain credentials, and alert on such activity.  
- Document clearly in architecture and governance artifacts that AI systems are explicitly out of scope for credential distribution responsibilities.

**Applies To:** TI-2 (mandatory), TI-3 (mandatory)

---
### 3.9 Compiler, Build, and Artifact Integrity Controls (ATLAS-BUILD)

Compiler, build, and packaging stages are systemic control surfaces that directly determine what code enters execution. If build pipelines are non-deterministic, network-dependent, or loosely governed, downstream runtime controls cannot guarantee artifact integrity or provenance. ATLAS-BUILD controls require deterministic, hermetic, cryptographically verifiable builds that close common supply-chain attack paths and eliminate ambiguity in artifact origin, lineage, and behaviour.

These controls apply to compilers, interpreters, linkers, packagers, container builders, and any system that transforms source or configuration into executable or deployable artifacts, including intermediate artifacts used by further build stages.

---

#### 3.9.1 (BUILD-01) ATLAS-BUILD-DETERMINISTIC-OUTPUT — Deterministic Build Outputs

Governed build processes MUST be deterministic: given identical source code, configuration, dependency versions and digests, compiler and toolchain versions, and environment declarations, the resulting artifacts MUST produce identical cryptographic digests. Sources of non-determinism (including timestamps, random seeds, file ordering, and concurrency race conditions) MUST be controlled, eliminated, or explicitly normalised. Non-deterministic builds in TI-2 and TI-3 contexts SHALL be treated as supply-chain defects and MUST NOT be promoted to production.

**Rationale**  
Without determinism, defenders cannot reliably verify that a deployed artifact corresponds to a reviewed source, nor can they distinguish tampering from incidental variation. Non-deterministic builds undermine reproducibility, complicate incident response, and create plausible deniability for malicious changes introduced in opaque pipelines. Deterministic outputs allow independent rebuilds, third-party verification, and precise correlation between source, artifact, and behaviour.

**Implementation Notes**  
- Configure compilers and packagers to strip or normalise timestamps, build paths, and other variable metadata from outputs.  
- Use fixed random seeds, deterministic file ordering, and controlled parallelism for build steps that would otherwise introduce non-determinism.  
- Maintain a canonical “build recipe” that fully specifies inputs, tool versions, and environment parameters for governed builds.  
- Implement automated comparison of artifact digests between independent rebuilds; fail builds that cannot reproduce identical outputs under controlled conditions.  
- Treat persistent non-determinism as a security issue, not merely an engineering inconvenience, and track remediation as part of supply-chain hardening.

**Applies To:**  
- TI-1: recommended for critical components  
- TI-2: mandatory  
- TI-3: mandatory

---

#### 3.9.2 (BUILD-02) ATLAS-BUILD-HERMETIC-ENV — Hermetic Build Environments

Governed builds MUST execute in hermetic environments that do not depend on undeclared host OS libraries, environment variables, machine-local state, user home directories, or implicit caches. All inputs to the build, including toolchains, dependencies, and configuration, MUST be explicitly declared, hash-pinned, and isolated from ambient system state. Hermeticity MUST be enforceable (for example, via sandboxing or containerisation) and verifiable via inspection and attestation.

**Rationale**  
Builds that implicitly depend on host state, user configuration, or ambient network-accessible resources create hidden channels for tampering and non-determinism. Attackers can modify shared libraries, PATH entries, or local caches to inject malicious behaviour into artifacts without touching source repositories. Hermetic builds constrain the dependency surface to the declared inputs and make deviations observable.

**Implementation Notes**  
- Run builds inside containers, VMs, or sandboxes that mount only explicitly declared dependencies and tools.  
- Block access to user home directories, general `/usr/local` trees, or arbitrary environment variables unless they are part of the declared build contract.  
- Use explicit allowlists for environment variables allowed into the build, and default to denying undeclared variables.  
- Validate hermeticity by running the same build in clean environments and confirming that undeclared host changes do not affect outputs.  
- Treat any discovered dependency on ambient host state as a defect in the build specification and remediate before production use.

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory

---

#### 3.9.3 (BUILD-03) ATLAS-BUILD-NO-NETWORK — No Network Resolution During Build

Governed build processes MUST NOT perform outbound network calls to resolve dependencies, tools, configuration, or build scripts at build time. All dependencies and tools MUST be pre-fetched, hash-pinned, and stored in controlled repositories with provenance before the build starts. Builds that require live network resolution or ad-hoc downloads SHALL fail closed in TI-2 and TI-3 environments.

**Rationale**  
Network-dependent builds introduce non-determinism and expand the attack surface to include every external registry, mirror, and service consulted during the build. Attackers can poison dependencies, manipulate DNS, or compromise mirrors to influence artifacts at build time. Eliminating live network resolution ensures that build inputs are stable, reviewable, and governed before execution.

**Implementation Notes**  
- Use internal artifact repositories and mirrors that synchronise upstream content under controlled, auditable processes.  
- Enforce build-time policies that deny outbound network access for governed build jobs, except where explicitly justified and logged.  
- Pre-resolve and cache all dependencies and tools, storing them with cryptographic digests and provenance metadata in internal repositories.  
- Validate that build scripts do not invoke `curl`, `wget`, or similar tools against arbitrary endpoints; treat such patterns as anti-patterns in governed builds.  
- For exceptional cases requiring external data, package that data as a declared, versioned input artifact rather than fetching it inline during build.

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory

---

#### 3.9.4 (BUILD-04) ATLAS-BUILD-COMPILER-ATTEST — Compiler and Toolchain Attestation

Compilers, interpreters, linkers, packagers, and other toolchain components used in governed builds MUST support integrity attestation, including version identifiers, cryptographic digests, signatures, and provenance of origin. Build systems MUST verify that the compiler and toolchain in use match expected, attested identities before accepting build outputs. If the compiler or toolchain cannot be verified, the build MUST be rejected for TI-2 and TI-3 artifacts.

**Rationale**  
Compromised or replaced compilers and toolchains can inject malicious behaviour into binaries even when source code and dependencies appear clean, as highlighted by “trusting trust” class attacks. Without attestation, defenders cannot be sure which tool actually produced a given artifact or whether it matches the reviewed version. Toolchain attestation anchors the trust chain for build outputs to verifiable, auditable components.

**Implementation Notes**  
- Maintain an inventory of approved toolchain versions, including digests and signatures from trusted sources or internal build authorities.  
- Configure build environments to verify toolchain binaries or containers against this inventory at startup or before each build.  
- Use signed toolchain images or packages distributed from controlled internal registries.  
- Log the exact toolchain identity (version, digest, signature verification result) alongside each build as part of lineage records.  
- Periodically re-verify toolchains and rotate them under change control rather than allowing quiet drift.

**Applies To:**  
- TI-1: recommended for critical pipelines  
- TI-2: mandatory  
- TI-3: mandatory

---

#### 3.9.5 (BUILD-05) ATLAS-BUILD-SOURCE-DEPS-PIN — Source and Dependency Hash-Pinning

All source inputs and dependencies – including direct and transitive dependencies, build scripts, and configuration templates – used in governed builds MUST be pinned to exact versions and associated with cryptographic digests. References MUST use immutable identifiers (such as commit hashes, content hashes, or immutable tags), not floating versions, mutable tags, or “latest” selectors. Unpinned or implicitly mutable dependencies SHALL NOT be used in TI-2 or TI-3 builds.

**Rationale**  
Floating versions and mutable tags allow dependencies to change underneath a fixed build recipe, breaking reproducibility and creating a path for supply-chain poisoning. When dependency resolution can silently drift, defenders cannot establish which code actually entered the artifact. Hash-pinning and immutable references ensure that the full dependency set is stable, reviewable, and traceable.

**Implementation Notes**  
- Use lock files, dependency manifests, or similar mechanisms that record exact versions and digests for all dependencies.  
- Configure package managers to fail on unpinned or wildcard version specifications in governed build configurations.  
- Store source and dependency artifacts in internal repositories keyed by content hash, not only by human-readable version numbers.  
- Integrate hash verification into the build, failing early if any dependency digest does not match the expected value.  
- Treat changes to dependency lock sets as new inputs that require a new artifact identity and lineage entry.

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory

---

#### 3.9.6 (BUILD-06) ATLAS-BUILD-IMMUTABLE-INPUTS — Immutable Build Inputs

Inputs to a governed build – including source repositories, configuration files, schemas, dependency manifests, and toolchain descriptors – MUST be treated as immutable once used for a specific build identity. Updating any input MUST create a new version with updated digests and an explicit lineage link to prior versions. In-place modification of previously consumed build inputs is prohibited for TI-2 and TI-3 contexts.

**Rationale**  
If build inputs can be modified in place after artifacts have been produced, it becomes impossible to reconstruct which inputs correspond to which outputs or to prove that a given artifact reflects a reviewed configuration. Attackers can retroactively alter inputs to align with compromised artifacts, obscuring tampering. Immutable inputs and explicit versioning preserve a stable historical record and support forensic reconstruction.

**Implementation Notes**  
- Use version control systems, immutable object stores, or append-only configuration registries for all governed build inputs.  
- Tag or snapshot repositories at specific commits for each build, and record these identifiers in artifact lineage metadata.  
- Prohibit force-pushes, history rewrites, or mutable configuration paths for inputs used in TI-2/TI-3 builds.  
- Implement governance that requires new versions or branches for meaningful configuration or schema changes rather than editing values in place.  
- Align CI/CD systems to pull from immutable references (for example, commit hashes or signed tags) rather than mutable branches when producing governed artifacts.

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory

---

#### 3.9.7 (BUILD-07) ATLAS-BUILD-IDENTITY-SEPARATION — Separation of Build and Runtime Identities

Identities used to operate build pipelines, access build infrastructure, and sign build artifacts MUST be cryptographically distinct from runtime execution identities, control-plane identities, and human operator identities used in production environments. Build systems SHALL NOT mint, assume, or reuse runtime execution identities, nor shall runtime systems reuse build identities for operational actions. Cross-use of identities across build and runtime domains is prohibited in TI-2 and TI-3 systems.

**Rationale**  
Collapsing build, runtime, and operator identities allows compromise in one domain to cascade into others and obscures responsibility for actions. If build systems can impersonate runtime services or vice versa, attackers can exploit CI/CD footholds to gain operational control, or hide runtime tampering behind build signatures. Separating identities constrains blast radius and clarifies attribution.

**Implementation Notes**  
- Issue separate PKI certificates, tokens, or keys for build infrastructure, runtime services, control-plane components, and human operators.  
- Configure IAM so that build identities lack permissions to invoke production control-plane APIs beyond what is strictly necessary for artifact publication.  
- Use distinct key material for artifact signing and runtime authentication; do not reuse the same keys or certificates.  
- Record identity roles in logs (for example, `role=build`, `role=runtime`) to support clear analysis of which domain performed each action.  
- Regularly review IAM policies for unintended overlaps between build and runtime privileges.

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory

---

#### 3.9.8 (BUILD-08) ATLAS-BUILD-SBOM — Hash-Bound Software Bill of Materials

Each governed artifact MUST be accompanied by a Software Bill of Materials (SBOM) that enumerates all direct and transitive dependencies, their versions, cryptographic digests, and provenance sources. The SBOM MUST be cryptographically bound to the artifact – via embedded digest, external signed manifest, or equivalent mechanism – such that tampering with either the SBOM or the artifact is detectable. Absence of a valid SBOM for TI-2 and TI-3 artifacts MUST block deployment.

**Rationale**  
Without a trustworthy SBOM, organisations cannot rapidly determine exposure to newly disclosed vulnerabilities, supply-chain compromises, or licensing issues. Unbound or mutable SBOMs can be quietly altered to hide problematic dependencies. Binding SBOMs to artifacts ensures that dependency information is consistent with the deployed code and that changes are visible and reviewable.

**Implementation Notes**  
- Generate SBOMs as part of the governed build process using standard formats and include dependency digests and provenance.  
- Sign SBOMs and either embed their digests in artifact metadata or sign a manifest that covers both artifact and SBOM digests.  
- Store SBOMs in accessible repositories alongside artifacts, and reference them in deployment metadata.  
- Integrate SBOM checks into deployment gates, failing deployments where SBOMs are missing, invalid, or out-of-sync with artifact digests.  
- Use SBOM data to drive automated vulnerability, license, and policy checks as part of ongoing risk management.

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory

---

#### 3.9.9 (BUILD-09) ATLAS-BUILD-CROSS-ENV-REPRO — Cross-Environment Reproducibility

Governed builds MUST be reproducible across different machines, regions, and cloud providers, provided the declared environment specification is satisfied. Build outputs MUST NOT vary materially based on underlying hardware, geography, or cloud-specific context. Where hardware or platform differences can affect binary layout or performance characteristics, verification procedures MUST exist to prove functional equivalence and detect unexpected variations.

**Rationale**  
If build outputs depend on where or on which hardware they are built, attackers can target specific build locations or platforms to insert malicious changes that evade detection in other environments. Cross-environment reproducibility limits geographic and infrastructural attack surfaces and supports independent rebuilds by external parties or regulators.

**Implementation Notes**  
- Specify build environments in portable, declarative forms (for example, container images, VM images, or configuration descriptors) that can be instantiated consistently across providers.  
- Run periodic cross-environment rebuilds and compare artifact digests or other verification outputs to detect discrepancies.  
- Where bit-for-bit equivalence is not feasible (for example, due to platform-specific code generation), define and execute equivalence tests (for example, symbol maps, functional test suites, or formal verification artefacts).  
- Ensure that region-specific or provider-specific metadata is not embedded into artifacts unless explicitly required and accounted for.  
- Treat systematic differences in cross-environment rebuilds as potential indicators of toolchain or infrastructure compromise.

**Applies To:**  
- TI-1: recommended for widely distributed software  
- TI-2: mandatory where multiple build locations are used  
- TI-3: mandatory

---

#### 3.9.10 (BUILD-10) ATLAS-BUILD-NO-VERSION-SLIDE — No Transitive Version Sliding

Dependency resolution for governed builds MUST NOT “slide” to newer or different versions (including semver-compatible updates) without explicit human approval and generation of a new artifact identity. Semver ranges, loose constraints, or “latest” selectors MUST be resolved once into a fully pinned, hash-verified lock set, which then becomes part of the build inputs. Regenerating the lock set SHALL create a new lineage entry and MUST be subject to review and attestation.

**Rationale**  
Automatic version “sliding” hides significant changes behind superficially minor version bumps and can introduce vulnerable or malicious dependencies without explicit decision. Attackers can exploit transitive dependencies or newly published minor versions to introduce backdoors. Requiring explicit lock set regeneration and artifact re-identification ensures that dependency changes are treated as deliberate, reviewable events.

**Implementation Notes**  
- Configure dependency managers to resolve ranges into specific versions and to generate lock files that are committed and reviewed.  
- Treat any change to a lock file as a configuration change requiring code review, CI validation, and updated artifact versions.  
- Disable “auto-upgrade” features for governed builds; updates should be performed in controlled branches or pipelines.  
- Integrate vulnerability and license scanning into the process of regenerating lock sets before approving new dependencies.  
- Maintain lineage records that link each artifact to the specific lock set used, enabling precise reconstruction of dependency states over time.

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory


---

#### 3.9.11 (BUILD-11) ATLAS-BUILD-DUAL-SIGN-CROSS-DOMAIN — Dual-Signature for Cross-Domain Artifacts

Artifacts intended for execution across separate trust domains (such as between organisations, tenants, or regulatory jurisdictions) MUST be signed by both the producing domain’s build authority and the receiving domain’s intake or validation authority before they are allowed to execute. No single trust domain MAY unilaterally authorise cross-domain artifact execution in TI-2 or TI-3 environments. Removal or bypass of either signature MUST invalidate the artifact for cross-domain use.

**Rationale**  
Cross-domain artifacts impact multiple independently governed parties. If only the producing side attests an artifact, the receiving side inherits risk without explicit consent or validation. Conversely, if receivers accept unsigned or single-signed artifacts, a compromised producer can propagate malicious payloads broadly. Dual-signature requirements ensure that both domains consciously accept responsibility for the artifact and that neither can silently impose risk on the other.

**Implementation Notes**  
- Establish separate signing keys and policies for “producer build authority” and “receiver intake authority,” each managed under independent governance.  
- Require receiving domains to perform their own validation (including SBOM, policy, and regulatory checks) before applying their intake signature.  
- Configure deployment systems to verify both signatures and reject artifacts where either signature is missing, invalid, or revoked.  
- Record dual-signature metadata (identities, timestamps, policy references) as part of TI-3 evidence for cross-domain deployments.  
- Treat attempts to deploy cross-domain artifacts with only a single domain signature as policy violations and log them as TI-2 or TI-3 incidents depending on criticality.

**Applies To:**  
- TI-1: recommended for shared components  
- TI-2: mandatory for cross-domain use  
- TI-3: mandatory

---

#### 3.9.12 (BUILD-12) ATLAS-BUILD-ISOLATION-FROM-PROD — Build Isolation from Production Secrets and Data

Build systems and pipelines MUST be strictly isolated from production secrets, production data, and runtime trust anchors. Governed build environments SHALL NOT have access to production databases, production message buses, production key stores, or runtime signing keys. Production data MUST NOT be used directly as build input; any test data derived from production MUST be explicitly transformed, de-identified where required, and governed as a separate artifact with its own provenance.

**Rationale**  
If build systems can read or influence production secrets and data, compromise of CI/CD infrastructure becomes an immediate path to full environment compromise, data breaches, and undetectable backdoors. Similarly, using live production data in builds creates unnecessary exposure and complicates legal and regulatory obligations. Isolating build from production keeps CI/CD in a constrained domain and ensures that build compromise does not automatically equate to total operational compromise.

**Implementation Notes**  
- Enforce network and IAM segmentation so build environments cannot reach production databases, queues, or internal-only services except via strictly controlled, read-only interfaces where necessary.  
- Store build-time secrets (for example, tokens for internal repositories) in dedicated secret stores that are separate from production secret managers and use distinct keys.  
- Generate synthetic, masked, or sampled datasets specifically for testing and training in build pipelines and track them as separate governed artifacts.  
- Prohibit build identities from holding roles that can mint runtime signing keys or modify runtime key stores; use dedicated key management flows for runtime.  
- Periodically review connectivity and IAM policies to ensure that no “temporary” or legacy paths have reintroduced build-to-production coupling.

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory

---

#### 3.9.13 (BUILD-13) ATLAS-BUILD-LINEAGE — Explicit Artifact Lineage and Derivation

Each governed build artifact MUST record explicit lineage, including immediate inputs (source commits, configuration versions, dependency lock sets), prior artifact identity if the artifact is a transform or derivative, build environment identifiers, and toolchain versions and digests. Lineage MUST form a continuous, verifiable chain from deployed artifact back to reviewed source and declared dependencies, with no gaps or ambiguous links in TI-2 and TI-3 systems.

**Rationale**  
During incidents, audits, and regulatory inquiries, organisations must be able to answer “where did this artifact come from?” with precision. Without explicit lineage, defenders cannot determine whether an artifact was built from approved inputs, whether known-vulnerable dependencies are present, or whether a compromised pipeline introduced changes. A continuous lineage chain makes each artifact explainable and supports rapid impact assessment and targeted remediation.

**Implementation Notes**  
- Capture and store, for each build, the source repository URLs, commit hashes, configuration identifiers, dependency lock set digests, and toolchain identities.  
- Represent lineage in structured, queryable formats that link artifacts to their inputs and, where relevant, to prior artifacts (for example, base images, parent packages).  
- Integrate lineage identifiers into deployment metadata so that running workloads can be mapped back to their full build context.  
- Ensure lineage records are themselves covered by ATLAS-EV controls (see 3.7) and stored as tamper-evident evidence for TI-3 contexts.  
- Make lineage retrieval part of standard operational, security, and compliance workflows (for example, vulnerability response, change review, and regulatory reporting).

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory

---

#### 3.9.14 (BUILD-14) ATLAS-BUILD-EVIDENCE-TI — Build Evidence as Forensic Records

Build logs, SBOMs, lineage records, and attestation metadata for governed artifacts MUST be stored according to telemetry integrity requirements appropriate to system criticality. At minimum, TI-2 systems MUST treat build evidence as structured, schema-validated security telemetry; where ATLAS requires TI-3 WORM evidence (for example, for systemic control planes or safety-critical workloads), build evidence MUST be stored in tamper-evident, cryptographically chained systems. Build evidence SHALL NOT rely on mutable, in-place-editable logging mechanisms.

**Rationale**  
Build systems are often the first targets in supply-chain attacks, and their logs and metadata are central to reconstructing how a compromise occurred. If build evidence can be altered or deleted, attackers can erase their tracks or forge alternative histories. Treating build evidence as security- and forensics-grade telemetry ensures it is preserved, verifiable, and admissible in investigations and legal processes.

**Implementation Notes**  
- Classify build evidence according to the highest TI level of workloads that consume the resulting artifacts and store it accordingly.  
- Route build logs, SBOMs, attestation bundles, and lineage records into central telemetry infrastructure that enforces immutability guarantees appropriate for TI-2/TI-3.  
- Apply schema validation to build evidence to ensure consistency, and reject or quarantine malformed records.  
- Periodically test evidence retrieval and verification (for example, re-deriving digests from logs and comparing them with stored values).  
- Treat gaps or inconsistencies in build evidence for TI-3 systems as security incidents requiring investigation and possible rebuilds.

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory (with WORM / tamper-evident storage)

---

#### 3.9.15 (BUILD-15) ATLAS-BUILD-DEPLOY-BLOCK — Deployment Fails Closed on Provenance or Attestation Failure

Deployment systems for governed artifacts MUST fail closed automatically when provenance or attestation checks fail or are incomplete. If any of the following checks fail or cannot be completed: artifact signature verification, dependency digest verification, compiler/toolchain attestation, SBOM integrity validation, or lineage completeness, the deployment MUST be blocked. Human operators SHALL NOT be permitted to bypass or override these failures to force deployment of TI-2 or TI-3 artifacts.

**Rationale**  
If provenance and attestation checks are treated as advisory rather than mandatory, operational pressure will eventually lead teams to bypass them during incidents or tight deadlines, thereby normalising insecure deployments. Attackers can exploit such “break glass” patterns to introduce compromised artifacts exactly when defenders are most distracted. Making deployments fail closed on provenance failures ensures that integrity checks remain hard requirements, not optional safeguards.

**Implementation Notes**  
- Integrate provenance and attestation verification into deployment pipelines as gating steps that must succeed before rollout proceeds.  
- Configure deployment tooling so that provenance failures cannot be overridden using simple flags, manual approvals, or direct API calls in TI-2/TI-3 environments.  
- Provide safe fallback behaviours (for example, continuing to run the last known-good version) when new deployments are blocked.  
- Log all blocked deployments, including which checks failed, as security events with sufficient context for follow-up analysis.  
- Periodically test failure paths by intentionally introducing invalid signatures or incomplete attestations to confirm that deployment gates behave as expected.

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory

---
### 3.10 Runtime Isolation and Sandbox Enforcement Controls (ATLAS-RUN)

Runtime environments are active execution surfaces where malicious code, unauthorized privilege escalation, lateral identity movement, syscall abuse, or environment manipulation may occur. ATLAS-RUN controls require strict isolation boundaries, capability-constrained execution, and deterministic sandboxing to prevent runtime behaviour from escaping declared identities, domains, and privilege scopes. These controls apply to processes, containers, VMs, enclaves, serverless runtimes, and any environment in which governed artifacts execute.

Runtime isolation is treated as a primary enforcement layer, not as a best-effort defence. Where isolation guarantees cannot be established or verified, governed execution MUST NOT proceed.

---

#### 3.10.1 (RUN-01) ATLAS-RUN-HERMETIC-EXEC — Hermetic Execution Environments

Runtime execution for governed workloads MUST occur in hermetic environments where external state, system libraries, hardware interfaces, environment variables, and host resources outside the declared boundary are not implicitly inherited. Execution environments MUST explicitly declare all accessible resources, including libraries, devices, environment variables, mounts, and services, and MUST prevent access to undeclared resources by default.

**Rationale**  
If runtime environments inherit host-level state or incidental resources, attackers can exploit ambient capabilities that were never intended to be part of the workload’s trust contract. Hidden dependencies on host libraries, environment variables, or hardware features make behaviour non-deterministic and undermine boundary enforcement. Hermetic execution ensures that runtime behaviour is constrained to what was explicitly declared and reviewed at deployment.

**Implementation Notes**  
- Use container or VM profiles that mount only explicitly declared directories, devices, and libraries; avoid broad host mounts such as `/` or `/var/run` unless strictly required.  
- Define and enforce allowlists for environment variables exposed to each workload, and drop all others by default.  
- Disable implicit access to host devices (for example, raw block devices, GPUs, USB, character devices) unless declared and justified.  
- Validate hermeticity periodically by running the same workload on differently configured hosts and confirming that undeclared host differences do not affect behaviour.  

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory  

---

#### 3.10.2 (RUN-02) ATLAS-RUN-SANDBOX-MANDATORY — Mandatory Sandbox Enforcement

All governed execution MUST run inside explicit isolation mechanisms such as sandboxes, containers, VMs, enclaves, or equivalent runtime isolation constructs. Direct execution of governed artifacts on raw hosts, without controlled isolation boundaries and policy enforcement, is prohibited in TI-2 and TI-3 environments. Isolation MUST be configured and validated per workload identity, not assumed from platform defaults.

**Rationale**  
Raw host execution collapses boundaries between workloads and the underlying infrastructure, making it trivial for a compromised process to affect unrelated services or control planes. Modern exploitation techniques routinely assume that if an attacker gains code execution, they can pivot across the host. Mandatory sandboxing ensures that even if a workload is compromised, its blast radius is constrained to a defined isolation domain.

**Implementation Notes**  
- Run governed workloads in containers or VMs with clearly defined namespaces, capabilities, and resource controls.  
- For serverless or managed runtimes, obtain and review guarantees from the platform regarding process and tenant isolation, and treat them as part of the control plane.  
- Block deployment of TI-2 and TI-3 workloads that are configured to run directly on the host without isolation.  
- Validate that isolation is enforced at runtime by checking effective namespaces, capabilities, and security profiles for each governed process.  

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory  

---

#### 3.10.3 (RUN-03) ATLAS-RUN-NO-SHARED-MEMORY — No Shared Memory Across Domains

Execution environments for distinct trust domains MUST NOT share memory regions, buffers, or direct inter-process communication channels that bypass policy enforcement. Shared memory mechanisms (for example, shared memory segments, memory-mapped files, GPU-bus transfers, or zero-copy IPC) MUST be explicitly declared, constrained to a single execution domain, and subject to the same boundary and capability controls as other inter-domain communication.

**Rationale**  
Shared memory and low-level IPC primitives provide high-bandwidth, low-visibility channels that can bridge isolation boundaries and evade network-centric monitoring. Attackers can use shared memory to exfiltrate secrets, inject code, or coordinate lateral movement without leaving conventional network traces. Prohibiting cross-domain shared memory and forcing communication through governed channels preserves the integrity of isolation boundaries.

**Implementation Notes**  
- Configure container and VM runtimes to disable general-purpose shared memory constructs between tenants or trust domains by default.  
- Treat GPU memory, DMA-capable devices, and other high-speed buses as shared memory and apply equivalent isolation policies.  
- Where intra-domain shared memory is required for performance, document the domain scope and ensure that no cross-tenant or cross-trust mapping is possible.  
- Monitor for unexpected use of shared memory APIs in workloads that should not require them and treat such usage as suspicious.  

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory  

---

#### 3.10.4 (RUN-04) ATLAS-RUN-CONTROLLED-SYSCALLS — Controlled System Call Surface

System call usage by governed workloads MUST be restricted to an allowlist defined per execution identity or class of workloads. Attempts to invoke syscalls outside the declared capability set MUST fail closed and generate security-relevant telemetry. Workloads MUST NOT dynamically request or obtain new syscall privileges at runtime beyond those declared and approved at deployment.

**Rationale**  
The system call interface is the primary bridge between user space and kernel space. Unrestricted or poorly governed syscall access allows attackers to perform arbitrary file operations, privilege manipulations, and low-level attacks even within otherwise isolated environments. Constraining syscall surfaces to what is operationally necessary reduces exploitability and makes anomalous behaviour easier to detect.

**Implementation Notes**  
- Use kernel-level mechanisms such as seccomp filters, pledge-like constructs, or syscall policies to restrict available syscalls per workload.  
- Derive syscall allowlists from documented workload requirements and keep them under version control and review.  
- Monitor and log blocked syscall attempts, correlating them with workload identity and context for incident investigation.  
- Periodically review syscall policies to remove obsolete allowances and verify that workloads function correctly under constrained surfaces.  

**Applies To:**  
- TI-1: recommended for exposed services  
- TI-2: mandatory  
- TI-3: mandatory  

---

#### 3.10.5 (RUN-05) ATLAS-RUN-NO-ESCAPE — Isolation Escape Prevention

Governed workloads MUST NOT perform actions intended to escape their isolation boundaries, such as namespace manipulation, filesystem pivoting, privilege escalation, container breakout techniques, or direct modification of host control surfaces. Attempted isolation escapes MUST be blocked by runtime controls and treated as high-severity security incidents with TI-3 evidence capture in TI-2 and TI-3 environments.

**Rationale**  
Isolation escapes convert a controlled compromise of a single workload into a broader compromise of the host or cluster. Many modern attack techniques focus on container escapes, kernel exploitation, or misconfigured namespaces precisely to bypass sandbox guarantees. Explicitly prohibiting and detecting escape behaviours reinforces the boundary model and signals that any attempt to cross it is inherently malicious.

**Implementation Notes**  
- Enforce strict namespace separation (PID, mount, network, user, IPC) between workloads and the host for TI-2/TI-3 systems.  
- Deny workloads capabilities and privileges commonly used in escape techniques (for example, privileged containers, host PID namespace, unrestricted `CAP_SYS_ADMIN`).  
- Monitor for runtime behaviours indicative of escape attempts (for example, mounting host filesystems, accessing `/proc` for other namespaces, loading unapproved kernel modules).  
- Automatically quarantine or terminate workloads that trigger potential escape behaviours and generate TI-3 evidence records for follow-up.  

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory  

---

#### 3.10.6 (RUN-06) ATLAS-RUN-EPHEMERAL-FS — Ephemeral and Scoped Filesystems

Filesystems accessible to governed workloads MUST be scoped to the active execution domain and, by default, ephemeral for runtime state. Workloads MUST NOT have direct access to host or sibling domain filesystems. Persistent writes from governed workloads MUST occur only through explicitly governed storage channels (for example, declared object stores, WORM volumes, or controlled databases) with clear provenance and access policies.

**Rationale**  
Unscoped or persistent filesystem access enables attackers to implant long-lived backdoors, tamper with other workloads, or modify future executions via stored state. Ephemeral, domain-scoped filesystems limit the persistence of compromise and reduce opportunities for cross-workload manipulation. Routing persistence through governed storage channels brings data access and modification under policy and evidence controls.

**Implementation Notes**  
- Configure containers and VMs with per-workload filesystems that are destroyed or reset on redeploy or restart, unless explicitly configured otherwise.  
- Avoid mounting host directories or shared volumes into multiple domains unless absolutely required and heavily governed.  
- Use explicit volume declarations for persistent state, tagged with ownership, purpose, and allowed identities, and enforce access controls accordingly.  
- Integrate filesystem and storage access with ATLAS data-access and evidence controls to ensure proper logging and provenance.  

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory  

---

#### 3.10.7 (RUN-07) ATLAS-RUN-CGROUP-LIMITS — Deterministic Resource Boundaries

Governed workloads MUST be constrained by explicit resource boundaries, including CPU and memory ceilings, process and thread count limits, I/O quotas, GPU allocation limits, and rate limits on key operations. Lack of declared resource limits for TI-2 and TI-3 workloads SHALL be treated as insufficient governance. Resource boundaries MUST be enforced via kernel or platform primitives such as cgroups, quotas, or equivalent mechanisms.

**Rationale**  
Unbounded or loosely constrained workloads can exhaust shared resources, enable denial-of-service attacks, or hide malicious activity behind excessive consumption. Resource constraints also influence determinism; behaviour that depends on opportunistic resource availability is harder to reason about and test. Explicit limits make performance and failure modes more predictable and reduce the ability of a compromised workload to disrupt others.

**Implementation Notes**  
- Configure cgroups or equivalent mechanisms per workload, with explicit settings for CPU shares, memory limits, process caps, and I/O quotas.  
- Apply rate-limiting to external calls, such as network requests or database operations, to prevent abuse and runaway loops.  
- Monitor resource usage against declared limits and alert on repeated near-limit behaviour that may indicate abuse or misconfiguration.  
- Treat absence of resource configurations in deployment manifests for TI-2/TI-3 workloads as a policy violation requiring remediation.  

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory  

---

#### 3.10.8 (RUN-08) ATLAS-RUN-CAPABILITY-BOUND-IO — Capability-Bound I/O Controls

Network, device, and filesystem I/O for governed workloads MUST be bound to explicit capability declarations tied to execution identity. Accessing undeclared endpoints, devices, or storage locations MUST fail closed. Execution environments SHALL NOT auto-inherit host network interfaces or broad device access; instead, specific interfaces and endpoints MUST be declared and permitted per workload.

**Rationale**  
Implicit I/O capabilities allow workloads to reach unplanned destinations, interact with sensitive devices, or exfiltrate data through covert channels. Attackers exploit overly broad network and device access to move laterally or access protected resources. Binding I/O abilities to explicit capabilities tied to identity ensures that workloads can only interact with what they were designed and approved to reach.

**Implementation Notes**  
- Define per-workload network policies that restrict allowed destinations, ports, and protocols; enforce them via service meshes, firewalls, or network policies.  
- Restrict device access by default and grant explicit permissions only for required devices (for example, specific GPUs or hardware accelerators).  
- Use filesystem mounts and storage access policies that map to specific, declared volumes and prohibit arbitrary path traversal to host or peer volumes.  
- Log and alert on attempted I/O to undeclared destinations or devices as potential boundary violations.  

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory  

---

#### 3.10.9 (RUN-09) ATLAS-RUN-IMMUTABLE-RUNTIME — Immutable Runtime Environment

Runtime environments for governed workloads MUST be treated as immutable once initialisation is complete. Installing packages, modifying system libraries, adding plugins, or mutating dependencies during runtime is prohibited unless such changes are declared in deployment, subject to the same controls as new artifacts, and result in a new signed runtime identity. In-place modification of the runtime environment for TI-2 and TI-3 workloads MUST be blocked.

**Rationale**  
Runtime mutation blurs the line between “what was deployed” and “what is executing”, making it difficult to validate behaviour against reviewed artifacts. Attackers frequently install additional tools, modify libraries, or inject new code at runtime to establish persistence and evade controls. Keeping runtime environments immutable forces all significant changes back through governed build and deployment processes where provenance and review apply.

**Implementation Notes**  
- Use minimal, read-only base images or templates for containers and VMs, and avoid package managers in running workloads.  
- Disable or restrict shell access and administrative tools within runtime environments for TI-2/TI-3 workloads.  
- Treat any need to modify runtime libraries, dependencies, or system configuration as a trigger for a new build and redeployment.  
- Monitor for package installation, dynamic library loading from unexpected paths, or modifications to runtime filesystems as potential compromise indicators.  

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory  

---

#### 3.10.10 (RUN-10) ATLAS-RUN-RUNTIME-ATTEST — Runtime Integrity Attestation

Before governed workloads begin execution, the runtime environment MUST perform integrity attestation that covers execution identity, boundary scope, toolchain versions, filesystem state, and declared resource constraints. Attestation results MUST be validated against expected values derived from deployment metadata. Failure to attest, or attestation mismatches in TI-2 and TI-3 contexts, MUST block execution and generate security events.

**Rationale**  
Even if builds and deployments are controlled, runtime environments may drift due to misconfiguration, manual changes, or compromise. Without attestation, systems may unknowingly execute governed workloads in environments that no longer match their declared assumptions. Runtime attestation ensures that the environment still conforms to the intended contract at the moment of execution.

**Implementation Notes**  
- Use platform attestation features (for example, measured boot, integrity measurement, or signed environment descriptors) to capture runtime state before starting workloads.  
- Compare attestation measurements to expected hashes or manifests stored in deployment metadata or policy stores.  
- Refuse to start workloads when attestation data is missing, stale, or does not match expected values, and log these failures as security events.  
- For TI-3 systems, anchor attestation results into TI-3 evidence stores alongside workload identity and deployment records.  

**Applies To:**  
- TI-1: recommended for sensitive workloads  
- TI-2: mandatory  
- TI-3: mandatory  

---
---

#### 3.10.11 (RUN-11) ATLAS-RUN-BOUNDARY-ENFORCE — Boundary Enforcement at Execution

Runtime execution MUST NOT assume access to domains, identities, or capabilities that were not explicitly declared and authorised at deployment time. Any attempt by a governed workload to escalate or modify its boundaries – including changes to identities, domains, network scopes, or privilege sets – MUST be blocked by enforcement controls. In TI-2 and TI-3 environments, such attempts MUST halt execution and generate security-relevant evidence.

**Rationale**  
Deployment-time declarations describe the intended execution contract for a workload. If runtime behaviour can silently expand or reinterpret these boundaries, the system’s trust model collapses and attackers can transform low-privilege footholds into high-privilege control. Enforcing boundaries at execution ensures that workloads remain constrained to the reviewed and approved scope, and that deviations are treated as violations rather than configuration quirks.

**Implementation Notes**  
- Treat deployment manifests, policies, or descriptors as the authoritative source of domains, identities, and capabilities for each workload.  
- Configure runtime admission and sidecar enforcement components to compare requested identities, namespaces, and network scopes against deployment declarations.  
- Block token acquisition, role assumption, or network path usage that would extend a workload beyond its declared boundaries.  
- Log all boundary-violation attempts, including context (who, what, where) as at least TI-2 telemetry, and as TI-3 evidence in high-integrity environments.  
- Integrate boundary enforcement with control-plane policies (for example, IAM, network policy, service mesh) to ensure consistent behaviour across layers.

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory  

---

#### 3.10.12 (RUN-12) ATLAS-RUN-HARDWARE-ISOLATION — Hardware-Level Execution Separation

Where supported, governed workloads SHOULD leverage hardware-backed isolation mechanisms such as virtualisation extensions, secure enclaves, IOMMU enforcement, and PCIe device isolation to strengthen runtime boundaries. For TI-3 workloads, hardware-level isolation MUST be used wherever feasible and MUST be explicitly documented when unavailable. Absence or degradation of hardware isolation guarantees in TI-3 contexts MUST be considered a risk that requires compensating controls and explicit acceptance.

**Rationale**  
Software-only isolation is vulnerable to kernel-level exploits, shared-hardware side channels, and misconfigurations. Hardware-backed mechanisms provide stronger separation between workloads and between workloads and the host, reducing the feasibility of cross-tenant attacks, DMA abuse, and low-level tampering. For high-integrity and safety-critical workloads, relying solely on software isolation is insufficient without explicit risk assessment and compensating measures.

**Implementation Notes**  
- Enable and configure CPU virtualisation features, secure enclaves, and IOMMU on hosts running TI-2/TI-3 workloads where platform support exists.  
- Use hardware-backed attestation (for example, measured boot, enclave attestation) to prove that workloads are running in expected hardware isolation contexts.  
- Isolate DMA-capable devices such as GPUs and NICs using IOMMU and per-tenant or per-workload mappings.  
- Document, for each TI-3 workload, whether hardware isolation is in effect, which mechanisms are used, and what compensating controls apply if not.  
- Periodically verify that hardware isolation settings have not drifted (for example, BIOS/firmware changes, disabled VT-x/SEV/TDX) and treat regressions as security issues.

**Applies To:**  
- TI-1: recommended  
- TI-2: recommended  
- TI-3: mandatory (or explicit, governed exception with compensating controls)

---

#### 3.10.13 (RUN-13) ATLAS-RUN-STATE-CONTAINMENT — State Containment Between Runs

State generated during execution of governed workloads MUST NOT implicitly carry over to subsequent runs in ways that alter behaviour outside declared channels. Rehydration of state across runs MUST occur only through explicitly declared, provenance-governed storage and configuration mechanisms. Hidden or informal persistence mechanisms (for example, local scratch disks misused as durable stores) are prohibited for TI-2 and TI-3 workloads.

**Rationale**  
Implicit state carry-over allows compromises, misconfigurations, and subtle behavioural changes to persist across restarts and deployments without visibility. Attackers can implant configuration or data in unexpected locations so that “clean” redeploys continue to execute malicious logic. Containing state and routing cross-run persistence through governed channels ensures that evolutions in behaviour are explainable and auditable.

**Implementation Notes**  
- Treat local ephemeral storage as non-durable; design workloads so that any state that must survive restarts is written to explicitly declared persistent stores.  
- Use configuration systems, databases, object stores, or evidence systems that are already under provenance and access-control governance for persistent state.  
- Prohibit use of untracked local directories, temp folders, or scratch volumes as de facto durable storage for TI-2/TI-3 systems.  
- On redeploy or restart, validate that behaviour is determined by declared configuration and governed state sources, not by residual artefacts in runtime environments.  
- Monitor for unexpected re-use of local state (for example, files reappearing across runs in supposedly ephemeral locations) and treat it as a design or security defect.

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory  

---

#### 3.10.14 (RUN-14) ATLAS-RUN-SELF-MODIFY-BLOCK — Block Runtime Self-Modification

Executables and governed workloads MUST NOT modify their own binary representation, linked libraries, interpreter frames, or core execution logic at runtime. Any system that requires self-modification of execution behaviour MUST be classified and governed as a Self-Modifying Autonomous Execution System (SM-AES) under Section 3.8.C and is subject to those stricter controls. For non-SM-AES workloads, self-modification attempts MUST be blocked and recorded as security events.

**Rationale**  
Self-modifying code obscures the link between the reviewed artifact and the behaviour actually executed, making static analysis and attestation unreliable. Attackers can use runtime patching, dynamic code loading, or in-memory rewriting to graft malicious logic onto otherwise trusted binaries. Restricting self-modification to explicitly governed SM-AES contexts and blocking it elsewhere preserves the integrity of the deployment–runtime linkage.

**Implementation Notes**  
- Disable or restrict mechanisms such as `dlopen` of unapproved libraries, dynamic code evaluation (for example, `eval` of fetched code), and runtime patching frameworks in governed workloads.  
- Configure runtimes and security tooling to detect and prevent modification of executable segments, JIT caches, or critical interpreter structures, unless explicitly governed as SM-AES.  
- Treat any need to change core execution logic as a trigger for a new build and redeployment rather than runtime modification.  
- Where SM-AES is required, apply the full set of ATLAS-SM-AES controls, including versioned evolution, provenance, and evolution-key separation.  

**Applies To:**  
- TI-1: mandatory for non-SM-AES workloads  
- TI-2: mandatory (SM-AES handled under 3.8.C)  
- TI-3: mandatory (SM-AES handled under 3.8.C)  

---

#### 3.10.15 (RUN-15) ATLAS-RUN-FAIL-CLOSED — Fail-Closed on Isolation or Boundary Breach

If runtime isolation or boundary controls fail – due to sandbox errors, namespace anomalies, privilege escalation attempts, enforcement misconfiguration, or detection of an escape attempt – the system MUST fail closed for the affected workload. This includes denying further execution, isolating or terminating the process, and preventing new sessions from starting under the compromised context. TI-2 and TI-3 environments MUST additionally produce TI-3 evidence and trigger predefined remediation and incident response policies. Execution MUST NOT continue under degraded or uncertain isolation conditions.

**Rationale**  
Allowing workloads to continue running after isolation has been breached or is suspected to be breached transforms a local control failure into a systemic compromise. Attackers rely on systems tolerating “partial failure” of controls so they can operate within weakened boundaries. A strict fail-closed posture ensures that any isolation or boundary anomaly is treated as a critical incident, not an operational nuisance.

**Implementation Notes**  
- Implement health checks for sandbox, namespace, and isolation subsystems; on failure, halt affected workloads and prevent new ones from starting until controls are restored.  
- Configure enforcement components (for example, container runtimes, policy agents, kernel guards) to treat serious violations as fatal for the workload rather than merely logging them.  
- Integrate isolation failure events with central incident response workflows, including alerts, automatic evidence capture, and optional host quarantine where needed.  
- Store detailed telemetry and evidence for isolation failures in TI-3-compliant systems to support forensics and compliance reporting.  
- Test fail-closed behaviour regularly by simulating isolation-control failures and validating that workloads are halted and evidence is recorded as designed.

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory  

---

### 3.11 Provenance Enforcement and Supply Chain Controls (ATLAS-SUP)

Execution of governed artifacts SHALL require verifiable, tamper-evident provenance at import, retrieval, and execution time. Provenance enforcement applies both to internally produced artifacts and those sourced externally from third parties, partners, and downstream ecosystems. Provenance ambiguity, inconsistency, or incompleteness SHALL be treated as a security risk and MUST cause systems to fail closed for TI-2 and TI-3 workloads. ATLAS-SUP controls extend ATLAS-BUILD and ATLAS-SC/PROV by governing how artifacts cross organisational and trust boundaries and how their provenance is validated at consumption points.

---

#### 3.11.1 (SUP-01) ATLAS-SUP-CHAIN-BOUNDARY — Supply Chain Domain Boundaries

Artifacts originating from external supply chains MUST be treated as belonging to distinct trust domains, even when sourced from long-standing partners or vendors. External artifacts MUST NOT inherit trust privileges, identities, or policy exemptions from the receiving domain by default. Domain boundaries between producer and consumer MUST be explicit, represented in metadata, and enforced at intake, deployment, and execution time.

**Rationale**  
Most supply-chain incidents exploit blurry boundaries between “internal” and “external” software, where partner or vendor artifacts are treated as if they were first-party. When domain boundaries are implicit or informal, upstream compromise quickly becomes downstream compromise without clear accountability. Explicit, enforced domain separation ensures that external artifacts are always evaluated and constrained according to their origin, not their convenience.

**Implementation Notes**  
- Tag all artifacts with an explicit domain-of-origin identifier (for example, `internal`, `vendor-X`, `open-source-registry-Y`).  
- Maintain separate trust policies and intake pipelines for internal and external domains.  
- Prevent external artifacts from assuming internal service identities, roles, or keys; use separate identity namespaces per domain.  
- Enforce stricter verification and monitoring requirements for external domains compared to internal builds.  
- Treat any artifact with unknown or unset domain-of-origin as untrusted until classified.

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory  

---

#### 3.11.2 (SUP-02) ATLAS-SUP-NO-IMPLICIT-TRUST — No Implicit Trust in Upstream Systems

Governed systems MUST NOT implicitly trust external sources, package registries, repositories, container hubs, model zoos, or distribution networks. Trust MAY ONLY be granted after verification of signatures, provenance digests, and origin proofs consistent with local policy. Default behaviour for newly encountered upstream systems MUST be “untrusted” until they are explicitly onboarded into the organisation’s trust policy.

**Rationale**  
Public registries and distribution networks are frequent targets for account takeovers, typosquatting, and poisoned packages. Assuming that a popular registry or well-known platform is inherently trustworthy ignores the reality of shared-risk infrastructure. Explicit trust decisions backed by cryptographic verification significantly reduce the likelihood that upstream compromise silently becomes local compromise.

**Implementation Notes**  
- Maintain an allowlist of approved upstream registries and repositories with documented security expectations and SLAs.  
- Require TLS with certificate validation and, where possible, mutual authentication for all connections to upstream sources.  
- Verify artifact signatures and checksums using keys and digests managed under local policy, not solely those advertised by upstream.  
- Periodically re-assess upstream providers for security posture and incident history, and adjust trust policies accordingly.  
- Treat any artifact fetched from a non-approved or misconfigured upstream endpoint as untrusted and block its intake.

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory  

---

#### 3.11.3 (SUP-03) ATLAS-SUP-IMPORT-ATTEST — Import Attestation Requirements

Imported artifacts MUST include a minimum attestation set covering: a cryptographic signature from the origin, the artifact’s content digest, an SBOM or equivalent dependency description, and toolchain and build provenance identifiers. Intake systems MUST validate this attestation before the artifact is admitted into governed environments. Artifacts lacking complete, verifiable attestation MUST NOT be imported for TI-2 and TI-3 workloads.

**Rationale**  
Without strong attestation at import, consumers cannot know how an artifact was built, what it depends on, or whether it has been tampered with in transit. Post-hoc analysis during incidents is then forced to rely on incomplete or unverifiable metadata. Requiring attestation at intake ensures that only artifacts with sufficient provenance and build context enter the environment, reducing guesswork and limiting exposure.

**Implementation Notes**  
- Define a baseline attestation schema specifying required fields (signature, digest, SBOM reference, toolchain identity, build time, origin domain).  
- Use structured formats and signed envelopes for attestation data to prevent undetected modification.  
- Integrate attestation validation into intake pipelines as mandatory gates prior to publishing artifacts internally.  
- Reject or quarantine artifacts where attestation is missing, malformed, or cannot be cryptographically verified.  
- Link attestation records to lineage and evidence systems so they remain available for investigations and audits.

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory  

---

#### 3.11.4 (SUP-04) ATLAS-SUP-CROSS-DOMAIN-BRIDGE — Cross-Domain Provenance Bridging

When artifacts must be exchanged across trust domains, both producing and receiving domains MUST sign provenance proofs that bind the artifact identity to its origin and to the receiving domain’s intake decision. A single party SHALL NOT unilaterally authorise cross-domain artifact trust for TI-2 and TI-3 artifacts. The resulting provenance bridge MUST be verifiable end-to-end and stored as TI-2 or TI-3 evidence according to criticality.

**Rationale**  
Cross-domain artifacts represent shared risk; if only the producer attests to the artifact, the consumer’s due diligence is invisible and unenforced. Conversely, if consumers rely solely on their own checks without anchoring to producer assertions, inconsistencies and disputes about origin become likely. Dual-sided provenance bridging ensures that both domains explicitly accept their roles and that trust decisions are grounded in mutual evidence.

**Implementation Notes**  
- Require producing domains to publish signed provenance bundles with artifact digests and origin metadata.  
- Require receiving domains to generate their own signed intake records referencing the producer’s bundle and local verification results.  
- Treat the combination of producer and receiver signatures as the minimum proof required for cross-domain deployment.  
- Store provenance bridge records in TI-3-compliant evidence systems for artifacts used in systemic control planes or safety-critical contexts.  
- Deny execution where either side of the provenance bridge is missing, revoked, or fails verification.

**Applies To:**  
- TI-1: recommended for inter-org sharing  
- TI-2: mandatory for cross-domain use  
- TI-3: mandatory  

---

#### 3.11.5 (SUP-05) ATLAS-SUP-VERIFICATION-BEFORE-EXEC — Verification Before Execution

Provenance verification for governed artifacts MUST be completed before execution begins, not performed asynchronously or deferred to post-facto checks. Artifacts MUST NOT run in an unverified or “pending verification” state in TI-2 and TI-3 environments. Where verification cannot be completed (for example, offline keys, unavailable attestations), execution MUST fail closed or fall back to a previously verified artifact.

**Rationale**  
If verification is decoupled from execution, operational pressure will inevitably lead to “temporary” exceptions where unverified artifacts are allowed to run, normalising insecure behaviour. Attackers can exploit these gaps to deploy malicious artifacts precisely when verification systems are degraded or overloaded. Enforcing verification as a hard precondition for execution preserves the integrity of the provenance model.

**Implementation Notes**  
- Integrate provenance checks into admission controllers, deployment orchestrators, or runtime loaders so execution is impossible without successful verification.  
- Provide clear failure modes that block rollout while preserving existing known-good versions, rather than allowing partial deployment of unverified artifacts.  
- Log all verification results, including failures and reasons, as TI-2 telemetry or TI-3 evidence where relevant.  
- Periodically test controls by introducing deliberately invalid or incomplete provenance to confirm that execution is blocked.  

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory  

---

#### 3.11.6 (SUP-06) ATLAS-SUP-ORIGIN-LOCK — Origin Locking to Declared Trust Anchors

Artifacts MUST be bound to declared origin trust anchors that identify the expected source domains, signing authorities, and distribution channels. If provenance indicates that an artifact has shifted to an undeclared anchor – for example, due to mirroring, repackaging, proxying, or unauthorised redistribution – the artifact MUST be treated as untrusted until re-onboarded through intake pipelines. Origin lock violations for TI-2 and TI-3 artifacts MUST block use and trigger investigation.

**Rationale**  
Attackers often introduce malicious copies of legitimate artifacts through rogue mirrors, compromised CDNs, or “helpful” repackaging. If systems accept artifacts purely on name or version, ignoring where they were obtained, adversaries can stand in for trusted sources. Origin locking ensures that only artifacts delivered via expected, verified anchors are accepted, and that unexpected provenance shifts are surfaced as risks.

**Implementation Notes**  
- Maintain a mapping between artifact identities and allowed origin anchors (for example, specific registries, GPG keys, or PKI hierarchies).  
- Validate that the actual retrieval path and signer for each artifact match the configured origin-lock policy before allowing import or execution.  
- Treat retrieval from unexpected mirrors or cache layers as a policy violation, even if signatures superficially validate.  
- Use explicit re-onboarding procedures when changing distribution channels (for example, migrating registries), including dual-signing phases and updated origin-lock policies.  

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory  

---

#### 3.11.7 (SUP-07) ATLAS-SUP-CONTENT-LOCK — Content Lock Against Repackaging

Artifact identity MUST be tied to content, not filenames, labels, or superficial metadata. Repackaging, rehydration, compression changes, or other transformations that alter an artifact’s content MUST result in a new artifact identity and updated lineage and provenance. Systems MUST NOT treat differently packaged or transformed artifacts as equivalent solely on the basis of version strings or labels in TI-2 and TI-3 contexts.

**Rationale**  
Repackaging and format transformations are common vectors for inserting malicious payloads while preserving outward-facing identifiers such as names or version numbers. If identity is based on labels rather than content, defenders cannot reliably distinguish genuine artifacts from doctored ones. Content-locked identities ensure that any change that could affect behaviour is visible and traceable.

**Implementation Notes**  
- Use content digests (for example, cryptographic hashes over canonical forms of the artifact) as primary identities rather than relying only on version numbers.  
- Treat container re-layering, compression changes, archive restructuring, or bundle repacking as transformations that require new identities and lineage entries.  
- Ensure that deployment and configuration systems reference artifacts by content digest where possible, not only by tags or human-readable names.  
- Link repackaged or optimised artifacts back to their source artifacts through explicit lineage relationships, making the transformation history auditable.  

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory  

---

#### 3.11.8 (SUP-08) ATLAS-SUP-NO-TRANSITIVE-TRUST — No Transitive Trust Through Dependencies

Dependencies of trusted artifacts MUST NOT inherit trust implicitly from the primary artifact. Each dependency – direct or transitive – MUST be independently verified and subject to the same provenance and integrity controls as the artifact that consumes it. Trust SHALL NOT cascade automatically across dependency graphs in TI-2 and TI-3 environments.

**Rationale**  
Many large-scale compromises abuse transitive dependencies buried deep in dependency trees, knowing that consumers rarely review or verify these components individually. If trust is assumed to propagate from a top-level artifact downwards, attackers can plant malicious code in seemingly minor libraries that are nonetheless widely deployed. Requiring independent verification for dependencies forces organisations to confront the full risk surface of their software stacks.

**Implementation Notes**  
- Use SBOMs and dependency graphs to enumerate all dependencies (direct and transitive) for each artifact.  
- Apply provenance, signature, and origin-lock checks to each dependency in the graph, not only to the top-level artifact.  
- Treat unverified or unverifiable dependencies as policy violations and block deployment until they are removed, replaced, or brought under governance.  
- Periodically re-evaluate dependency trust decisions as new vulnerabilities or supply-chain incidents are disclosed.  

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory  

---
---

#### 3.11.9 (SUP-09) ATLAS-SUP-IMPORT-BLOCK-ON-PARTIAL — Block Partial or Incomplete Provenance

Artifacts with partial, missing, or unverifiable provenance MUST be blocked from intake into governed environments. This includes artifacts with incomplete lineage, partial SBOMs, unverifiable or missing signatures, ambiguous origin identifiers, or unresolved dependency lists. For TI-2 and TI-3 workloads, human override SHALL NOT permit import or execution of partially verified artifacts; the only acceptable remediation is to obtain complete provenance or to remove the artifact from governed use.

**Rationale**  
Partial provenance is indistinguishable from deliberate obfuscation in many real-world scenarios. Attackers frequently leave just enough information to appear legitimate while hiding crucial details such as malicious transitive dependencies or unverified rebuilds. Allowing “almost good enough” provenance under operational pressure normalises insecure intake. Treating incomplete provenance as a hard failure ensures that ambiguity is surfaced and resolved rather than silently tolerated.

**Implementation Notes**  
- Define precise criteria for “complete provenance” (for example, lineage coverage, SBOM completeness, signature presence, and verification status) per artifact class.  
- Configure intake pipelines so that provenance validation is atomic: any unmet requirement results in a single, clear failure state that blocks further processing.  
- Disable emergency flags, manual overrides, or undocumented procedures that allow operators to bypass provenance requirements for TI-2/TI-3 artifacts.  
- Provide standard remediation workflows (for example, requesting updated attestations from producers, regenerating SBOMs, or re-building internally) instead of ad-hoc exceptions.  
- Log all provenance failures, including which fields were missing or invalid, and use these logs to identify systemic intake weaknesses or recurring upstream issues.

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory (no manual override)  
- TI-3: mandatory (no manual override)  

---

#### 3.11.10 (SUP-10) ATLAS-SUP-REVOCATION — Enforcement of Upstream Revocation

When an originating domain revokes an artifact’s signature, provenance, or trust anchor, downstream systems consuming that artifact MUST enforce revocation automatically. Retained copies of the artifact MUST NOT continue to run as trusted in governed environments. Continued use, if absolutely required for emergency reasons, MUST occur under an explicitly degraded trust posture with containment and compensating controls, and MUST NOT be presented as a trusted state.

**Rationale**  
Revocation is the primary mechanism by which producers notify consumers that previously trusted artifacts are no longer safe. If downstream systems ignore revocation signals or only apply them selectively, attackers can continue to exploit compromised artifacts long after the issue is known. Automatic, enforced revocation ensures that downstream environments respond promptly and consistently when the trust status of an artifact changes.

**Implementation Notes**  
- Subscribe to upstream revocation feeds (for example, transparency logs, CRLs, update channels) for all trusted origin domains.  
- Maintain revocation lists locally and integrate them into deployment, runtime admission, and configuration management systems.  
- On revocation, block new deployments and schedule or perform controlled shutdown or replacement of running instances, based on impact assessment.  
- Record revocation enforcement actions, including affected systems and timelines, as TI-2 or TI-3 evidence depending on criticality.  
- Where emergency continued use is unavoidable (for example, safety systems with no immediate alternative), clearly label the system as operating under a degraded trust profile, apply strict containment, and prioritise remediation.

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory  

---

#### 3.11.11 (SUP-11) ATLAS-SUP-REVOCATION-PROPAGATION — Revocation Propagation Across Domains

Revocations in one domain that affect artifacts shared across multiple domains MUST be propagated to all downstream deployments consuming the shared artifact. Systems consuming revoked artifacts MUST detect the revocation, halt execution or downgrade trust as defined by policy, and generate TI-2 or TI-3 evidence. No domain may continue to treat an artifact as fully trusted once a trust anchor or signature has been revoked, unless it recomputes trust through independent rebuild and provenance.

**Rationale**  
Shared artifacts frequently span multiple organisations, regions, and regulatory environments. A revocation signal that remains siloed in one domain allows other domains to continue operating under false assumptions of safety. Automated propagation of revocation ensures that a compromise discovered by one party quickly benefits all, turning distributed usage into a collaborative defence rather than a shared liability.

**Implementation Notes**  
- Implement revocation propagation mechanisms in central governance systems (for example, internal registries, artifact catalogues, trust-policy engines) that span all consuming domains.  
- Ensure that dependency and SBOM data can be used to identify all consuming systems and tenants for a given revoked artifact.  
- Coordinate with partner organisations and vendors so that revocation events are communicated over authenticated channels, not only via public advisories.  
- Treat failures to propagate revocation (for example, outdated caches, offline environments) as incidents requiring corrective action and architectural hardening.  

**Applies To:**  
- TI-1: recommended for shared artifacts  
- TI-2: mandatory for cross-domain use  
- TI-3: mandatory  

---

#### 3.11.12 (SUP-12) ATLAS-SUP-PULL-ISOLATION — Isolation from Unverified Distribution Channels

Governed systems SHALL NOT pull artifacts directly from public or unmanaged distribution channels such as public package registries, generic container hubs, “model zoos,” or arbitrary Git repositories. All external pulls MUST route through controlled intake systems that enforce provenance, signing, and policy checks. Direct “pull and run” patterns from public sources are prohibited for TI-2 and TI-3 workloads.

**Rationale**  
Direct pulls from public infrastructure conflate retrieval, validation, and execution into a single step, leaving minimal room for governance. Attackers can compromise upstream accounts or inject malicious content into public channels, and direct consumers will unknowingly run those artifacts. Forcing all pulls through controlled intake systems creates a buffer where security policy, provenance verification, and risk assessment can be applied before artifacts reach execution environments.

**Implementation Notes**  
- Configure build and deployment systems so that they can only fetch artifacts from internal, governed registries or mirrors.  
- Disable or restrict use of arbitrary external URLs or public registry endpoints in production build and deployment configurations.  
- Implement dedicated intake services that mirror or proxy upstream repositories while enforcing ATLAS-SUP and ATLAS-BUILD/PROV policies.  
- Periodically audit configurations (for example, CI pipelines, IaC, container manifests) for residual direct pulls from public endpoints and remediate them.  

**Applies To:**  
- TI-1: strongly recommended  
- TI-2: mandatory  
- TI-3: mandatory  

---

#### 3.11.13 (SUP-13) ATLAS-SUP-INTAKE-BOUNDARY — Controlled Intake and Staging

External artifacts MUST enter the receiving ecosystem only through a controlled intake pipeline. The intake boundary MUST perform, at minimum: signature verification, origin-domain and trust-anchor checks, SBOM and origin validation, and archival of key metadata as TI-2 or TI-3 evidence. Direct execution of externally sourced artifacts without passing through intake and staging is prohibited for TI-2 and TI-3 workloads.

**Rationale**  
Without a clearly defined intake boundary, artifacts can seep into environments through ad-hoc paths such as manual downloads, developer experiments, or untracked CI changes. These grey channels undermine governance and make incident reconstruction extremely difficult. A formal intake and staging process ensures that each external artifact is vetted, recorded, and either admitted or rejected according to policy before it can influence production.

**Implementation Notes**  
- Designate a limited set of intake services or environments through which all external artifacts must pass, irrespective of their eventual use case.  
- Require intake systems to store verification results, provenance bundles, and SBOM references in evidence stores before making artifacts available internally.  
- Use staging repositories or registries to hold newly imported artifacts until they pass all required checks and governance reviews.  
- Prohibit direct promotion from external sources to production registries; all promotion MUST originate from the intake/staging tier.  
- Monitor for and block attempts to bypass intake (for example, manual registry pushes, side-channel imports, or developer-owned registries).

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory  

---

#### 3.11.14 (SUP-14) ATLAS-SUP-LINEAGE-CONTINUITY — Continuity of Provenance Across Transformations

When artifacts are transformed – such as being compiled, quantised, containerised, optimised, pruned, localised, or adapted for new runtimes – their lineage MUST remain continuous and verifiable. Transformation events MUST record the relationship between input and output artifacts, and updated provenance MUST reference both. If lineage is broken or cannot be demonstrated, the resulting artifact MUST be treated as a new, untrusted identity that requires full intake and verification.

**Rationale**  
Transformations can significantly change the behaviour or risk profile of an artifact, particularly in AI and model pipelines. If these transformations are opaque or detached from prior provenance, consumers cannot determine whether the transformed artifact still conforms to expectations. Continuity of lineage ensures that all stages in an artifact’s evolution are visible and that trust decisions can account for every transformation step.

**Implementation Notes**  
- Use structured, versioned metadata to capture transformation operations, including tools used, parameters, and input–output mappings.  
- Link each output artifact’s provenance to the provenance of its inputs, forming a graph rather than isolated lineage chains.  
- Treat transformations that cannot be fully described or reproduced as high risk, requiring additional validation or re-building from trusted sources.  
- Integrate transformation metadata with SBOMs so that derived artifacts still expose a complete view of their dependency surfaces.  

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory  

---

#### 3.11.15 (SUP-15) ATLAS-SUP-FAIL-CLOSED — Fail Closed on Provenance Ambiguity

If provenance validation fails or yields ambiguity – due to missing lineage, unverifiable or conflicting signatures, mismatched digests, revoked trust anchors, orphaned SBOM entries, or unresolved dependency mappings – governed systems MUST fail closed for TI-2 and TI-3 workloads. Execution MUST NOT proceed on the assumption that “probably safe” is acceptable; lack of proof SHALL be treated as evidence of risk, not as an invitation to proceed.

**Rationale**  
Provenance systems exist to provide determinism and clarity about what is running and where it came from. If ambiguous or contradictory signals are tolerated, the entire provenance model collapses into advisory noise that can be overridden whenever inconvenient. Requiring fail-closed behaviour for ambiguity forces teams to either resolve the uncertainty or refuse to run the artifact, reinforcing provenance as a first-class control.

**Implementation Notes**  
- Implement provenance validation logic that explicitly enumerates ambiguity conditions rather than treating them as non-fatal warnings.  
- Configure deployment and runtime systems to block rollout when provenance ambiguity is detected, and to surface clear reasons to operators.  
- Maintain playbooks for resolving ambiguity (for example, contacting producers, rebuilding artifacts, regenerating SBOMs, or deprecating affected components).  
- Treat repeated or systemic provenance ambiguities as architectural issues requiring redesign of intake, build, or distribution processes.  
- For TI-3 workloads, log ambiguity events and associated decisions as forensic evidence to support later review by internal or external stakeholders.

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory  

---
### 3.12 Key, Identity, and Privilege Lifecycle Controls (ATLAS-ID)

Cryptographic identities govern execution rights, policy enforcement, cross-domain boundaries, artifact lineage, and control-plane behaviour. Mishandling identity material introduces systemic compromise risk that can bypass even strong runtime and supply-chain controls. ATLAS-ID requires strict governance over identity issuance, scoping, rotation, revocation, delegation, and termination across human, machine, service, artifact, and agentic identities.

Identity controls MUST be applied consistently across build, runtime, and control-plane systems. Where contradictions arise between convenience and identity safety, identity safety SHALL prevail for TI-2 and TI-3 workloads.

---

#### 3.12.1 (ID-01) ATLAS-ID-ISSUE — Controlled Identity Issuance

Identities for governed systems MUST be issued only through governed, auditable processes under explicit policy. Ad-hoc creation of execution identities (for example, manual keypair generation on developer laptops, untracked service accounts, or shared local accounts) is prohibited for TI-2 and TI-3 contexts. All identities, including machine, artifact, user, service, and autonomous agent identities, MUST originate from approved trust roots and be recorded with scope, purpose, and expiry.

**Rationale**  
Uncontrolled identity creation leads to shadow credentials, untracked privileges, and opaque trust surfaces that attackers can exploit. If identities can be minted informally, provenance, revocation, and accountability all become unreliable. Centralised, governed issuance ensures that every identity can be traced to a specific process, policy, and owner.

**Implementation Notes**  
- Use dedicated identity management systems (for example, PKI, IAM, KMS) as the sole mechanism to issue governed identities.  
- Require requests for new identities to pass through approval workflows with clearly defined justifications and scopes.  
- Prohibit direct `openssl`-style key generation for governed identities outside approved infrastructure.  
- Ensure issuance records include requester, approver(s), trust root, intended scope, and planned expiry.  

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory  

---

#### 3.12.2 (ID-02) ATLAS-ID-TRUST-ROOT — Binding to Declared Trust Roots

Each governed identity MUST be cryptographically bound to a specific, declared trust root (for example, CA, key hierarchy, or root-of-trust). Trust roots SHALL be explicit, independently verifiable, and governed by documented policy. Identities without a declared trust root, or whose trust root cannot be verified, MUST NOT be accepted in TI-2 and TI-3 environments.

**Rationale**  
If trust roots are implicit or obscure, it becomes impossible to reason about where authority actually originates or to enforce consistent revocation and audit. Attackers abuse ambiguous or poorly managed trust roots to introduce rogue identities that appear legitimate. Binding identities to clearly defined roots localises and constrains the blast radius of any compromise.

**Implementation Notes**  
- Maintain a catalogue of approved trust roots with associated policies, key lifetimes, and ownership.  
- Embed trust-root identifiers (for example, CA IDs, key fingerprints) into issued credentials or metadata.  
- Reject or quarantine credentials signed by unknown, deprecated, or untrusted roots.  
- Apply stronger controls and more frequent review to high-privilege trust roots (for example, those that can issue H2+ identities).  

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory  

---

#### 3.12.3 (ID-03) ATLAS-ID-HARDWARE-GEN — Hardware- or Enclave-Bound Key Genesis

Generation of high-privilege identities (for example, control-plane operators, root CAs, system-wide signing keys) SHOULD occur in secure hardware modules or enclaves. Where hardware-backed key genesis is unavailable, equivalent software attestation and hardened key-generation environments MUST be enforced. Key genesis for H2+ identities MUST NOT occur in unmanaged or multi-tenant environments, and MUST be auditable.

**Rationale**  
If high-privilege keys are generated on untrusted or multi-tenant systems, attackers may intercept or copy them at birth, making later controls ineffective. Hardware-assisted or strongly attested key generation reduces exposure to malware, memory scraping, and supply-chain tampering at the precise moment identities are created.

**Implementation Notes**  
- Use HSMs, TPMs, or enclave-backed key generation for root and high-privilege keys.  
- For software-only generation, employ hardened, single-purpose hosts with TI-3-level monitoring and strict access controls.  
- Keep detailed records of generation events, including environment identifiers and attestation proofs.  
- Prohibit high-privilege key generation from developer laptops, generic CI workers, or cloud shells.  

**Applies To:**  
- TI-1: recommended for elevated identities  
- TI-2: mandatory for H2+  
- TI-3: mandatory for H2+  

---

#### 3.12.4 (ID-04) ATLAS-ID-NO-REALLOCATION — No Identity Reuse Across Domains

A governed identity MUST NOT be reused across distinct trust domains, execution domains, artifacts, or environments. Reassigning the same credential or identity across different systems, tenants, or lifecycle stages is prohibited for TI-2 and TI-3 workloads. Identity reuse that crosses domain or context boundaries MUST be treated as a boundary violation and remediated.

**Rationale**  
When the same identity is used in multiple domains, provenance and audit trails become ambiguous: the same key could represent multiple principals or contexts. Attackers benefit from such reuse because compromising one environment yields access to others. Enforcing one-identity-per-domain/context makes attribution and containment tractable.

**Implementation Notes**  
- Design policies that enforce “single principal, single domain” semantics for each identity.  
- Automatically trigger alerts when the same credential or certificate is presented in multiple domains or contexts.  
- Require issuance of fresh identities when workloads are moved between environments (for example, dev to prod, org A to org B).  
- Use different keypairs or certificates for on-prem, cloud, and third-party domains rather than sharing a single identity.  

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory  

---

#### 3.12.5 (ID-05) ATLAS-ID-PER-ARTIFACT — Unique Identity per Artifact Instance

Each governed artifact instance (for example, deployment, workload, agent) MUST execute under a unique execution identity rather than shared global identities. Identity MUST reflect the execution context (tenant, environment, role), not only the build or repository context. Shared “service-wide” credentials for multiple concurrent instances are prohibited for TI-2 and TI-3 environments.

**Rationale**  
Shared identities among many instances defeat fine-grained attribution and revocation: compromising any one instance yields a credential valid everywhere. Per-instance identities allow precise scoping of privileges, targeted revocation for compromised instances, and accurate forensic attribution.

**Implementation Notes**  
- Issue short-lived, per-instance credentials during deployment or launch, tied to that instance’s metadata (for example, pod UID, VM ID).  
- Avoid static, long-lived service accounts used by all instances of a service.  
- Ensure monitoring and audit logs record which instance identity was used for each action.  
- Implement automated clean-up of instance identities upon termination of the corresponding artifact.  

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory  

---

#### 3.12.6 (ID-06) ATLAS-ID-PRIVILEGE-CEILING — Privilege Ceilings

Each identity MUST have a clearly defined maximum possible privilege boundary (ceiling) beyond which authority cannot be granted, even via emergency policy changes or human request. Attempts to grant privileges beyond an identity’s configured ceiling MUST fail closed and generate security-relevant telemetry for TI-2 and TI-3 systems.

**Rationale**  
Without ceilings, privileges can expand ad hoc over time, especially under operational pressure, leading to “temporary” exceptions that become permanent. Attackers exploit such creep to turn low-privilege identities into effective super-admins. Privilege ceilings enforce structural limits and create predictable upper bounds on damage.

**Implementation Notes**  
- Define privilege classes (for example, H0–H3) with explicit ceiling constraints per class.  
- Configure IAM and authorization systems so that policy definitions cannot exceed the maximum role or scope allowed for each identity class.  
- Require issuance of new identities under higher classes when legitimate needs exceed the current ceiling, with full governance review.  
- Log all failed attempts to exceed ceilings as potential misconfiguration or malicious activity.  

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory  

---

#### 3.12.7 (ID-07) ATLAS-ID-DELEGATION-CEILING — Delegation Ceilings

Delegations from one identity to another MUST NEVER grant authority exceeding that of the originating identity. Delegation MUST always reduce or constrain capability, narrowing scope, duration, or privilege. Delegation that expands authority or creates a peer with equal or higher privileges than the delegator is prohibited in TI-2 and TI-3 environments.

**Rationale**  
Delegation is frequently misused to “bootstrap” more powerful identities or to create shadow-admin accounts. If delegations can elevate authority, the delegation mechanism itself becomes a privilege escalation vector. Constraining delegation to be strictly downward or lateral-with-reduction prevents identity graphs from drifting into uncontrolled hierarchies.

**Implementation Notes**  
- Implement delegation mechanisms that require specifying reduced scopes (for example, subset of resources, shorter lifetimes, fewer roles).  
- Enforce checks that compare delegated scopes against the delegator’s ceiling and current privileges.  
- Represent delegations as explicit, signed objects referencing both origin and delegate identities and their respective scopes.  
- Periodically review delegations for overreach and prune or tighten them as necessary.  

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory  

---

#### 3.12.8 (ID-08) ATLAS-ID-NO-HORIZONTAL-ESC — No Horizontal Privilege Escalation

Identities MUST NOT assume the privileges, roles, or credentials of sibling identities, even within the same trust domain. Lateral privilege escalation – for example, one service account using another service’s credentials, or one tenant’s identity operating as another tenant’s identity – is prohibited for TI-2 and TI-3 systems. Any detected horizontal adoption MUST be treated as a security incident.

**Rationale**  
Most multi-tenant and multi-service compromises proceed laterally rather than vertically: once inside, attackers move sideways to equivalent identities with different data access. If systems allow identities to masquerade as peers, containment boundaries within domains collapse. Blocking horizontal escalation preserves compartmentalisation and makes compromise scope easier to reason about.

**Implementation Notes**  
- Configure IAM and token systems so identities cannot request tokens or credentials for siblings.  
- Enforce tenant and service boundaries at identity-issuance and token-exchange points.  
- Monitor for unusual identity usage, such as Identity A presenting tokens normally used only by Identity B.  
- Treat cross-service or cross-tenant credential re-use as a high-severity signal requiring investigation.  

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory  

---

#### 3.12.9 (ID-09) ATLAS-ID-NO-IMPERSONATION — No Identity Substitution

Governed identities MUST NOT impersonate, forward, proxy, or alias other identities at the protocol or application layer without explicit, tightly bounded delegation mechanisms. Behavioural impersonation – where actions are recorded as if performed by a different principal – MUST be treated as a security incident in TI-2 and TI-3 environments. Where impersonation is required (for example, user delegation to support staff), it MUST be explicit, logged, and scope-limited.

**Rationale**  
Opaque impersonation collapses accountability: logs show one principal, but real control lies elsewhere. Attackers exploit impersonation pathways to hide their activity behind legitimate accounts. Prohibiting substitution by default, and making necessary impersonation explicit and well-bounded, preserves the integrity of attribution.

**Implementation Notes**  
- Remove or restrict generic “run as another user” capabilities from administrative tools and consoles.  
- Require explicit, signed delegation tokens for any legitimate impersonation, with clear actor/subject distinction in logs.  
- Ensure SIEM and audit systems can distinguish “acting as” from “is” to maintain accountability.  
- Investigate and remediate any identity reuse patterns where actions appear from multiple, inconsistent sources.  

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory  

---

#### 3.12.10 (ID-10) ATLAS-ID-EXPIRY — Mandatory Identity Expiration

All governed identities MUST have bounded lifetimes defined at issuance. Identities without explicit expiry SHALL NOT be issued for TI-2 and TI-3 workloads. Expiry MUST be enforced cryptographically (for example, via certificate validity or token TTLs) and operationally (for example, disabling accounts, rotating keys). Usage of identities beyond their expiry MUST fail closed.

**Rationale**  
Non-expiring identities accumulate risk over time: credentials leak, employees depart, services are retired, but authority persists. Attackers often rely on old, forgotten credentials that still work. Enforcing expiry limits the window in which any single credential can be abused and forces periodic review.

**Implementation Notes**  
- Set default and maximum lifetimes per identity class; use shorter lifetimes for higher privileges.  
- Ensure authentication and authorisation systems strictly enforce expiry times, with no “soft grace” in TI-2/TI-3 systems.  
- Implement renewal workflows that require re-validation of need and scope before extending identity lifetimes.  
- Periodically report on soon-to-expire and expired identities, and confirm that expired credentials no longer function.  

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory  

---

#### 3.12.11 (ID-11) ATLAS-ID-ROTATE — Rotation Requirements

Identities and associated keys MUST be rotated at defined intervals based on system criticality, key class, and threat model. Rotation MUST produce new cryptographic material and new identity lineage; simple extension of expiry without new keys is insufficient for TI-2 and TI-3 contexts. Rotation schedules MUST be documented, automated where possible, and validated through testing.

**Rationale**  
Even when no known compromise exists, long-lived keys accumulate exposure from backups, logging, and operational handling. Regular rotation reduces the payoff of long-term secret hunting and ensures that any undetected leakage eventually becomes inert. Proper rotation also exercises the organisation’s ability to update credentials without breaking systems.

**Implementation Notes**  
- Define rotation periods per key class (for example, daily for tokens, quarterly for service keys, annually for certain CAs) and enforce them through automation.  
- During rotation, ensure new keys are issued and old keys are revoked, not merely marked as “extended”.  
- Test rotation procedures regularly in lower environments and simulate failure scenarios.  
- Maintain lineage links between rotated identities so historical actions remain attributable.  

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory  

---

#### 3.12.12 (ID-12) ATLAS-ID-EPHEMERAL — Ephemeral and Short-Lived Identities

Short-lived computational tasks, such as batch jobs, ephemeral containers, serverless functions, or transient agents, MUST use ephemeral identities with automatic expiry and no reuse. Persistent, long-lived credentials SHALL NOT be issued to ephemeral workloads in TI-2 and TI-3 environments. Ephemeral identities MUST be destroyed or rendered unusable immediately after task completion.

**Rationale**  
Ephemeral workloads often run in high volume and are easy to compromise without long-term monitoring. If they carry long-lived credentials, each instance becomes a potential foothold with durable impact. Ephemeral identities that vanish with the workload minimise the residual risk and reduce the value of compromising any single transient execution.

**Implementation Notes**  
- Issue time-bounded tokens or short-lived certificates for each ephemeral execution, tied to task metadata.  
- Ensure identity lifetimes are shorter than or equal to the expected task duration and cannot be extended by the workload itself.  
- Prohibit embedding persistent keys or accounts into ephemeral runtime images.  
- Configure platforms to automatically revoke or invalidate ephemeral credentials upon completion or termination of the workload.  

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory for ephemeral workloads  
- TI-3: mandatory for ephemeral workloads  

---

#### 3.12.13 (ID-13) ATLAS-ID-REVOKE — Revocation Enforcement

When an identity is revoked, it MUST immediately lose authority across all systems where it is recognised. Revocation MUST propagate to dependent caches, sessions, and derived tokens with minimal delay. Execution or access attempts using revoked identities MUST fail closed and generate security telemetry, particularly in TI-2 and TI-3 environments.

**Rationale**  
Revocation without effective enforcement leaves revoked identities functionally active, giving a false sense of safety. Attackers leverage stale sessions, cached tokens, and slow-to-update systems to continue acting as revoked principals. Immediate, effective revocation is essential for containing compromise and enforcing lifecycle boundaries.

**Implementation Notes**  
- Implement central revocation lists or status services and integrate them into all major authn/authz paths.  
- Invalidate active sessions and cached tokens when identities are revoked, not only future authentications.  
- Measure and monitor revocation propagation latency; set SLOs for maximum acceptable delay.  
- Treat failures to enforce revocation as incidents and address gaps in architecture or integration.  

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory  

---

#### 3.12.14 (ID-14) ATLAS-ID-KEY-ENCRYPT — Encrypted Identity Storage

Key material, secrets, and credentials MUST remain encrypted at rest and protected by independent access controls from general data stores. Plaintext storage of private keys, passwords, or tokens in files, databases, code repositories, or configuration systems is prohibited for TI-2 and TI-3 environments. Decryption keys MUST be managed under separate controls from the data they protect.

**Rationale**  
Plaintext credential storage ensures that any compromise of a storage system immediately yields powerful secrets. Even partial access (for example, backup snapshots or misconfigured storage) becomes catastrophic. Encrypting identity material at rest, and separating key management from data storage, raises the bar for attackers and narrows the impact of data exposure.

**Implementation Notes**  
- Use dedicated secret management systems or HSM-backed stores for credentials, separate from general application data.  
- Ensure backups and replicas preserve encryption; do not decrypt secrets for convenience in backup workflows.  
- Audit repositories, configuration files, and infrastructure-as-code for embedded secrets and remediate promptly.  
- Enforce access controls on both the encrypted stores and key-management systems, with strong logging and monitoring.  

**Applies To:**  
- TI-1: strongly recommended  
- TI-2: mandatory  
- TI-3: mandatory  

---

#### 3.12.15 (ID-15) ATLAS-ID-NO-EMBED — No Embedded Keys in Artifacts

Private keys and other secret credentials MUST NOT be embedded in binaries, scripts, containers, models, configuration files, or source code. Any artifact found to contain embedded keys or secrets MUST be treated as compromised, invalidated for TI-2 and TI-3 use, and replaced through a clean build process. Detection of embedded secrets MUST trigger key rotation and incident handling.

**Rationale**  
Embedding secrets in artifacts makes them difficult or impossible to rotate effectively and turns every copy of the artifact into a bundled compromise kit. Attackers routinely search public repositories and container registries for such secrets. Prohibiting embedding forces identities to be injected at runtime from governed secret stores.

**Implementation Notes**  
- Integrate secret-scanning tools into build pipelines, artifact repositories, and code review processes.  
- Block promotion or deployment of artifacts that fail secret-scanning checks.  
- When embedded keys are discovered, revoke the affected keys immediately, rebuild artifacts without embedded secrets, and investigate distribution scope.  
- Educate developers and operators on proper separation between code and credentials.  

**Applies To:**  
- TI-1: mandatory for governed artifacts  
- TI-2: mandatory  
- TI-3: mandatory  

---

#### 3.12.16 (ID-16) ATLAS-ID-NO-KEY-TRANSFER — No Cross-Domain Private Key Transport

Private keys for governed identities SHALL NOT be transmitted or copied between trust domains. Each domain MUST generate and manage its own private keys locally. Cross-domain trust MUST be established through federation, shared trust anchors, or cross-signing, not by importing private keys from one domain into another.

**Rationale**  
Moving private keys between domains multiplies the number of environments that can leak or misuse them and makes it unclear which domain “owns” the security responsibility. Cross-domain key transport also breaks the assumption that compromise in one domain does not directly compromise another. Federation allows domains to interoperate without diluting isolation.

**Implementation Notes**  
- Prohibit export of private keys from HSMs, KMS, and secure key stores across domain boundaries.  
- Use cross-signing or mutual trust of CAs rather than copying root or intermediate keys into other organisations or regions.  
- For multi-region or multi-cloud setups, generate distinct keys per domain and link them through trust policy.  
- Regularly review key inventories to ensure no private keys are shared between domains.  

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory  

---

#### 3.12.17 (ID-17) ATLAS-ID-MEM-SCRUB — Memory Scrubbing

Key material and sensitive credentials loaded into memory MUST be erased as soon as practical after use. Execution environments and supporting libraries MUST actively zeroise buffers, stack frames, and key-bearing regions rather than relying on garbage collection or process termination to clear secrets for TI-2 and TI-3 workloads.

**Rationale**  
Residual secrets in memory are a frequent target for memory scraping, crash dump analysis, cold-boot attacks, and side-channel exploits. If memory is not deliberately scrubbed, secrets may persist far longer than necessary, multiplying the opportunity for theft. Active scrubbing narrows the time window during which in-memory secrets can be harvested.

**Implementation Notes**  
- Use cryptographic and security libraries that offer secure memory handling primitives and explicit zeroisation APIs.  
- Avoid copying secrets between many buffers or storing them in immutable or un-scrubbable memory structures.  
- Configure systems to avoid including raw secrets in core dumps, stack traces, or debug logs.  
- Periodically test that memory-scrubbing mechanisms work as expected (for example, by examining dumps in controlled test environments).  

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory  

---

#### 3.12.18 (ID-18) ATLAS-ID-MULTIPART — Multi-Part Keys for High-Privilege Identities

High-privilege identities (for example, root CAs, master signing keys, global control-plane operators) MUST use threshold cryptography, multi-signature schemes, or split-key storage so that no single individual or system can unilaterally exercise full authority. Operations requiring these identities MUST involve quorum-based participation according to policy.

**Rationale**  
Single-party control over extremely powerful keys introduces catastrophic insider and compromise risk. A single error or compromise can affect entire organisations or ecosystems. Multi-part keys distribute control, making accidental misuse or covert abuse much harder.

**Implementation Notes**  
- Implement threshold schemes (for example, m-of-n signing) for top-tier keys, with shares held by independent custodians.  
- Use secure key-sharing protocols and HSM features to store key shares without revealing full private keys to any one party.  
- Define clear procedures for quorum operations, including emergency processes and audits.  
- Regularly test that quorum mechanisms function and that shares can be combined only under intended conditions.  

**Applies To:**  
- TI-1: recommended for critical roots  
- TI-2: mandatory for H3-level identities  
- TI-3: mandatory for H2+ identities  

---

#### 3.12.19 (ID-19) ATLAS-ID-TI-EVIDENCE — TI-3 Evidence for Identity Actions

Issuance, rotation, revocation, delegation, and privilege-ceiling changes for governed identities MUST generate TI-3 forensic evidence bound to identity lineage. These records MUST be tamper-evident, time-stamped with trusted authorities, and retained according to organisational and regulatory requirements.

**Rationale**  
Identity lifecycle events are among the most important signals in understanding how authority is granted, used, and withdrawn. Without durable, high-integrity records of these actions, post-incident investigations and compliance reviews may be impossible to complete reliably. Treating identity lifecycle events as TI-3 evidence ensures long-term accountability.

**Implementation Notes**  
- Log all identity lifecycle operations (create, update, rotate, delegate, revoke, terminate) to WORM or chain-anchored evidence stores.  
- Include in evidence: actor identity, approvals, justification, scopes, ceilings, timestamps, and relevant trust roots.  
- Integrate identity-management systems with central evidence pipelines rather than relying on local logs alone.  
- Provide secure, verifiable export of identity evidence for audits, investigations, and cross-domain reviews.  

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory  

---

#### 3.12.20 (ID-20) ATLAS-ID-LINEAGE — Identity Lineage Continuity

Identity lineage MUST remain intact across rotations, updates, and delegated uses. Where lineage is broken or cannot be demonstrated (for example, due to missing records or inconsistent identifiers), the affected identity MUST be treated as a new identity with no inherited trust. Lineage MUST allow reconstruction of which prior keys and privileges are associated with a given principal over time.

**Rationale**  
Without clear lineage, it is impossible to answer basic questions such as “who had this access when?” or “which key was used for this action?”. Attackers benefit from lineage gaps, which can conceal long-running abuses or misconfigurations. Maintaining continuity ensures that historical evidence remains interpretable even as keys and attributes change.

**Implementation Notes**  
- Assign stable principal identifiers distinct from key material or concrete credentials.  
- For each rotation or update, record explicit links between old and new credentials for the same principal.  
- Include lineage identifiers in tokens and audit logs to connect actions to evolving identities.  
- When lineage gaps are discovered, treat the impacted identities as suspect and consider re-issuance under clean lineage.  

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory  

---

#### 3.12.21 (ID-21) ATLAS-ID-DELEGATION-TRACE — Delegation Traceability

Delegations MUST be traceable back to their origin identities through cryptographic audit trails. Each delegation record MUST identify the delegator, the delegate, the delegated scope, and the timeframe. Delegation SHOULD NOT occur without lineage binding that preserves attribution across chains of delegation.

**Rationale**  
Delegation graphs can become complex, especially in large organisations and agentic systems. Without clear traceability, it may be impossible to determine who ultimately authorised a given action. Attackers can hide in long delegation chains to obscure responsibility. Strong traceability keeps the delegation structure transparent and auditable.

**Implementation Notes**  
- Represent delegations as signed tokens or objects that reference the delegator’s identity and lineage ID.  
- Log delegation issuance, updates, and revocations as TI-2 or TI-3 events, depending on scope.  
- Provide tooling to traverse delegation graphs and answer questions like “who gave this identity its rights?”.  
- Limit delegation-chain length to prevent overly complex and opaque structures.  

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory for privileged delegations  
- TI-3: mandatory  

---

#### 3.12.22 (ID-22) ATLAS-ID-RUNTIME-BOUND — Runtime Binding to Execution Identity

Execution MUST occur strictly under the declared execution identity for a workload, process, or session. Runtime systems SHALL NOT silently switch identities, merge identities, or attach new privileges without explicit, governed operations. Attempts to operate outside the declared execution identity MUST be blocked for TI-2 and TI-3 workloads.

**Rationale**  
If runtime can freely change identities underneath policy, logs and provenance no longer describe actual execution. Attackers exploit such flexibility to perform actions under identities that appear unrelated to their initial foothold. Binding execution tightly to declared identities preserves the integrity of attribution and policy reasoning.

**Implementation Notes**  
- Ensure that OS-level and platform-level mechanisms (for example, `setuid`, token exchange APIs) are controlled and audited.  
- Use execution wrappers or sidecars that validate that runtime identity matches declarations from deployment manifests.  
- Prohibit dynamic changes of user IDs, groups, or principals inside long-running processes unless explicitly required and governed.  
- Treat unexpected identity changes during a session as high-severity anomalies.  

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory  

---

#### 3.12.23 (ID-23) ATLAS-ID-NO-DYNAMIC-ADOPT — No Dynamic Adoption of Identities

Governed workloads and agents SHALL NOT obtain, switch, or assume new identities dynamically at runtime beyond those declared and approved at deployment. Attempts to adopt identities outside the pre-declared set (for example, by requesting arbitrary tokens or credentials) MUST fail closed and be logged as security events in TI-2 and TI-3 environments.

**Rationale**  
Dynamic adoption of identities allows workloads to cross boundaries and expand privileges in ways not accounted for by deployment-time analysis. Attackers exploit token-request interfaces and misconfigured identity providers to move from low-privilege to high-privilege identities. Restricting adoption to predetermined, governed paths prevents such opportunistic escalation.

**Implementation Notes**  
- Configure identity providers so applications can only obtain tokens for their own identities or tightly scoped delegates.  
- Enforce static allowlists of permissible identity transitions per workload.  
- Monitor calls to token and credential services for requests that deviate from expected patterns.  
- Treat successful acquisition of undeclared identities as an incident requiring immediate containment and root-cause analysis.  

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory  

---

#### 3.12.24 (ID-24) ATLAS-ID-BUILD-ISOLATION — Identity Isolation from Build Systems

Build pipelines and CI systems MUST NOT issue runtime identities or sign runtime tokens for governed environments. Identity issuance MUST occur through independent trust-governance systems, separate from build infrastructure. Build systems MAY request temporary credentials limited to build operations but MUST NOT act as authorities for production identity.

**Rationale**  
If build systems can mint or sign runtime identities, compromise of CI infrastructure becomes equivalent to compromise of the entire runtime trust fabric. Separation of concerns ensures that each compromise domain has bounded impact and that build compromises cannot directly forge long-lived runtime authority.

**Implementation Notes**  
- Remove or disable production identity-issuance capabilities from CI/CD environments.  
- Provide build systems with narrowly scoped identities for fetching dependencies, pushing artifacts, and interacting with registries.  
- Use out-of-band approval and signing mechanisms for runtime identities (for example, through dedicated PKI or IAM systems).  
- Audit build infrastructure for keys and certificates that appear to be runtime or production identities, and migrate them out.  

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory  

---

#### 3.12.25 (ID-25) ATLAS-ID-NO-DIRECT-HUMAN-MINT — Humans Cannot Directly Mint High-Privilege Identities

Human operators SHALL NOT unilaterally mint identities above defined privilege thresholds (for example, high-scope admin, CA, or control-plane identities). Issuance of high-privilege identities MUST be mediated by governed systems that enforce policy, approval workflows, and multi-party controls. Direct manual creation of such identities is prohibited for TI-2 and TI-3 systems.

**Rationale**  
Manual creation of powerful identities is error-prone and susceptible to coercion, insider threats, and poor record-keeping. Even well-intentioned emergency actions can introduce uncontrolled privileges that persist indefinitely. Mediated minting ensures that policy and oversight are applied consistently.

**Implementation Notes**  
- Define privilege thresholds above which automatic controls and multi-party approvals are required.  
- Route all requests for high-privilege identities through identity-governance platforms with enforced workflows.  
- Restrict direct access to key-generation tools and admin consoles so that humans cannot bypass governance paths.  
- Periodically review all high-privilege identities to confirm that their issuance path complied with policy.  

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory for H2+  
- TI-3: mandatory  

---

#### 3.12.26 (ID-26) ATLAS-ID-MULTIROOT-ISSUE — Multi-Root Issuance for Privileged Identities

Issuance of identities with broad or systemic scope (for example, cross-tenant admin, global signing keys, root CAs) MUST require multi-party approval anchored in separate trust roots or organisational roles. No single trust root or individual may authorise such identities unilaterally in TI-2 and TI-3 environments.

**Rationale**  
Centralising authority for powerful identities in a single root or role creates single points of catastrophic failure. An attacker who compromises that one element gains global control. Multi-root issuance distributes trust and requires collusion or multiple compromises to issue or alter systemic identities.

**Implementation Notes**  
- Implement workflows that require approvals from independent organisational units (for example, security, operations, compliance) for high-scope identities.  
- Use technical enforcement (for example, multi-signature certificates, split issuance) so that issuance is impossible without all required approvals.  
- Log all steps in multi-root issuance workflows as TI-3 evidence.  
- Perform periodic audits of high-scope identities to ensure their issuance history reflects multi-root approval.  

**Applies To:**  
- TI-1: recommended for systemic identities  
- TI-2: mandatory for cross-tenant/systemic identities  
- TI-3: mandatory  

---

#### 3.12.27 (ID-27) ATLAS-ID-EVIDENCE-ON-ISSUE — Issuance MUST Generate Forensic Evidence

Every identity issuance event – including low-privilege identities in TI-2/TI-3 environments – MUST generate forensic evidence suitable for TI-3 storage. Evidence MUST record requester, approvers, trust root, intended scope, privilege ceiling, expiry, and any associated delegations. Issuance records MUST be immutable and retained according to risk and regulatory requirements.

**Rationale**  
Issuance is the moment when trust is conferred. If these moments are not recorded with sufficient integrity and detail, later questions about how an identity came to exist cannot be answered. Attackers and negligent insiders rely on undocumented identities that appear “out of nowhere”. Forensic-grade issuance evidence closes this gap.

**Implementation Notes**  
- Integrate identity-governance systems with TI-3 evidence stores for all issuance actions.  
- Include cross-references from issuance records to associated artifacts, services, or users.  
- Make issuance evidence searchable by identity, principal, date range, and scope to support investigations.  
- Ensure issuance evidence is accessible to relevant oversight functions (for example, internal audit, security, compliance) under appropriate controls.  

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory  

---

#### 3.12.28 (ID-28) ATLAS-ID-NO-CROSS-IMPORT — No Import of External Private Keys

External private keys from third parties, partners, vendors, or customers SHALL NOT be imported into governed environments for use as local identities. Trust MUST be bridged via federation, cross-signing, or dedicated interop mechanisms, not by transplanting external keys into internal trust roots. Where external keys must be verified (for example, validating signatures), verification MUST occur without copying those keys into local key stores.

**Rationale**  
Importing external keys blurs responsibility and weakens both external and internal security postures. If internal systems hold copies of external keys, compromise of internal infrastructure may directly compromise external ecosystems. Federation preserves trust relationships while keeping each domain accountable for its own private material.

**Implementation Notes**  
- Configure systems to accept and validate external credentials (for example, certificates, tokens) without storing or reusing their private components.  
- Use trust policies that recognise and validate external trust roots rather than copying their private keys.  
- Reject proposals or integrations that require third parties to hand over their private keys for “simplified management”.  
- Periodically verify that internal key inventories contain only keys generated and governed within the local domain.  

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory  

---

#### 3.12.29 (ID-29) ATLAS-ID-DOMAIN-SCOPING — Identity Scoping to Single Trust Domain

Each governed identity MUST be scoped to exactly one trust domain. Cross-domain operations MUST use separate identities per domain, even when representing the same underlying principal. Single identities spanning multiple domains (for example, one certificate valid across multiple unrelated administrative zones) are prohibited for TI-2 and TI-3 workloads.

**Rationale**  
Multi-domain identities make it difficult to apply domain-specific policies, revoke access selectively, or understand where a compromise originated. Attackers benefit because a single stolen credential lets them roam across domains. Domain-scoped identities keep each domain’s risks and controls distinct.

**Implementation Notes**  
- Use domain-specific namespaces or issuer identifiers when constructing identities.  
- For principals that operate in multiple domains, issue separate identities and manage relationships at a higher logical layer.  
- Ensure revocation, rotation, and evidence are tracked per domain-specific identity rather than globally.  
- Audit for identities that appear in multiple domains and refactor them into domain-scoped identities.  

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory  

---

#### 3.12.30 (ID-30) ATLAS-ID-NO-REUSE — Non-Reusability After Termination

Once an identity is terminated, it MUST NOT be resurrected, reassigned, or reused for a different principal, workload, or purpose. Termination MUST be final and enforced by trust anchors and identity-management systems. Any attempt to reissue an identity with the same identifiers (for example, subject names, IDs) MUST be treated as a new identity with fresh lineage and recorded as such.

**Rationale**  
Reusing identities – for example, reassigning a user account to a new employee or reusing a service principal name – causes historical records to conflate actions by different principals. Attackers exploit this confusion to hide their activity or to gain access under the guise of legitimate turnover. Non-reusability preserves the semantic integrity of identity histories.

**Implementation Notes**  
- Mark terminated identities as permanently retired in identity stores, preventing recreation with the same identifiers.  
- Use unique, never-recycled identifiers (for example, GUIDs) as the primary keys for identities, even if human-readable names change.  
- When a similar identity is needed for a new principal, create a fresh identity with new identifiers and lineage.  
- Reflect non-reusability in documentation and training so operators do not treat identity “slots” as reusable resources.  

**Applies To:**  
- TI-1: recommended  
- TI-2: mandatory  
- TI-3: mandatory  

---

---

### 3.13 Data Classification, Boundary Enforcement, and Deterministic Handling Controls (ATLAS-DATA)

Data MUST maintain governed classification, enforced boundaries, immutable provenance lineage, and identity-scoped access constraints across its entire lifecycle. Controls in this section define the deterministic handling of all data under ATLAS-DESS, ensuring no implicit privilege, uncontrolled propagation, or cross-domain leakage occurs.


#### 3.13.1 (DATA-01) ATLAS-DATA-CLASSIFY — Mandatory Classification on Ingestion

All data entering any trust domain MUST be assigned a governed classification including: sensitivity level, domain, lineage source, scope of use, cryptographic protections required, and retention bounds. Unclassified data MUST NOT be persisted, processed, or forwarded to downstream systems.

**Why this exists (Non-Normative Rationale)**  
Unclassified data creates blind spots in enforcement and allows implicit escalation in automated systems.

**Implementation Notes (Non-Normative)**  
- Classification MUST occur before storage or transformation.  
- For AI pipelines, classification MUST reflect dataset-of-origin, not derived model interpretation.

**Applies To:** TI-2 (mandatory), TI-3 (mandatory)


#### 3.13.2 (DATA-02) ATLAS-DATA-NO-UNBOUND — No Execution Without Boundaries

Execution environments MUST reject data without a declared classification boundary. Workflows MUST NOT assume default or inherited boundaries. Any unbounded data input MUST halt execution.

**Rationale (Non-Normative)**  
"Unknown" or "raw" data enables uncontrolled propagation and privilege inflation.

**Implementation Notes**  
- Reject execution when classification metadata is absent.  
- Boundary tagging MUST persist through all transformation stages.

**Applies To:** TI-2, TI-3


#### 3.13.3 (DATA-03) ATLAS-DATA-PROVENANCE — Immutable Provenance Lineage

All data MUST maintain a cryptographically verifiable provenance chain linking its origin, transformations, upstream identities, and domain boundaries. Any break, corruption, or ambiguity MUST invalidate the dataset.

**Rationale**  
Lineage collapse enables replay, impersonation, and cross-domain exfiltration.

**Implementation Notes**  
- Hash-chain versioning MUST be applied.  
- Provenance MUST be anchored in evidence sinks (Section 3.16).

**Applies To:** TI-3 required  


#### 3.13.4 (DATA-04) ATLAS-DATA-NO-CROSS-SCOPE — No Implicit Scope Expansion

Access to one dataset MUST NOT imply access to related datasets, derivatives, subsets, embeddings, or logs. Scope MUST be explicitly defined for each access request.

**Rationale**  
AI-derived or relationally-linked data can implicitly broaden privilege surfaces.

**Implementation Notes**  
- Do not rely on table-level or bucket-level implicit access inheritance.  
- Identity scoping MUST be re-validated per dataset.

**Applies To:** TI-2, TI-3


#### 3.13.5 (DATA-05) ATLAS-DATA-DERIVED-INHERIT — Derived Data Inherits Highest Sensitivity

All derived, transformed, aggregated, summarized, hashed, tokenized, or AI-generated outputs MUST inherit the strictest sensitivity of all contributing sources until independently downgraded via governed attestation.

**Rationale**  
Derivatives often reveal or reconstruct sensitive attributes.

**Implementation Notes**  
- Embeddings and vector indexes inherit highest classification.  
- Downstream APIs MUST not assume reduced sensitivity.

**Applies To:** TI-3


#### 3.13.6 (DATA-06) ATLAS-DATA-NO-LOSSY-DOWNGRADE — No Downgrade via Obfuscation

Obfuscation techniques (tokenization, masking, hashing, perturbation) MUST NOT be treated as declassification. Controls MUST remain equally strict unless governed downgrade occurs.

**Rationale**  
Obfuscated data is frequently reversible with modern inference techniques.

**Implementation Notes**  
- “Hashed = safe” MUST NOT be allowed as policy.  
- Downgrade requires audit, attestation, and risk evaluation.

**Applies To:** TI-2, TI-3


#### 3.13.7 (DATA-07) ATLAS-DATA-CRYPT — Mandatory Encryption for All States

Data MUST remain encrypted at rest, in transit, and in queued or buffered states. Temporary plaintext MUST exist only in memory isolated to the authorized execution identity.

**Rationale**  
Encryption prevents unauthorized reading even in fallback or failure conditions.

**Implementation Notes**  
- Restart or crash handlers MUST not dump plaintext memory.  
- Decryption keys MUST be identity-scoped (Section 3.12).

**Applies To:** TI-2, TI-3


#### 3.13.8 (DATA-08) ATLAS-DATA-MEM-BOUND — Memory Binding to Execution Identity

Decrypted data MUST remain bound to the execution identity and MUST NOT be shared across tenants, trust domains, or identities. Copy-on-write, mmap, or other shared-memory optimization MUST NOT bypass this requirement.

**Rationale**  
Memory sharing enables cross-domain data inference.

**Implementation Notes**  
- Sandboxes MUST enforce memory isolation.  
- Shared GPU VRAM requires strict partitioning.

**Applies To:** TI-3 mandatory


#### 3.13.9 (DATA-09) ATLAS-DATA-NO-LOCAL-STORAGE — No Persistent Local Copies

Local persistence MUST be prohibited unless explicitly approved and re-classified. Temporary local buffers MUST be zeroized immediately after use.

**Rationale**  
Local persistence allows uncontrolled replication and boundary escape.

**Implementation Notes**  
- Prevent saving to `/tmp`, notebook autosaves, or IDE caches.  
- Prevent model serving systems from caching inference inputs.

**Applies To:** TI-2, TI-3


#### 3.13.10 (DATA-10) ATLAS-DATA-NO-EXPORT — Export Requires Reclassification

Data MUST NOT leave its originating trust domain without formal reclassification. Export rules MUST NOT assume equivalence between domains.

**Rationale**  
Domain equivalence assumptions are a leading cause of multi-tenant leakage.

**Implementation Notes**  
- Use egress gateways with enforcement hooks.  
- All exports MUST be logged at TI-3 fidelity.

**Applies To:** TI-2, TI-3

#### 3.13.11 (DATA-11) ATLAS-DATA-ZEROIZE — Mandatory Zeroization After Use

Decrypted data, temporary buffers, intermediate representations, embeddings, or cached inference inputs MUST be zeroized immediately after use or upon error conditions. Zeroization MUST occur even when the workflow terminates abnormally, including panics, faults, or forced shutdowns.

**Rationale (Non-Normative)**  
Residual plaintext in memory is a primary source of unintended lateral disclosure and cross-boundary inference.

**Implementation Notes (Non-Normative)**  
- GPU VRAM, CPU RAM, enclave memory, and shared accelerators all require explicit zeroization APIs.  
- Crash handlers MUST guarantee zeroization before emitting logs or evidence.  
- Memory reclamation MUST NOT rely on garbage collection alone.

**Applies To:** TI-3 (mandatory), TI-2 (mandatory)


#### 3.13.12 (DATA-12) ATLAS-DATA-BUFFER-ISOLATION — Isolation of All Data Buffers

Data buffers—including intermediate tensors, batch preprocessors, token sequences, stream chunks, or GPU kernel outputs—MUST be isolated from all other workloads. Shared buffers MUST be cryptographically segregated and scoped to the execution identity.

**Rationale**  
Implicit buffer sharing enables boundary bypass and inference leakage in concurrent systems.

**Implementation Notes**  
- Disable mmap-based shared regions unless domain-partitioned.  
- Ensure GPU compute frameworks enforce buffer tagging.

**Applies To:** TI-3


#### 3.13.13 (DATA-13) ATLAS-DATA-ACCESS-AUDIT — Access Must Produce TI-3 Evidence

Every data access event MUST emit cryptographically signed TI-3 evidence including identity, domain, data classification, timestamp, requested operation, and lineage pointer. Missing evidence MUST invalidate future access.

**Rationale**  
Deterministic traceability prevents repudiation and enables forensic reconstruction.

**Implementation Notes**  
- Evidence sinks MUST be append-only (Section 3.16).  
- Access tokens MUST be linked to domain-bound identities.

**Applies To:** TI-2, TI-3


#### 3.13.14 (DATA-14) ATLAS-DATA-FEDERATION — Federation Requires Local Enforcement

Federated access MUST enforce local classification, local boundaries, and local enforcement ceilings. Remote policies MUST NOT be accepted as sufficient. Federation MUST NOT permit privilege expansion or classification downgrade.

**Rationale**  
Federated assumptions create gaps when enforcement differs between domains.

**Implementation Notes**  
- Always recompute classification locally.  
- Reject attempts to “inherit” remote classification.

**Applies To:** TI-3 mandatory


#### 3.13.15 (DATA-15) ATLAS-DATA-NO-TEMP-CACHE — No Implicit Caching of Sensitive Data

Systems MUST NOT implicitly cache data for performance. Any attempt to cache sensitive data (in RAM, VRAM, SSD, CPU buffers, object stores, or model intermediate caches) MUST require explicit classification-aware approval.

**Rationale**  
Implicit caches silently create duplicate ungoverned data copies.

**Implementation Notes**  
- Prevent model serving frameworks from keeping past requests in memory.  
- Caches MUST adhere to classification rules and zeroization.

**Applies To:** TI-2, TI-3


#### 3.13.16 (DATA-16) ATLAS-DATA-HASH-CHAIN — Hash-Chain Integrity for All Data States

Each modification, transformation, or version of data MUST be append-only and representable as part of a cryptographically verifiable hash chain. Any break invalidates downstream usage.

**Rationale**  
Hash chains enforce tamper-evident lineage.

**Implementation Notes**  
- Pair with TI-3 evidence for forensic recovery.  
- Hash chain MUST be domain-scoped to prevent cross-tenant entanglement.

**Applies To:** TI-3


#### 3.13.17 (DATA-17) ATLAS-DATA-NONREPUD — Non-Repudiation of Data Use

Every data operation MUST bind identity, domain, intended use, and execution environment to ensure no party can deny requesting, transforming, or consuming data.

**Rationale**  
Repudiation undermines accountability and incident response.

**Implementation Notes**  
- Sign all access artifacts with identity-scoped keys.  
- Store evidence in immutable WORM sinks.

**Applies To:** TI-2, TI-3


#### 3.13.18 (DATA-18) ATLAS-DATA-KEY-ROTATE — Classification Changes Require Key Rotation

Any classification change, data boundary expansion, trust-domain shift, or access downgrade MUST trigger immediate key rotation. Downstream caches MUST be invalidated.

**Rationale**  
Key reuse across classification changes allows lateral access.

**Implementation Notes**  
- Rotate keys on every domain or sensitivity shift.  
- Re-encrypt downstream datasets proactively.

**Applies To:** TI-3


#### 3.13.19 (DATA-19) ATLAS-DATA-NO-CHAIN-LEAK — Prevent Cross-Lineage Mixing

Datasets from distinct provenance chains MUST NOT be merged, co-trained, co-indexed, or cross-referenced unless governed reclassification explicitly approves it.

**Rationale**  
Cross-lineage mixing breaks provenance, complicates incident response, and enables inference leakage.

**Implementation Notes**  
- Reject multi-source merges without lineage re-attestation.  
- Vector indexes MUST reflect lineage partitioning.

**Applies To:** TI-3 mandatory


#### 3.13.20 (DATA-20) ATLAS-DATA-RESCOPE — Rescoping Requires Fresh Attestation

Before data is used in a new workload, execution domain, model training cycle, or analytical pipeline, classification and identity scoping MUST be re-attested. Prior approvals MUST NOT carry over.

**Rationale**  
Preventing privilege drift requires scope revalidation.

**Implementation Notes**  
- Implement domain-scoped rescoping gates.  
- Ensure rescoping emits TI-3 evidence with lineage pointers.

**Applies To:** TI-2, TI-3

#### 3.13.21 (DATA-21) ATLAS-DATA-TIMEBOUND — Time-Bound Data Validity

All data MUST be treated as time-bound. Expiry windows MUST be encoded in classification metadata. Once expired, data MUST NOT be processed, copied, cached, re-trained, or re-evaluated without fresh classification and attestation. Expired data MUST fail closed.

**Rationale (Non-Normative)**  
Time-based attacks leverage stale data, previously valid tokens, or outdated lineage to bypass controls.

**Implementation Notes (Non-Normative)**  
- Embed expiry metadata in provenance hashes and identity tokens.  
- Expiry enforcement must occur before model inference, training, or downstream analytics.  
- Expiry MUST be tied to both absolute time and maximum lineage age.

**Applies To:** TI-2, TI-3


#### 3.13.22 (DATA-22) ATLAS-DATA-AI-INHERIT — AI Outputs Inherit Input Sensitivity

All AI outputs—including logits, embeddings, vector indexes, gradients, activations, summaries, synthetic data, and inference metadata—MUST inherit the highest sensitivity of their inputs. Inheritance MUST remain until explicit governed downgrade occurs.

**Rationale**  
AI transformations do not reduce risk; they often amplify reconstructability.

**Implementation Notes**  
- Embeddings MUST be classified equal to or higher than originals.  
- Vector indices MUST be domain-scoped.  
- Model logs and inference traces MUST inherit input classification.

**Applies To:** TI-3 mandatory


#### 3.13.23 (DATA-23) ATLAS-DATA-PIPELINE-ISOLATION — Training and Inference Pipeline Isolation

Training pipelines MUST NOT share identities, memory, intermediate tensors, caches, or feature stores with inference pipelines. Boundaries MUST remain cryptographically enforced and identity-scoped.

**Rationale**  
Training data often contains sensitive raw information not permissible in inference contexts.

**Implementation Notes**  
- Separate keyrings and identity roles for training vs inference.  
- No shared GPU memory pools without domain partitioning.  
- Prevent models from caching inference requests for retraining purposes.

**Applies To:** TI-3


#### 3.13.24 (DATA-24) ATLAS-DATA-TOKENIZATION-NO-EXPORT — Tokenization Does Not Permit Export

Tokenized, pseudonymized, masked, or hashed data MUST NOT be exported across trust domains unless fully reclassified. Tokenization MUST NOT weaken or reduce the classification level of the original dataset.

**Rationale**  
Tokenization is frequently reversible using correlation attacks, embeddings, or statistical inference.

**Implementation Notes**  
- Export gateways MUST reject tokenized-only downgrade attempts.  
- Use explicit downgrade workflows with additional evidence requirements.

**Applies To:** TI-2, TI-3


#### 3.13.25 (DATA-25) ATLAS-DATA-SHARED-STATE-BLOCK — Prohibit Implicit Shared State

Systems MUST NOT place data into shared global state without cryptographic tenant/domain partitioning. Implicit shared state (e.g., caches, KV stores, GPU buffers, analytic layers) MUST be blocked unless explicitly governed.

**Rationale**  
Global state collapses boundaries and enables cross-domain inference.

**Implementation Notes**  
- Per-tenant or per-domain encryption layers MUST wrap all shared state.  
- No memcached/Redis/global KV without scoped partitions.

**Applies To:** TI-2, TI-3


#### 3.13.26 (DATA-26) ATLAS-DATA-INFERRED-SENSITIVITY — Sensitivity Propagation for Inferred Data

Any inferred, generated, deduced, aggregated, or statistically estimated data MUST inherit the strictest classification of its contributing sources. Propagation MUST be enforced automatically.

**Rationale**  
Inference can reveal original sensitive traits even after transformations.

**Implementation Notes**  
- Analytical outputs MUST embed source sensitivity metadata.  
- Model explanations, SHAP values, or attention maps MUST follow propagation rules.

**Applies To:** TI-3 mandatory


#### 3.13.27 (DATA-27) ATLAS-DATA-DERIVATIVE — Derivatives Cannot Escape Original Controls

Data derivatives, including logs, summaries, embeddings, synthetic samples, or metadata structures, MUST NOT escape original controls simply by changing form. Controls MUST remain equivalent or stricter.

**Rationale**  
Attackers often exploit derivative formats to bypass controls.

**Implementation Notes**  
- Treat all model internals as classified data.  
- Store metadata derivatives using equivalently strong policies.

**Applies To:** TI-2, TI-3


#### 3.13.28 (DATA-28) ATLAS-DATA-BOUND-TO-IDENTITY — Identity-Scoped Decryption and Use

Decryption or access MUST be tied to an execution identity and MUST NOT grant portable plaintext. Plaintext MUST NOT persist across identity change, lateral domain switch, session renewal, or workload migration.

**Rationale**  
Identity-bound data prevents reuse, replay, impersonation, and session hijacking.

**Implementation Notes**  
- Rotate session keys on identity switch.  
- Enforce identity-scoped ephemeral key derivation.

**Applies To:** TI-3


#### 3.13.29 (DATA-29) ATLAS-DATA-REPLAY-IMMUNITY — Immunity to Replay of Past Access

Past valid access events MUST NOT grant future access. Replay of cached tokens, lifted session identifiers, or previously valid lineage proofs MUST be rejected automatically.

**Rationale**  
Replay attacks occur when old permissions remain implicitly trusted.

**Implementation Notes**  
- Enforce tight timestamp windows (Section 3.21).  
- Store nonce + identity + lineage linkage for all access events.

**Applies To:** TI-2, TI-3


#### 3.13.30 (DATA-30) ATLAS-DATA-BREACH-INVALIDATE — Breach Invalidates Data and Keys

If data escapes boundary, lineage breaks, classification metadata is corrupted, or unauthorized domains gain exposure, the data MUST be treated as compromised. All associated keys MUST rotate and downstream datasets MUST be revalidated before further use.

**Rationale**  
Boundary breaches create cascading compromise unless data and keys are invalidated.

**Implementation Notes**  
- Auto-rotate all keys associated with compromised data.  
- Quarantine affected lineage trees until reclassification.  
- Require TI-3 forensic evidence before restoring access.

**Applies To:** TI-3 mandatory

---

### 3.14 Execution Sandbox and Process Isolation Controls (ATLAS-RUNISO)

Execution environments MUST enforce strict, non-bypassable, cryptographically verifiable sandbox boundaries that constrain system calls, memory access, device interaction, network egress, privilege ceilings, and process identity. Runtime surfaces MUST remain deterministic, isolated, and fail-closed under all fault conditions.

These controls apply to all compute surfaces including containers, VMs, enclaves, interpreters, compilers, GPU workloads, distributed execution frameworks, and AI inference runtimes.


#### 3.14.1 (RUNISO-01) ATLAS-RUNISO-LOCALITY — Localized Execution Scope

Execution MUST be restricted to a declared sandbox with explicit resource boundaries including filesystem, network, memory, device access, and environment variables. Any attempt to operate outside declared locality MUST fail closed.

**Rationale (Non-Normative)**  
Locality violations are the most common escape vector for container, VM, and enclave bypass.

**Implementation Notes**  
- Sandbox boundaries MUST be validated pre-execution.  
- Attempted access to undeclared files, sockets, or devices MUST generate TI-3 evidence.  
- Locality MUST be enforced even when workloads self-mutate.

**Applies To:** TI-2, TI-3


#### 3.14.2 (RUNISO-02) ATLAS-RUNISO-SYS-EGRESS — Restricted Syscall Surface

Only explicitly whitelisted syscalls MAY be invoked by the runtime. Dynamic syscall invocation, kernel passthrough, or adaptive syscall expansion MUST be prohibited.

**Rationale**  
Syscall surfaces define the security boundary of operating systems; uncontrolled access leads directly to privilege escalation.

**Implementation Notes**  
- Use seccomp-like enforcement for Linux-class environments.  
- Syscall tables MUST be hashed and attested at runtime.

**Applies To:** TI-3 mandatory


#### 3.14.3 (RUNISO-03) ATLAS-RUNISO-CAP-CEILING — Enforced Capability Ceilings

Execution MUST operate under a fixed, immutable capability ceiling. Capabilities MUST NOT expand after initialization and MUST NOT be inherited from parent processes unless explicitly declared.

**Rationale**  
Dynamic capability expansion is the root cause of container breakout and lateral domain jumps.

**Implementation Notes**  
- Use minimal POSIX capability sets.  
- Token-based capability expansion MUST be rejected.

**Applies To:** TI-2, TI-3


#### 3.14.4 (RUNISO-04) ATLAS-RUNISO-NO-ESC — Prohibition of Sandbox or Host Escape

Execution MUST NOT escape the sandbox or host boundary through kernel extensions, device passthrough, namespace manipulation, or driver-level exploits. Escape attempts MUST invalidate execution immediately.

**Rationale**  
Sandbox escape is a catastrophic boundary failure.

**Implementation Notes**  
- Kernel modules MUST NOT be loadable from within workloads.  
- Device passthrough MUST require governed provisioning.

**Applies To:** TI-3 mandatory


#### 3.14.5 (RUNISO-05) ATLAS-RUNISO-NO-EXEC-STRING — No Execution of Constructed Code Strings

Execution of dynamically constructed code (eval, reflection, JIT bytecode, string-to-code compilers) MUST be prohibited in deterministic security contexts.

**Rationale**  
Dynamic code evaluation invalidates provenance and bypasses supply chain controls.

**Implementation Notes**  
- Disable eval(), exec(), Function(), reflection-based dispatch.  
- Compiled binaries MUST originate only from governed build pipelines.

**Applies To:** TI-2, TI-3


#### 3.14.6 (RUNISO-06) ATLAS-RUNISO-ENCLAVE — Mandatory Enclave Execution for High-Sensitivity Workloads

Workloads classified H2 or higher MUST execute within hardware-backed enclaves or equivalent attested environments. Software-only isolation is insufficient at these trust levels.

**Rationale**  
High-sensitivity workloads demand hardware-rooted verification and isolation.

**Implementation Notes**  
- TEEs MUST provide attestation for identity, code integrity, and configuration.  
- Enclave keys MUST be identity-scoped.

**Applies To:** TI-3 mandatory


#### 3.14.7 (RUNISO-07) ATLAS-RUNISO-MEM-BOUNDS — Enforced Memory Boundary Protections

Memory access MUST be restricted to explicitly allocated regions. Arbitrary pointer dereferencing, raw device memory mapping, or shared VRAM access across processes MUST be blocked.

**Rationale**  
Memory boundary violations enable side-channel attacks, key extraction, and data exposure.

**Implementation Notes**  
- Use hardware page protections.  
- GPU workloads MUST enforce VRAM partitioning.

**Applies To:** TI-2, TI-3


#### 3.14.8 (RUNISO-08) ATLAS-RUNISO-NO-SHARED-MEM — Prohibition on Implicit Shared Memory

Shared memory segments MUST NOT be created automatically. Any shared memory MUST be explicitly declared, identity-scoped, cryptographically partitioned, and provenance-tracked.

**Rationale**  
Implicit shared memory silently links trust domains.

**Implementation Notes**  
- /dev/shm MUST be disabled or partitioned.  
- Mmap regions must include domain-scoped encryption overlays.

**Applies To:** TI-3 mandatory


#### 3.14.9 (RUNISO-09) ATLAS-RUNISO-PROCESS-UNIQUE — Unique Identity Per Process

Each executing process MUST have a unique runtime identity. Identity reuse across concurrent processes MUST be prohibited. Identity MUST NOT be cloned, forked, or inherited at privilege level.

**Rationale**  
Identity reuse hides provenance and enables cross-process contamination.

**Implementation Notes**  
- Derive ephemeral session keys per process.  
- Identity MUST bind to runtime attestation.

**Applies To:** TI-2, TI-3


#### 3.14.10 (RUNISO-10) ATLAS-RUNISO-NO-KERNEL-PASSTHROUGH — No Direct Kernel Passthrough

User-level workloads MUST NOT directly invoke kernel code paths. All kernel interaction MUST pass through controlled syscall or enclave enforcement layers.

**Rationale**  
Direct kernel access collapses privilege boundaries and invalidates deterministic control.

**Implementation Notes**  
- Disable module loading from user space.  
- Reject unmediated ioctl calls or device-level passthrough.

**Applies To:** TI-3 mandatory

#### 3.14.11 (RUNISO-11) ATLAS-RUNISO-IMMUTABLE-CONFIG — Immutable Runtime Configuration

All runtime configuration—including mounts, namespaces, environment variables, capability sets, network routes, device bindings, and sandbox-local policies—MUST become immutable once execution begins. Post-initialization mutation MUST fail closed and produce TI-3 evidence.

**Rationale (Non-Normative)**  
Mutable configuration enables dynamic privilege escalation, namespace escape, and injection of higher-trust surfaces into running processes.

**Implementation Notes (Non-Normative)**  
- Freeze configuration and mount tables upon process start.  
- Runtime mutation attempts MUST result in forced termination.  
- Use cryptographic attestation over configuration metadata at initialization.

**Applies To:** TI-2, TI-3


#### 3.14.12 (RUNISO-12) ATLAS-RUNISO-NO-DYN-PRIV — No Dynamic Privilege Expansion

Execution MUST NOT gain additional privileges during runtime. Privilege elevation via environment changes, token injection, runtime provisioning, role-switching, credential inheritance, or process forking MUST be prohibited.

**Rationale**  
Privilege drift is a primary exploit vector enabling lateral movement and escalation.

**Implementation Notes**  
- Disable sudo/su/setuid/setcap within sandbox.  
- Temporary privileges MUST NOT be granted even during maintenance workflows.

**Applies To:** TI-3 mandatory


#### 3.14.13 (RUNISO-13) ATLAS-RUNISO-PROC-BOUNDARY — Strict Process Boundary Enforcement

Processes MUST NOT access memory pages, file descriptors, handles, semaphores, or synchronization primitives belonging to other processes except through explicitly governed interfaces. All cross-boundary interactions MUST be domain-scoped and identity-validated.

**Rationale**  
Cross-process access enables impersonation, data leakage, and coordinate bypass of sandbox restrictions.

**Implementation Notes**  
- Disable PID namespace sharing unless explicitly approved.  
- Enforce per-process memory fencing with hardware support (MPK, MTE).

**Applies To:** TI-2, TI-3


#### 3.14.14 (RUNISO-14) ATLAS-RUNISO-ATTEST — Mandatory Runtime Attestation

Execution environments handling sensitive workloads MUST support runtime attestation proving identity, integrity, configuration, and enclave/sandbox boundary state. Attestation MUST be verifiable before and during execution.

**Rationale**  
Attestation prevents running workloads from silently downgrading security posture or modifying their own runtime.

**Implementation Notes**  
- Attestation tokens MUST bind process identity, code hash, and configuration hash.  
- Attestation failures MUST terminate execution and rotate associated keys.

**Applies To:** TI-3 mandatory


#### 3.14.15 (RUNISO-15) ATLAS-RUNISO-NO-SHELL — Prohibition of Implicit Shell Access

Execution environments MUST NOT expose shell interpreters, command dispatch surfaces, or REPL entry points unless explicitly approved and identity-scoped. Shell access MUST NOT be implicitly available via embedded runtimes.

**Rationale**  
Shell access circumvents sandbox enforcement, enabling unrestricted syscalls, file access, and network traversal.

**Implementation Notes**  
- Remove `/bin/sh`, `bash`, or equivalent binaries from runtime images unless necessary.  
- Disable subprocess invocation (e.g., Python’s subprocess module) unless tightly controlled.

**Applies To:** TI-2, TI-3


#### 3.14.16 (RUNISO-16) ATLAS-RUNISO-NAMESPACE-SPLIT — Mandatory Namespace Segmentation

Filesystem, network, IPC, PID, and time namespaces MUST be isolated per execution unit unless explicitly declared and governed. Namespace merging MUST NOT occur dynamically.

**Rationale**  
Namespace sharing silently collapses process, identity, and boundary separation.

**Implementation Notes**  
- Use container/VM namespace isolation technologies.  
- Prevent automatic inheritance of host namespaces.

**Applies To:** TI-2, TI-3


#### 3.14.17 (RUNISO-17) ATLAS-RUNISO-FS-SCOPE — Filesystem Scope Restriction

Execution MAY access only explicitly declared filesystem paths. Access to host filesystem, device nodes, global mounts, kernel paths, or undeclared volumes MUST be rejected.

**Rationale**  
Filesystem overreach is a common causal factor in sandbox escape and privilege elevation.

**Implementation Notes**  
- Enforce chroot-style or container-mount root scope.  
- Prevent bind-mounts unless cryptographically scoped.

**Applies To:** TI-2, TI-3


#### 3.14.18 (RUNISO-18) ATLAS-RUNISO-NO-IPDISCOVERY — Prohibition of Dynamic Peer Discovery

Workloads MUST NOT discover new peers, hosts, or external network endpoints at runtime. All acceptable targets MUST be predeclared. Discovery attempts MUST generate TI-3 evidence and fail closed.

**Rationale**  
Dynamic peer discovery enables stealth lateral movement, command-and-control beaconing, and unbounded egress.

**Implementation Notes**  
- Disable DNS except for declared endpoints.  
- Block multicast/broadcast scans and dynamic service discovery protocols.

**Applies To:** TI-3 mandatory


#### 3.14.19 (RUNISO-19) ATLAS-RUNISO-NO-SELF-REWRITE — No Self-Modifying Execution Artifacts

Executing code MUST NOT modify its executable regions, binary images, loaded libraries, device kernels, or JIT profiles. Any attempt to self-rewrite MUST terminate execution.

**Rationale**  
Self-modifying code bypasses supply chain guarantees and provenance authenticity.

**Implementation Notes**  
- Disable writable/executable memory regions (W^X).  
- Reject hot-patching mechanisms outside governed update flows.

**Applies To:** TI-3 mandatory


#### 3.14.20 (RUNISO-20) ATLAS-RUNISO-RESOURCE-QUOTA — Deterministic Resource Ceilings

Memory, CPU, GPU, IO, thread counts, and storage ceilings MUST be explicitly declared before execution. Runtime attempts to exceed quotas MUST fail closed rather than trigger expansion or autoscaling.

**Rationale**  
Deterministic ceilings prevent runaway behavior, DoS amplification, and privilege gain via resource escalation.

**Implementation Notes**  
- Enforce hard cgroup-level ceilings.  
- Reject any runtime request to increase quotas.

**Applies To:** TI-2, TI-3

#### 3.14.21 (RUNISO-21) ATLAS-RUNISO-EXIT-BOUND — Deterministic Termination Behavior

Processes MUST terminate deterministically when encountering unrecoverable faults, policy violations, or enclave/sandbox integrity failure. Soft exits MUST emit TI-3 evidence including identity, boundary state, and last-known configuration. Hung or stalled processes MUST be force-terminated under governed rules.

**Rationale (Non-Normative)**  
Indeterminate exit states allow attackers to capture memory residue, interfere with attestation, or exploit partial execution surfaces for lateral movement.

**Implementation Notes (Non-Normative)**  
- Integrate runtime watchdogs with TI-3 evidence emission.  
- Use verifiable shutdown sequences inside enclaves and isolated runtimes.  
- Block any attempt to mask or override exit handlers.

**Applies To:** TI-2, TI-3


#### 3.14.22 (RUNISO-22) ATLAS-RUNISO-NO-DEVICE-ACCESS — Restricted Hardware Device Access

Execution MUST NOT access hardware devices (GPU, USB, PCIe, DMA engines, accelerators, NIC offload engines) unless explicitly declared, identity-scoped, and boundary-protected. Hardware access MUST be tightly scoped and provenance-verified.

**Rationale**  
Device interfaces are high-risk escape vectors capable of bypassing OS-level and VM-level sandboxing.

**Implementation Notes**  
- GPU VRAM access MUST be domain-partitioned and zeroized on release.  
- PCIe passthrough MUST require governed provisioning workflows.  
- DMA access MUST be blocked unless sandbox IOMMU policies explicitly allow it.

**Applies To:** TI-3 mandatory


#### 3.14.23 (RUNISO-23) ATLAS-RUNISO-NO-STACK-EXEC — Non-Executable Stack and Heap (W^X)

Memory regions designated for data (heap, stack, globals, buffers, shared memory) MUST NOT be executable. Write XOR Execute (W^X) enforcement MUST be applied universally. Self-modifying code MUST be prohibited.

**Rationale**  
Executable data segments allow injection attacks, ROP/JOP chains, and adversarial modification of runtime behavior.

**Implementation Notes**  
- Disable JIT engines unless executed inside approved enclaves.  
- Memory mappings MUST be created with immutable permissions.

**Applies To:** TI-2, TI-3


#### 3.14.24 (RUNISO-24) ATLAS-RUNISO-DOWNGRADE-LOCK — No Sandbox Downgrade Post-Initialization

Once a sandbox, enclave, or VM initializes its boundary posture, the security level MUST NOT be downgraded. Attempts to reduce isolation, remove restrictions, or widen syscall surfaces MUST invalidate execution immediately.

**Rationale**  
Runtime downgrades are indistinguishable from compromise attempts.

**Implementation Notes**  
- Lock namespaces, mounts, and capabilities on initialization.  
- Any downgrade attempt MUST generate TI-3 evidence and terminate.

**Applies To:** TI-3 mandatory


#### 3.14.25 (RUNISO-25) ATLAS-RUNISO-NO-HYPERVISOR-HOP — Hypervisor Boundary Non-Crossing

Workloads MUST NOT migrate across hypervisors, VMM boundaries, or orchestration nodes unless prior attested provisioning authorizes relocation. Hypervisor-level identity MUST NOT be reused across nodes.

**Rationale**  
Hypervisor hopping allows boundary bypass, identity drift, and cross-domain resource access.

**Implementation Notes**  
- Enforce node pinning for sensitive workloads.  
- Hypervisor signatures MUST be validated at runtime.

**Applies To:** TI-3 mandatory


#### 3.14.26 (RUNISO-26) ATLAS-RUNISO-BREACH-INVALIDATE — Automatic Invalidations Upon Isolation Breach

If a sandbox or enclave experiences an integrity breach, unverifiable state, namespace collapse, or memory-domain violation, execution MUST halt immediately, session keys MUST be rotated, and all downstream data MUST be quarantined.

**Rationale**  
Continuing execution after boundary breaches compounds compromise severity.

**Implementation Notes**  
- Breach detection MUST trigger auto-quarantine.  
- Invalidate attestation tokens and force re-attestation on restart.

**Applies To:** TI-3 mandatory


#### 3.14.27 (RUNISO-27) ATLAS-RUNISO-EVIDENCE — TI-Level Forensic Evidence for Runtime Isolation Events

Sandbox initialization, enclave attestation, boundary enforcement events, syscall violations, memory violations, device-access attempts, configuration mutations, runtime faults, and termination events MUST emit TI-level forensic evidence. Evidence MUST bind to identity, domain, and runtime configuration hash.

**Rationale**  
Forensic-grade evidence enables deterministic reconstruction of execution behavior and containment of compromised workloads.

**Implementation Notes**  
- Evidence MUST be emitted to append-only WORM sinks.  
- Evidence MUST include timestamps verified via Section 3.21 deterministic time controls.  
- Evidence MUST be cryptographically signed and lineage-linked.

**Applies To:** TI-2, TI-3

---

### 3.15 Network Boundaries and Deterministic Routing Controls (ATLAS-NET)

Network behavior MUST be deterministic, identity-scoped, domain-bound, cryptographically verifiable, and incapable of runtime expansion. Workloads MUST NOT discover new peers, assume new routes, alter protocol surfaces, or propagate into new network spaces without governed redeployment and re-attestation. All communication MUST operate within declared, immutable scopes.


#### 3.15.1 (NET-01) ATLAS-NET-STATIC-ROUTES — Static Declared Routing Only

All routing targets, peers, and network paths MUST be explicitly declared prior to execution. Dynamic route discovery, fallback routing, adaptive routing algorithms, or environment-driven expansions MUST be prohibited. If undeclared routes appear, execution MUST fail closed.

**Rationale (Non-Normative)**  
Dynamic routing collapses determinism and allows workloads to escape declared domains.

**Implementation Notes**  
- Enforce fixed routing tables per workload identity.  
- Block routing protocols such as BGP, OSPF, RIP, or service-mesh autoconfig.  
- Treat appearance of a new route as a boundary violation.

**Applies To:** TI-2, TI-3


#### 3.15.2 (NET-02) ATLAS-NET-NO-EGRESS — No Default Egress

Outbound network access MUST be disabled by default. Egress MUST be explicitly enumerated, identity-scoped, and governed. Wildcard outbound rules (e.g., `0.0.0.0/0`) MUST be rejected automatically.

**Rationale**  
Default egress creates open exfiltration paths and enables lateral pivoting.

**Implementation Notes**  
- Require explicit per-destination whitelisting with classification review.  
- Enforce outbound firewalls scoped to identity.  
- Block DNS-over-HTTPS or TLS-based covert tunnels.

**Applies To:** TI-3 mandatory


#### 3.15.3 (NET-03) ATLAS-NET-BOUNDARIES — Domain-Bound Network Scopes

Workloads MUST communicate only within declared trust domains. Cross-domain communication MUST require explicit governed approval, identity-bound channels, and deterministic routing rules. Domain shifts MUST NOT occur dynamically.

**Rationale**  
Domain drift silently expands the attack surface.

**Implementation Notes**  
- Require domain-scoped mTLS certs.  
- Do not allow transitive domain trust.  
- Enforce network segmentation via enclave or VLAN boundaries.

**Applies To:** TI-2, TI-3


#### 3.15.4 (NET-04) ATLAS-NET-NO-PEER-DISCOVERY — No Runtime Peer Discovery

Workloads MUST NOT discover peers dynamically using DNS, broadcast, multicast, service meshes, gossip protocols, workload APIs, cluster membership services, or dynamic SNI probing. Discovery attempts MUST fail closed.

**Rationale**  
Peer discovery enables uncontrolled expansion and dynamic graph formation.

**Implementation Notes**  
- Disable DNS except for declared domains.  
- Block mDNS, SSDP, LLMNR, and mesh service-discovery APIs.  
- Force explicit peer declarations in deployment manifests.

**Applies To:** TI-3 mandatory


#### 3.15.5 (NET-05) ATLAS-NET-PEER-WHITELIST — Strict Peer Whitelisting

Only explicitly whitelisted endpoints SHALL be permitted as communication peers. Unknown, undeclared, or untrusted endpoints MUST be rejected without negotiation.

**Rationale**  
Implicit trust leads to lateral propagation and unauthorized cross-talk.

**Implementation Notes**  
- Validate peer certs against identity-scoped trust stores.  
- Block opportunistic TLS or auto-downgraded trust models.

**Applies To:** TI-2, TI-3


#### 3.15.6 (NET-06) ATLAS-NET-IDENTITY-BOUND — Identity-Bound Connections

All network flows MUST be tied to an execution identity. Anonymous, unauthenticated, shared-secret, IP-based, or token-forwarded connections MUST be prohibited. Identity MUST be cryptographically bound to both endpoints.

**Rationale**  
Identity-bound connection guarantees prevent connection reuse and impersonation.

**Implementation Notes**  
- Require mTLS with identity-scoped certs.  
- Enforce identity in flow metadata at the network boundary.

**Applies To:** TI-3 mandatory


#### 3.15.7 (NET-07) ATLAS-NET-NONTRANSITIVE — Non-Transitive Trust Boundaries

Trust MUST NOT extend beyond immediate peers. One approved hop MUST NOT imply that the workload may transitively trust the next hop. Each hop requires its own identity-scoped authorization.

**Rationale**  
Transitive trust is a classic cause of lateral expansion.

**Implementation Notes**  
- Do not reuse authorization tokens across multiple hops.  
- Disallow relaying or chaining identity approvals.

**Applies To:** TI-2, TI-3


#### 3.15.8 (NET-08) ATLAS-NET-PROTOCOL-SCOPE — Protocol Scope Restriction

Workloads MAY only use declared protocols. Dynamic protocol switching, opportunistic protocol negotiation, fallback to plaintext, or fallback to weaker crypto MUST be prohibited.

**Rationale**  
Protocol switching is frequently used to downgrade security and escape detection.

**Implementation Notes**  
- Permit only declared ports, ciphers, and protocol suites.  
- Disable ALPN-based auto-negotiation unless domain-scoped.

**Applies To:** TI-2, TI-3


#### 3.15.9 (NET-09) ATLAS-NET-NO-OVERLAY — No Unauthorized Overlay Networks

Workloads MUST NOT form overlay networks, tunnels, mesh overlays, encrypted peer-to-peer fabrics, VPN-like tunnels, or NAT traversal surfaces. Attempts MUST be blocked and generate TI-3 evidence.

**Rationale**  
Overlay networks hide traffic from governance and collapse segmentation boundaries.

**Implementation Notes**  
- Block WireGuard-like ad-hoc tunnels, SSH reverse tunnels, and mesh sidecars.  
- Block VXLAN or GRE unless formally declared.

**Applies To:** TI-3 mandatory


#### 3.15.10 (NET-10) ATLAS-NET-NO-SERVICE-MESH-AUTO — No Automatic Service Mesh Injection

Service mesh sidecars, proxies, or routing layers MUST NOT inject automatically. Workload network topology MUST remain explicit, governed, and identity-scoped.

**Rationale**  
Implicit injection bypasses determinism and introduces undeclared hops.

**Implementation Notes**  
- Require explicit mesh enrollment with identity-scoped certs.  
- Block auto-injection in orchestrators such as Kubernetes.

**Applies To:** TI-2, TI-3

#### 3.15.11 (NET-11) ATLAS-NET-MTLS — Mandatory Mutual Authentication

All permitted network channels MUST use mTLS with identity-scoped certificates bound to workload identity, domain, and execution purpose. Connections MUST NOT proceed unless both endpoints authenticate each other cryptographically. TLS without mutual authentication, shared secrets, token-only auth, or IP-based trust MUST be prohibited.

**Rationale (Non-Normative)**  
Mutual authentication ensures that every network flow is explicitly tied to a verifiable identity. It prevents impersonation, downgrade attacks, service spoofing, and unauthorized connection reuse.

**Implementation Notes (Non-Normative)**  
- Certificates MUST be short-lived and identity-scoped.  
- Certificate rotation MUST occur on redeployment and identity change.  
- Reject mTLS that does not embed domain and classification metadata.

**Applies To:** TI-2, TI-3


#### 3.15.12 (NET-12) ATLAS-NET-NO-PLAIN — No Plaintext Transport

Plaintext network transport MUST NOT occur under any circumstance, including internal networks, localhost paths, private overlays, or enclave-local communications. All communications MUST be encrypted and identity-bound. Plaintext attempts MUST fail closed.

**Rationale**  
Plaintext traffic is trivially interceptable and bypasses classification enforcement.

**Implementation Notes**  
- Disable HTTP, plaintext TCP, UDP, and unencrypted RPC.  
- Enforce encryption in cluster/service mesh communication paths.  
- Validate encryption at the socket layer and protocol layer.

**Applies To:** TI-3 mandatory


#### 3.15.13 (NET-13) ATLAS-NET-SCOPE-LOCK — Locked Network Scope

Network scopes MUST be immutable after deployment. Workloads MUST NOT expand permitted peers, CIDRs, DNS targets, or protocols at runtime. Scope-lifting attempts MUST terminate execution.

**Rationale**  
Dynamic expansion leads to silent domain escape and privilege inflation.

**Implementation Notes**  
- Freeze network policy upon workload initialization.  
- Reject runtime changes to network ACLs.  
- Use attestation bindings for allowed scopes.

**Applies To:** TI-3 mandatory


#### 3.15.14 (NET-14) ATLAS-NET-PORT-SCOPE — Port Scope Restriction

Workloads MUST bind only to explicitly declared ports and interfaces. Wildcard binding (`0.0.0.0:*` or IPv6 equivalents), port scanning, or binding expansion MUST be blocked.

**Rationale**  
Wildcard binding exposes interfaces unintentionally and increases attack exposure.

**Implementation Notes**  
- Bind only to declared ports and declared IPs.  
- Disable wildcard listeners within orchestration platforms.  
- Enforce port-level identity-scoped authorization.

**Applies To:** TI-2, TI-3


#### 3.15.15 (NET-15) ATLAS-NET-NO-LATERAL-MOVE — Anti-Lateral Movement Enforcement

Workloads MUST NOT perform lateral movement across hosts, namespaces, clusters, or trust domains. Attempting to enumerate peers, pivot across nodes, or scan reachable surfaces MUST be treated as a boundary violation and halted.

**Rationale**  
Lateral movement is a hallmark of post-compromise escalation.

**Implementation Notes**  
- Block ICMP sweeps, TCP SYN scans, ARP scans, and mesh probing.  
- Force workloads to operate only within fixed peer maps.  
- Generate TI-3 evidence on any attempted lateral enumeration.

**Applies To:** TI-3 mandatory


#### 3.15.16 (NET-16) ATLAS-NET-NO-BROADCAST — Prohibition on Broadcast or Multicast

Broadcast, multicast, gossip, cluster membership discovery, NAT traversal, or auto-group formation MUST be disabled unless explicitly declared and governed. Runtime discovery MUST not be possible.

**Rationale**  
Broadcast and multicast allow autonomous peer expansion outside deterministic boundaries.

**Implementation Notes**  
- Disable IPv4/IPv6 broadcast, IGMP, mDNS, SSDP, and gossip protocols.  
- Enforce static peer lists even in distributed systems.

**Applies To:** TI-2, TI-3


#### 3.15.17 (NET-17) ATLAS-NET-FLOW-BOUND — Flow-Specific Identity Scoping

Each network flow MUST be bound to the execution identity, target domain, classification metadata, and intended purpose. Reuse of connections across identities or intents MUST be prohibited.

**Rationale**  
Binding flows to identity and intent prevents covert channel reuse.

**Implementation Notes**  
- Include identity metadata in connection handshake.  
- Enforce identity and domain validation for every new flow.  
- Treat flow reuse attempts as violations.

**Applies To:** TI-3 mandatory


#### 3.15.18 (NET-18) ATLAS-NET-NO-PIGGYBACK — No Credential or Token Forwarding

Workloads MUST NOT forward credentials, headers, tokens, certificates, or authorization artifacts to downstream systems. A workload MAY NOT act as an authority carrier. Delegation MUST require new identity-scoped credentials.

**Rationale**  
Credential forwarding extends authority unintentionally and enables chained escalation.

**Implementation Notes**  
- Block header forwarding in proxies unless explicitly governed.  
- Prevent reuse of upstream credentials downstream.  
- Force downstream workloads to authenticate independently.

**Applies To:** TI-3 mandatory


#### 3.15.19 (NET-19) ATLAS-NET-SINGLE-HOP — Single-Hop Enforcement

Workloads MUST NOT route, relay, forward, or transit traffic for any other workload. Acting as a router, NAT device, relay node, mesh transit, or proxy MUST be prohibited unless explicitly declared as a dedicated routing identity.

**Rationale**  
Transit behavior introduces unbounded graph expansion and route obfuscation.

**Implementation Notes**  
- Disable IP forwarding and Linux kernel forwarding flags.  
- Block proxy functionality unless explicitly defined in the workload role.  
- Reject any attempt to send traffic to undeclared downstream peers.

**Applies To:** TI-2, TI-3


#### 3.15.20 (NET-20) ATLAS-NET-NO-LOCALHOST-SHARE — Localhost Isolation

Multiple workloads sharing the same host MUST NOT communicate via localhost unless isolated through unique loopback namespaces. Localhost MUST NOT imply trust, shared identity, or shared memory.

**Rationale**  
Localhost bypasses segmentation and conceals traffic within node-local boundaries.

**Implementation Notes**  
- Use per-namespace loopback interfaces.  
- Block 127.0.0.1 communication across process boundaries.  
- Enforce localhost identity checks.

**Applies To:** TI-3 mandatory

#### 3.15.21 (NET-21) ATLAS-NET-NO-DNS-LEAK — DNS Boundary Enforcement

DNS resolution MUST be restricted to explicitly approved domains. Workloads MUST NOT resolve arbitrary domains, public DNS endpoints, wildcard patterns, or upstream resolvers inherited from the host or orchestrator. Any attempt to resolve undeclared domains MUST fail closed and generate TI-3 evidence.

**Rationale (Non-Normative)**  
Unbounded DNS enables covert exfiltration, peer discovery, command-and-control signaling, and dynamic boundary escape.

**Implementation Notes (Non-Normative)**  
- Enforce workload-local DNS allowlists.  
- Disable recursive DNS or upstream resolver inheritance.  
- Block DNS over HTTPS, DNS over TLS, and encrypted DNS tunnels unless explicitly declared.

**Applies To:** TI-3 mandatory


#### 3.15.22 (NET-22) ATLAS-NET-NO-OUTBOUND-SCANS — Prohibition on Outbound Network Scanning

Workloads MUST NOT initiate scanning behavior including port scans, ICMP sweeps, ARP probes, cluster membership discovery, or reachability enumeration. Scanning attempts MUST be immediately terminated and logged as boundary violations.

**Rationale**  
Scanning is a precursor to lateral movement and unauthorized expansion of the network graph.

**Implementation Notes**  
- Block SYN scans, UDP probes, ICMP discovery, and ARP interrogation.  
- Enforce flow-specific outbound rate caps and anomaly detection.  
- Generate TI-3 evidence on first violation.

**Applies To:** TI-3 mandatory


#### 3.15.23 (NET-23) ATLAS-NET-NO-IMPLICIT-METADATA — No Cloud Metadata or Host Introspection

Workloads MUST NOT access cloud metadata endpoints (e.g., AWS IMDSv1/IMDSv2, GCE metadata, Azure metadata), Kubernetes node metadata, orchestrator API surfaces, or any environment-based introspection surfaces unless explicitly declared and identity-scoped.

**Rationale**  
Metadata endpoints often grant credentials, configuration secrets, or authority surfaces far outside workload scope.

**Implementation Notes**  
- Block all access to `169.254.169.254`, `/var/run/secrets`, and in-cluster metadata APIs by default.  
- Require explicit metadata access declarations tied to classification and trust domain.  
- Disable IMDS entirely for high-sensitivity workloads.

**Applies To:** TI-2, TI-3


#### 3.15.24 (NET-24) ATLAS-NET-THROTTLE — Deterministic Rate Limiting

Network flows MUST be rate-limited based on deterministic quotas. Unbounded egress, burst behavior, entropy spikes, anomalous flow density, or suspicious upload patterns MUST be blocked and treated as potential exfiltration.

**Rationale**  
Rate-limiting prevents covert channel formation, resource exhaustion, and data exfiltration via burst traffic.

**Implementation Notes**  
- Enforce per-identity flow quotas at ingress and egress.  
- Detect and block high-entropy outbound streams.  
- Tie rate limits to classification and domain boundaries.

**Applies To:** TI-3 mandatory


#### 3.15.25 (NET-25) ATLAS-NET-EXFIL-TRIPWIRE — Exfiltration Tripwires

Large data transfers, unexpected directional flow, unauthorized target domains, high-entropy payloads, or deviation from known flow patterns MUST trigger automatic tripwire responses: immediate flow termination, TI-3 evidence generation, and identity quarantine.

**Rationale**  
Tripwires reduce exfiltration dwell time and force deterministic containment.

**Implementation Notes**  
- Monitor for anomalous egress patterns and streaming behaviors.  
- Block high-volume uploads lacking classification alignment.  
- Pair tripwire events with automatic key rotation.

**Applies To:** TI-3 mandatory


#### 3.15.26 (NET-26) ATLAS-NET-BREACH-INVALIDATE — Routing Breach Auto-Invalidation

If routes expand, undeclared peers appear, unauthorized CIDRs become reachable, or a workload attempts to alter its routing table, execution MUST halt immediately. All identities associated with the workload MUST be invalidated until re-attestation and reclassification occur.

**Rationale**  
Route expansion or peer appearance is indistinguishable from active compromise.

**Implementation Notes**  
- Freeze routes at deployment; treat mutations as violations.  
- Validate route tables on each network operation.  
- Invalidate identity tokens after any routing-related violation.

**Applies To:** TI-3 mandatory


#### 3.15.27 (NET-27) ATLAS-NET-EVIDENCE — TI-Level Network Forensic Evidence

All network activities MUST emit TI-level forensic evidence including source identity, destination identity, target domain, classification, protocol, intent (declared purpose), timestamps, and flow metadata. Evidence MUST be cryptographically signed, lineage-linked, and written to append-only WORM sinks.

**Rationale**  
Network evidence enables deterministic replay, forensic reconstruction, and containment of compromised flows.

**Implementation Notes**  
- Evidence MUST be collected at both client and server boundaries.  
- Timestamps MUST align with deterministic time controls (Section 3.21).  
- Evidence MUST bind network flow to identity and boundary metadata.

**Applies To:** TI-2, TI-3

---

### 3.16 Deterministic Observability, Telemetry, and Runtime Evidence Controls (ATLAS-OBS)

Systems MUST produce complete, tamper-evident, identity-scoped telemetry that enables deterministic reconstruction of execution, routing, data transformations, access patterns, sandbox states, and failure modes. Telemetry MUST function as a security boundary, not an operational convenience. The absence of evidence, degradation of evidence, or interruption of evidence MUST be treated as a boundary violation, not as a permissible operating state.


#### 3.16.1 (OBS-01) ATLAS-OBS-REQUIRED — Observability Is Mandatory

All governed workloads MUST emit telemetry at or above defined minimum levels. Silent execution, partial logging, or telemetry-disabled modes MUST NOT exist. A workload that cannot emit telemetry MUST NOT run.

**Rationale (Non-Normative)**  
Silent execution invalidates forensic analysis, breaks deterministic reconstruction, and creates blind spots exploitable by adversaries.

**Implementation Notes**  
- Telemetry MUST start before workload initialization completes.  
- Telemetry sinks MUST be validated before execution begins.  
- Temporary network failures MUST not be grounds for silent continuation.

**Applies To:** TI-2, TI-3


#### 3.16.2 (OBS-02) ATLAS-OBS-NO-SELECTIVE — No Selective Logging

Workloads SHALL NOT suppress, throttle, omit, or dynamically filter logs based on flags, control-plane conditions, load conditions, or operator request. Logging fidelity MUST remain constant for the lifetime of the workload.

**Rationale**  
Selective logging hides evidence during targeted periods and undermines deterministic forensics.

**Implementation Notes**  
- Disable log-level changes post-initialization.  
- All suppression attempts MUST be treated as violations.  
- Debug-only logs MAY be additive but never subtractive.

**Applies To:** TI-2, TI-3


#### 3.16.3 (OBS-03) ATLAS-OBS-IDENTITY — Identity-Bound Telemetry

All telemetry MUST be cryptographically bound to workload identity. Anonymous logs, logs without identity metadata, or logs relying solely on IP-based origin MUST be rejected.

**Rationale**  
Identity-binding enforces accountability and prevents impersonation or log spoofing.

**Implementation Notes**  
- Signing keys MUST be identity-scoped.  
- Include identity metadata in every log line or record.  
- Verify identity binding at ingestion into evidence pipeline.

**Applies To:** TI-3 mandatory


#### 3.16.4 (OBS-04) ATLAS-OBS-TI-TIERING — Tiered Evidence Requirements

Telemetry MUST be generated according to defined tiers (TI-1, TI-2, TI-3). Security-critical events—including identity issuance, routing changes, sandbox violations, data-boundary attempts, and attestation operations—require TI-3 evidence with full provenance and cryptographic integrity.

**Rationale**  
Evidence tiering ensures that high-risk events receive the highest fidelity logging.

**Implementation Notes**  
- Enforce per-event TI-tier classification rules.  
- TI-3 events MUST include lineage, intent, domain, and identity proofs.

**Applies To:** TI-2, TI-3


#### 3.16.5 (OBS-05) ATLAS-OBS-NO-DOWNGRADE — Evidence Cannot Degrade

Logging quality, fidelity, or completeness MUST NOT degrade after initialization. Attempts to reduce visibility, rotate to low-fidelity modes, suppress metadata, or reconfigure evidence sinks MUST be blocked and treated as violations.

**Rationale**  
Downgrades are indistinguishable from malicious tampering.

**Implementation Notes**  
- Freeze logging configuration at start.  
- Detect and block dynamic level changes.  
- All downgrade attempts MUST generate TI-3 audit events.

**Applies To:** TI-3 mandatory


#### 3.16.6 (OBS-06) ATLAS-OBS-APPEND-ONLY — Append-Only Evidence

Telemetry MUST be append-only and cryptographically verifiable. Logs MUST NOT be overwritten, compacted, truncated, or merged in ways that break continuity. All evidence MUST preserve forward-only chain-of-custody.

**Rationale**  
Append-only evidence ensures tamper-evident history and supports forensic replay.

**Implementation Notes**  
- Hash-chain or Merkle-tree structures SHOULD be used.  
- Compaction MUST occur only in governed, cryptographically linked forms.  
- All writes MUST be monotonic and evidence-protected.

**Applies To:** TI-3 mandatory


#### 3.16.7 (OBS-07) ATLAS-OBS-NO-LOCAL-ONLY — No Local-Only Logs

Local-only logging MUST NOT be considered sufficient. Evidence MUST be exported to governed sinks with WORM guarantees. Loss of connectivity MUST NOT justify local-only persistence except as a temporary buffer.

**Rationale**  
Local logs are vulnerable to tampering, deletion, and host compromise.

**Implementation Notes**  
- Logs MUST flush to remote sinks frequently.  
- Local buffers MUST be encrypted and ephemeral.  
- Buffer overflows MUST halt execution rather than drop evidence.

**Applies To:** TI-2, TI-3


#### 3.16.8 (OBS-08) ATLAS-OBS-WORM — WORM Evidence Storage

Security-related telemetry MUST be stored in append-only, replay-verifiable WORM (Write Once Read Many) systems. Deletion, retroactive modification, truncation, or rewriting MUST be impossible.

**Rationale**  
WORM storage guarantees long-term integrity of forensic records.

**Implementation Notes**  
- WORM enforcement MUST be cryptographically enforced, not soft policy.  
- Pair WORM stores with lineage hashes from execution context.  
- Retention MUST comply with trust-domain classification rules.

**Applies To:** TI-3 mandatory


#### 3.16.9 (OBS-09) ATLAS-OBS-NO-USER-SUPPRESS — Humans Cannot Suppress Evidence

No human operator—including administrators—MUST have the ability to delete, suppress, redact, or disable evidence generation. Administrative privilege MUST NOT override forensic integrity.

**Rationale**  
Human suppression compromises incident response, audit trails, and trust.

**Implementation Notes**  
- Evidence pipelines MUST ignore user-level suppression flags.  
- Admin interfaces MUST be incapable of disabling logging.  
- Attempted suppression MUST be logged as TI-3 violations.

**Applies To:** TI-2, TI-3


#### 3.16.10 (OBS-10) ATLAS-OBS-TRACE-CONTINUITY — Trace Continuity Across Components

Trace identifiers MUST persist across system boundaries, identity transitions, pipeline stages, execution splits, transformations, and model inference cycles. Evidence MUST record full lineage across distributed and multi-stage workflows.

**Rationale**  
Continuity enables deterministic reconstruction of full execution paths.

**Implementation Notes**  
- Use globally unique, identity-scoped trace IDs.  
- Include trace IDs in all downstream evidence and RPC flows.  
- Reject evidence lacking trace-continuity metadata.

**Applies To:** TI-3 mandatory

#### 3.16.11 (OBS-11) ATLAS-OBS-KERNEL-BOUND — Kernel-Level Enforcement

Security-critical workloads MUST bind evidence generation to kernel, hypervisor, or hardware signals in addition to user-space telemetry. User-space logging alone is insufficient. Kernel-bound hooks MUST capture process start, syscall violations, memory faults, sandbox escapes, network expansions, and integrity failures.

**Rationale (Non-Normative)**  
User-space logging can be bypassed, disabled, or tampered with. Kernel-bound signals form a stronger enforcement boundary that adversaries cannot easily suppress.

**Implementation Notes**  
- Use kernel audit frameworks, hypervisor events, enclave hardware signals.  
- Evidence MUST include syscall ID, process identity, and boundary metadata.  
- Any failure to bind kernel signals MUST halt execution.

**Applies To:** TI-3 mandatory


#### 3.16.12 (OBS-12) ATLAS-OBS-NO-DEBUG-BYPASS — Debugging Cannot Bypass Evidence

Debug, trace, or introspection modes MUST NOT circumvent telemetry, reduce evidence fidelity, disable sandbox checks, or bypass identity requirements. Debugging MUST remain subject to the same deterministic evidence controls as production execution.

**Rationale**  
Debug bypasses are commonly exploited to silence logs or disable enforcement.

**Implementation Notes**  
- Debug builds MUST still enforce identity-bound telemetry.  
- Attach/detach debugger events MUST be logged at TI-3.  
- Runtime inspection tools MUST NOT modify evidence trails.

**Applies To:** TI-2, TI-3


#### 3.16.13 (OBS-13) ATLAS-OBS-RTM — Runtime Measurement of State Transitions

Workloads MUST measure and emit evidence for state transitions, including environment changes, library loads, configuration modifications, mount updates, memory map changes, resource ceilings, and identity scope changes. All state transitions MUST be traceable.

**Rationale**  
Unrecorded state changes hide boundary violations and enable stealth compromise.

**Implementation Notes**  
- Track loaded libraries, version hashes, and dynamic configs.  
- Emit evidence on mount changes, namespace shifts, and device binding.  
- Use kernel or enclave signals for integrity-sensitive transitions.

**Applies To:** TI-3 mandatory


#### 3.16.14 (OBS-14) ATLAS-OBS-FAIL-CLOSE — Fail Closed on Telemetry Loss

If telemetry cannot be emitted, validated, delivered, or cryptographically chained, workloads MUST terminate execution. Silent continuation MUST NOT occur. Loss of telemetry is equivalent to loss of boundary integrity.

**Rationale**  
Failure to produce evidence means compromise cannot be detected.

**Implementation Notes**  
- Enforce telemetry heartbeat checks.  
- Terminate on evidence sink unavailability.  
- Telemetry failures MUST generate local TI-3 events before shutdown.

**Applies To:** TI-3 mandatory


#### 3.16.15 (OBS-15) ATLAS-OBS-CRYPTO-SIGN — Cryptographically Signed Telemetry

All telemetry MUST be signed with identity-scoped cryptographic keys. Evidence lacking valid signatures MUST be rejected, quarantined, or treated as malicious. Verification MUST occur at ingestion.

**Rationale**  
Unsigned telemetry can be forged, spoofed, or replayed.

**Implementation Notes**  
- Use per-identity signing keys with rotation.  
- Attach lineage metadata to signature envelopes.  
- Invalidate evidence with mismatched identity or domain.

**Applies To:** TI-2, TI-3


#### 3.16.16 (OBS-16) ATLAS-OBS-EPOCH-SCOPECHECK — Time and Scope Anchoring

All telemetry MUST include deterministic timestamps anchored to trust-domain time controls (Section 3.21). Evidence MUST include identity, dataset scope, trust domain, model version, pipeline stage, and execution epoch.

**Rationale**  
Time and scope anchoring prevents replay, ambiguity, and multi-domain confusion.

**Implementation Notes**  
- Timestamps MUST use deterministic time sources.  
- Include domain and version metadata in all evidence.  
- Reject evidence lacking verifiable temporal anchors.

**Applies To:** TI-2, TI-3


#### 3.16.17 (OBS-17) ATLAS-OBS-VERSIONMAP — Version Mapping for Complete Traceability

Evidence MUST include identifiers for the exact versions of code, config, datasets, models, libraries, and parameters used during execution. Version mapping ensures deterministic reconstruction of workflows.

**Rationale**  
Without version mapping, replaying or auditing execution is impossible.

**Implementation Notes**  
- Generate version manifest at deployment.  
- Include git commits, dataset hashes, model hashes, config IDs.  
- Validate mapping on every TI-3 event.

**Applies To:** TI-3 mandatory


#### 3.16.18 (OBS-18) ATLAS-OBS-PROCESS-CORR — Process-Level Correlation

Each process MUST have a unique lineage identifier that persists across forks, threads, and parallel workloads. Child processes MUST inherit correlation metadata and tie back to originating identity.

**Rationale**  
Forked or parallel processes without lineage create blind forensic zones.

**Implementation Notes**  
- Inject lineage IDs into process environment.  
- Log PID transitions, fork events, and process tree metadata.  
- Correlate network flows and telemetry to process lineage.

**Applies To:** TI-2, TI-3


#### 3.16.19 (OBS-19) ATLAS-OBS-NO-LOG-SWAP — No Log Backend Substitution

Evidence sinks MUST NOT be swapped or redirected at runtime. Switching logging destinations, pipelines, or endpoints MUST require redeployment and attestation. Runtime substitution MUST be blocked.

**Rationale**  
Log backend substitution allows silent redirection or suppression.

**Implementation Notes**  
- Enforce static sink definitions in deployment manifest.  
- Block runtime modifications to logging endpoints or credentials.  
- Detect substitution attempts with TI-3 violation events.

**Applies To:** TI-3 mandatory


#### 3.16.20 (OBS-20) ATLAS-OBS-RAW-PROTECT — Raw Telemetry Must Be Protected

Raw telemetry MUST NOT be altered, summarized, filtered, or enriched before WORM storage. Analytics, dashboards, or monitoring pipelines MUST operate on copies, never originals. Unauthorized reads MUST be blocked.

**Rationale**  
Raw telemetry is the authoritative forensic source; modification destroys forensic value.

**Implementation Notes**  
- Enforce read protections at sink level.  
- Only post-processing pipelines may access derivative copies.  
- Evidence readers MUST be identity-scoped.

**Applies To:** TI-2, TI-3

#### 3.16.21 (OBS-21) ATLAS-OBS-DATA-SHADOW — No Shadow Logging

Workloads MUST NOT emit divergent or partially overlapping telemetry streams that produce conflicting, duplicative, or inconsistent evidence. Shadow logs, alternate log paths, debug-only logs not reflected in authoritative pipelines, or forked telemetry streams MUST be treated as tampering and immediately invalidate trust in the workload.

**Rationale (Non-Normative)**  
Shadow logging allows adversaries to create a false evidence trail, hide boundary violations, or mislead auditors. Deterministic security requires single-source, authoritative telemetry.

**Implementation Notes**  
- All evidence MUST converge into a unified, append-only pipeline.  
- Disable sideband logging, debug-only pipes, or per-module log overrides.  
- Detect divergence by comparing trace IDs across all pipelines.

**Applies To:** TI-3 mandatory


#### 3.16.22 (OBS-22) ATLAS-OBS-HARDENED-PIPELINE — Hardened Evidence Pipelines

Evidence pipelines MUST operate within hardened, tamper-resistant execution environments. Client-side or workload-generated evidence MUST NOT be considered authoritative unless validated and cryptographically verified. Pipeline compromise MUST invalidate workloads relying on that telemetry.

**Rationale**  
Weak evidence pipelines allow silent log manipulation, late injection, or loss of forensic integrity.

**Implementation Notes**  
- Use kernel-level or enclave-level ingestion points where possible.  
- Enforce strong authentication and authorization for pipeline readers.  
- Evidence pipelines MUST use non-bypassable integrity checking.

**Applies To:** TI-3 mandatory


#### 3.16.23 (OBS-23) ATLAS-OBS-NO-DELAY — No Deferred or Batch-Only Evidence

Telemetry MUST be emitted at the time events occur. Deferred logging, batch-only submission, asynchronous buffering without guaranteed delivery, or retroactive reconstruction MUST be prohibited except under strictly bounded buffering rules compliant with deterministic evidence guarantees.

**Rationale**  
Deferred evidence undermines ordering, causality, and timely detection of compromise.

**Implementation Notes**  
- Enforce near-real-time emission of TI-tier events.  
- Batches MUST contain original timestamps and ordering metadata.  
- Buffer overflow MUST halt execution, not drop evidence.

**Applies To:** TI-2, TI-3


#### 3.16.24 (OBS-24) ATLAS-OBS-NO-KAFKA-ONLY — Brokers Are Not Evidence Stores

Streaming brokers, message queues, or event buses (e.g., Kafka, NATS, Pulsar) MUST NOT serve as authoritative evidence stores. Evidence MUST be forwarded to governed WORM sinks for final retention. Brokers MAY serve as transport layers but MUST NOT be relied upon for compliance.

**Rationale**  
Brokers allow message deletion, log compaction, or retention-based loss, all incompatible with forensic guarantees.

**Implementation Notes**  
- Mark broker messages as transient.  
- Evidence MUST land in WORM storage before being considered valid.  
- Downstream systems MUST reject telemetry that never reached WORM stores.

**Applies To:** TI-3 mandatory


#### 3.16.25 (OBS-25) ATLAS-OBS-MODEL-TRACE — Model Input/Output Evidence

AI and ML workloads MUST generate evidence for model inputs, prompts, embeddings, inference outputs, and transformation metadata unless explicitly classified otherwise. Evidence MUST reflect input sensitivity and identity linkage.

**Rationale**  
Model processing can transform or replicate sensitive data; unlogged model activity creates blind forensic zones.

**Implementation Notes**  
- Log model version, input classification, and inference metadata.  
- Treat embeddings and logits as sensitive data requiring evidence.  
- Enforce identity-scoped tracing for all inference calls.

**Applies To:** TI-3 mandatory


#### 3.16.26 (OBS-26) ATLAS-OBS-TRANSFORM-TRACE — Transformation Provenance

All data transformations MUST emit provenance linking inputs, transformations, algorithms, execution identity, and resulting outputs. Evidence MUST preserve ordering and causality.

**Rationale**  
Transformation provenance ensures downstream datasets and artifacts can be trusted and reconstructed.

**Implementation Notes**  
- Hash inputs and outputs and anchor them in evidence.  
- Record algorithm version, configuration, and parameters.  
- Maintain continuity across multi-stage ETL and ML pipelines.

**Applies To:** TI-3 mandatory


#### 3.16.27 (OBS-27) ATLAS-OBS-FLOW-EVIDENCE — Flow-Level Evidence for External Calls

Each outbound network call MUST emit TI-3 evidence documenting source identity, destination identity, authorization proofs, route used, classification constraints, and intended purpose. Absence of outbound flow evidence MUST invalidate the call.

**Rationale**  
Flow-level evidence prevents covert exfiltration, unauthorized propagation, and unintended multi-hop behavior.

**Implementation Notes**  
- Attach identity-scoped session IDs to outbound telemetry.  
- Map flows to declared routing tables.  
- Evidence MUST include deterministic timestamps (Section 3.21).

**Applies To:** TI-3 mandatory


#### 3.16.28 (OBS-28) ATLAS-OBS-FORCE-ROTATE — Evidence-Triggered Key Rotation

Any indication of evidence tampering—such as missing logs, broken hash chains, signature mismatches, diverted pipelines, or unexpected timestamp gaps—MUST trigger mandatory key rotation and identity invalidation.

**Rationale**  
Tampered evidence implies adversarial presence or boundary erosion.

**Implementation Notes**  
- Rotate identity-scoped keys immediately on detection.  
- Quarantine associated workloads until re-attestation.  
- Link rotation events to forensic audit metadata.

**Applies To:** TI-3 mandatory


#### 3.16.29 (OBS-29) ATLAS-OBS-BREACH-HALT — Evidence Breach Auto-Halt

If evidence pipelines suffer integrity failure, loss of continuity, unverified ingestion, or cryptographic mismatch, workloads MUST halt immediately. Dependent outputs MUST be marked compromised until revalidation.

**Rationale**  
Execution without evidence is execution outside deterministic boundaries.

**Implementation Notes**  
- Detect gaps in hash-chain continuity.  
- Invalidate workloads on ingestion failure.  
- Enforce halt-first, diagnose-later policy.

**Applies To:** TI-3 mandatory


#### 3.16.30 (OBS-30) ATLAS-OBS-BIDIRECTIONAL — Bidirectional Evidence

Both initiator and responder MUST emit evidence for shared operations. One-sided logging is insufficient. Bidirectional evidence ensures adversaries cannot exploit asymmetric blind spots or rely on unverified peer assertions.

**Rationale**  
Two-party evidence eliminates asymmetry and supports cross-verification.

**Implementation Notes**  
- Cross-check initiator and responder evidence for alignment.  
- Require identity-scoped signatures on both sides.  
- Evidence mismatches MUST be escalated to TI-3 alerts.

**Applies To:** TI-2, TI-3

---

### 3.17 Autonomous Code Generation, Mutation, and Execution Controls (ATLAS-GEN)

Systems capable of generating code, transforming execution logic, modifying configuration, synthesizing operational instructions, or invoking downstream actions MUST operate under deterministic guardrails. Code generation MUST NOT expand privileges, assume new trust boundaries, or gain execution rights not explicitly granted. Autonomous execution MUST NOT occur without governed authorization and identity-scoped review. Models, agents, and LLM-powered systems MUST be treated as untrusted code generators whose outputs require strict validation.


#### 3.17.1 (GEN-01) ATLAS-GEN-NO-AUTOEXEC — No Automatic Execution of Generated Code

Generated code MUST NOT execute automatically. Code generation and code execution MUST be strictly separated phases with independent trust boundaries, identities, and governance approvals. Generated artifacts MUST remain inert until approved.

**Rationale (Non-Normative)**  
Automatic execution collapses the boundary between untrusted model output and trusted runtime, enabling code injection and privilege escalation.

**Implementation Notes**  
- Generated artifacts MUST be stored in non-executable form until approved.  
- Execution MUST require explicit governance approval and identity revalidation.  
- Auto-run, hot-reload, and implicit eval MUST be prohibited.

**Applies To:** TI-2, TI-3


#### 3.17.2 (GEN-02) ATLAS-GEN-NO-RUNTIME-GEN — No Runtime Code Generation in Deterministic Environments

Deterministic execution environments MUST NOT generate new executable artifacts at runtime unless explicitly declared, sandboxed, and identity-scoped. Runtime generation MUST NOT introduce new privilege surfaces.

**Rationale**  
Runtime generation obscures provenance and creates unpredictable execution surfaces.

**Implementation Notes**  
- Disable JIT compilers unless within governed enclaves.  
- Enforce static code policies for deterministic lanes.  
- Generated bytecode MUST inherit highest input sensitivity.

**Applies To:** TI-3 mandatory


#### 3.17.3 (GEN-03) ATLAS-GEN-PROMPT-BOUND — Prompt Boundaries on Code Synthesis

Prompts and instructions driving code generation MUST be bound to declared task, identity, trust domain, and classification scope. Generators MUST NOT infer or assume broader authority based on linguistic ambiguity.

**Rationale**  
Prompt boundaries prevent unintended privilege leakage or cross-domain expansion.

**Implementation Notes**  
- Enforce strict prompt-to-scope mappings.  
- Reject prompts that reference undeclared operations or privileged tasks.  
- Enforce domain alignment checks before generation.

**Applies To:** TI-2, TI-3


#### 3.17.4 (GEN-04) ATLAS-GEN-NO-CHAIN — No Prompt or Model Self-Chaining

Systems MUST NOT chain model outputs into new prompts without governed approval. Autonomous prompt-chaining MUST be treated as an execution escalation and blocked.

**Rationale**  
Chaining outputs creates uncontrolled feedback loops that bypass human oversight and boundary enforcement.

**Implementation Notes**  
- Disable “self-ask” or “automatic refinement” flows unless governed.  
- Require explicit review for each generation cycle.  
- Log chain attempts as TI-3 events.

**Applies To:** TI-3 mandatory


#### 3.17.5 (GEN-05) ATLAS-GEN-NO-HIDDEN-TOOLING — No Implicit Tool Invocation

Models MUST NOT autonomously invoke tools, APIs, shells, execution environments, browsers, or network operations. Tool invocation MUST be explicitly declared, governed, and identity-scoped.

**Rationale**  
Implicit tool access transforms code generation into execution without accountability.

**Implementation Notes**  
- Block hidden tool-calling (e.g., “function calling” without audit).  
- Require explicit tool access declarations.  
- Emit TI-3 evidence for all approved tool invocations.

**Applies To:** TI-2, TI-3


#### 3.17.6 (GEN-06) ATLAS-GEN-NO-SELF-EDIT — No Self-Referential Code Mutation

Models, agents, or autonomous systems MUST NOT modify their own source code, weights, routing tables, configuration parameters, capabilities, or executable artifacts. Self-editing MUST be treated as a boundary breach.

**Rationale**  
Self-modification invalidates deterministic behavior and breaks provenance.

**Implementation Notes**  
- Disable write access to source trees and executing binaries.  
- Enforce immutable model weights at runtime.  
- Treat unauthorized config mutations as TI-3 violations.

**Applies To:** TI-3 mandatory


#### 3.17.7 (GEN-07) ATLAS-GEN-OUTPUT-SANDBOX — Generated Code Must Execute in Confined Sandboxes

If generated code is executed, it MUST run in isolated sandboxes with no privilege inheritance from the generator. Execution identities MUST be separate, lowest-privilege, and non-transitive.

**Rationale**  
Generated code must not influence or compromise the generator or control-plane environment.

**Implementation Notes**  
- Use per-artifact sandboxes with strict isolation.  
- Bind each sandbox to a unique, minimal identity.  
- Disallow network access by default.

**Applies To:** TI-2, TI-3


#### 3.17.8 (GEN-08) ATLAS-GEN-IDENTITY-SPLIT — Identity Separation Between Generator and Executor

Code generators MUST NOT share execution identities, credentials, network scopes, or trust ceilings with executors. Roles MUST remain strictly separated to prevent privilege inheritance.

**Rationale**  
Identity mixing enables privilege escalation and cross-boundary contamination.

**Implementation Notes**  
- Assign separate identity tokens for generation vs execution.  
- Enforce non-interchangeability of roles.  
- Require identity rotation before execution.

**Applies To:** TI-3 mandatory


#### 3.17.9 (GEN-09) ATLAS-GEN-NO-AUTO-UPDATE — No Autonomous Configuration Mutation

Systems MUST NOT autonomously update configuration, routing tables, identity scopes, data classifications, or capability boundaries. All modifications MUST be governed.

**Rationale**  
Autonomous updates create uncontrolled changes to trust surfaces.

**Implementation Notes**  
- Treat autonomous config writes as boundary violations.  
- Enforce signed, immutable configuration manifests.  
- Require governed workflows for all configuration changes.

**Applies To:** TI-2, TI-3


#### 3.17.10 (GEN-10) ATLAS-GEN-SIGN — Generated Artifacts Must Be Signed Before Execution

Generated artifacts MUST be cryptographically signed using identity-scoped keys prior to execution. Unsigned, malformed, or signature-mismatched artifacts MUST NOT execute.

**Rationale**  
Signing enforces provenance and prevents adversarial modification between generation and execution.

**Implementation Notes**  
- Use short-lived signing keys tied to generation identity.  
- Verify signatures inside execution sandbox before running.  
- Bind signatures to hash-chains for tamper detection.

**Applies To:** TI-3 mandatory

#### 3.17.11 (GEN-11) ATLAS-GEN-REVIEW — Governed Review of Generated Artifacts

Every generation event MUST pass through a governed review gate before execution. Review MUST validate identity, classification scope, trust domain alignment, transformation safety, and absence of privilege escalation. Review decisions MUST be immutable and TI-3 evidence MUST be produced.

**Rationale (Non-Normative)**  
Generated code is untrusted until fully validated. Review prevents silent or adversarial propagation.

**Implementation Notes**  
- Require human or independent-system review based on TI tier.  
- Enforce diff-based inspection before approval.  
- Bind reviews to non-repudiable signatures and lineage.

**Applies To:** TI-2, TI-3


#### 3.17.12 (GEN-12) ATLAS-GEN-NO-BYPASS — Generated Code Cannot Bypass Controls

Generated artifacts MUST NOT bypass identity ceilings, execution sandboxes, runtime boundaries, network restrictions, or control-plane rules. Attempts to circumvent controls MUST terminate generation and produce TI-3 evidence.

**Rationale**  
Without bypass prevention, models can generate code that circumvents enforcement layers.

**Implementation Notes**  
- Bind generated code to sandbox-enforced syscall ceilings.  
- Ensure routing, identity, and policy checks are re-applied post-generation.  
- Reject artifacts requiring additional privilege.

**Applies To:** TI-3 mandatory


#### 3.17.13 (GEN-13) ATLAS-GEN-AUDIT — TI-3 Evidence for All Generation Events

All code generation MUST produce TI-3 forensic evidence including:  
- prompt text,  
- model version and weights hash,  
- execution identity,  
- input classification,  
- output hash,  
- diff from previous generation cycles.

**Rationale**  
Generation without evidence creates untraceable execution surfaces and blind forensic zones.

**Implementation Notes**  
- Evidence MUST be signed and anchored to hash chains.  
- Store evidence in WORM sinks.  
- Retain evidence for lifetime of dependent artifacts.

**Applies To:** TI-3 mandatory


#### 3.17.14 (GEN-14) ATLAS-GEN-NO-RECURSION — No Recursive or Iterative Self-Generation

Models MUST NOT recursively trigger additional code generation cycles. Recursion or iterative self-triggering expansion MUST be blocked unless explicitly reviewed and declared under deterministic scope.

**Rationale**  
Recursive generation multiplies risk, creates runaway behavior, and breaks deterministic guarantees.

**Implementation Notes**  
- Disable “refine until safe” loops.  
- Log recursion attempts as TI-3 anomalies.  
- Require explicit governance for multi-stage generation pipelines.

**Applies To:** TI-3 mandatory


#### 3.17.15 (GEN-15) ATLAS-GEN-REG — Generation Restricted to Registered Policies

Only models, workflows, and generation pipelines registered in governed policy registries MAY generate code. Unregistered generators MUST be denied.

**Rationale**  
Unregistered generators fall outside governance and deterministic enforcement.

**Implementation Notes**  
- Maintain policy registry with signatures and lineage.  
- Reject any generator lacking registry fingerprint match.  
- Link registry entries to trust domains and ceilings.

**Applies To:** TI-2, TI-3


#### 3.17.16 (GEN-16) ATLAS-GEN-FINALITY — Finalization Before Execution

Generated artifacts MUST be finalized—immutable, signed, classification-validated—before any execution. Mutation after finalization MUST invalidate the artifact.

**Rationale**  
Finalization ensures deterministic, governed boundaries prior to execution.

**Implementation Notes**  
- Freeze artifacts via content hashing.  
- Disallow post-finalization edits or re-signing.  
- Require redeployment if changes are needed.

**Applies To:** TI-3 mandatory


#### 3.17.17 (GEN-17) ATLAS-GEN-TRUSTBOUND — Generated Code Must Not Create New Trust Domains

Generated artifacts MUST NOT create or assume new trust domains, identity classes, or privilege ceilings. Domain creation is solely a governance function.

**Rationale**  
AI-generated expansion of trust domains bypasses governance and breaks isolation obligations.

**Implementation Notes**  
- Reject attempts to modify domain or identity metadata.  
- Block generator-driven role creation.  
- Enforce strict domain boundaries inherited from prompts.

**Applies To:** TI-3 mandatory


#### 3.17.18 (GEN-18) ATLAS-GEN-NO-ENV-LEAK — No Environmental Exfiltration via Generation

Generated code MUST NOT extract or embed environment variables, secrets, host metadata, network topology, system fingerprints, or privileged contextual information.

**Rationale**  
Environment leakage enables privilege escalation, lateral movement, and covert exfiltration.

**Implementation Notes**  
- Sanitize environmental context before generation.  
- Monitor outputs for leakage patterns.  
- Treat detected leakage as TI-3 violation.

**Applies To:** TI-3 mandatory


#### 3.17.19 (GEN-19) ATLAS-GEN-NO-CRYPTOKEY — Models Cannot Generate Cryptographic Private Keys

Private keys MUST be generated only by governed key management systems. Models MUST NOT generate cryptographic private keys or materials resembling them.

**Rationale**  
Model-generated keys lack governance, lineage, and deterministic validation.

**Implementation Notes**  
- Block prompts requesting key generation.  
- Scan outputs for key patterns (RSA, ED25519, EC).  
- Auto-quarantine artifacts containing generated key-like material.

**Applies To:** TI-3 mandatory


#### 3.17.20 (GEN-20) ATLAS-GEN-NO-ESCALATE — Generated Code Cannot Escalate Privilege

Generated artifacts MUST NOT acquire or request privileges above their declared generation-time ceilings. Escalation attempts MUST invalidate the artifact and trigger TI-3 evidence.

**Rationale**  
Privilege escalation is the primary vector for generator-driven compromise.

**Implementation Notes**  
- Enforce strict privilege ceilings in execution sandboxes.  
- Detect operations requiring elevated capabilities.  
- Reject any code referencing unauthorized system calls or APIs.

**Applies To:** TI-3 mandatory

#### 3.17.21 (GEN-21) ATLAS-GEN-NO-DATA-LEAK — Generated Output Must Respect Data Classification

Generated outputs MUST inherit the highest classification of all inputs, prompts, embeddings, context windows, or retrieved data. Sensitive information MUST NOT be downgraded, declassified, or exposed in outputs without governed downgrade workflows. Classification inheritance MUST be strict and deterministic.

**Rationale (Non-Normative)**  
AI generation can unintentionally leak sensitive material through reconstruction, summarization, or rephrasing, bypassing traditional access controls.

**Implementation Notes**  
- Apply classification propagation from input → intermediate → output.  
- Block outputs that conflict with classification ceilings.  
- Enforce downgrade workflows for any reduction in sensitivity.

**Applies To:** TI-2, TI-3


#### 3.17.22 (GEN-22) ATLAS-GEN-NO-PIPELINE-BRIDGE — No Pipeline or Domain Boundary Bridging

Generated artifacts MUST NOT create logic that bridges execution pipelines, service layers, trust domains, clusters, namespaces, or identity boundaries. Cross-domain or cross-pipeline linking MUST be prohibited unless explicitly declared and governed.

**Rationale**  
Pipeline bridging enables lateral movement, identity inheritance, and unmonitored cross-domain propagation.

**Implementation Notes**  
- Detect cross-pipeline references or implicit bridging code.  
- Reject any generated artifact containing foreign-domain identifiers.  
- Identity-scoped sandboxes MUST enforce domain isolation.

**Applies To:** TI-3 mandatory


#### 3.17.23 (GEN-23) ATLAS-GEN-LOW-RUNNER — Generated Code Must Execute with Lowest Privilege

Generated artifacts MUST be executed with the minimal privilege required to perform their declared function. Privilege inheritance from generator, executor, or control-plane identities is prohibited.

**Rationale**  
Least-privilege execution prevents privilege escalation and sandbox escape by generated code.

**Implementation Notes**  
- Enforce privilege stripping before sandbox launch.  
- Bind execution identity to minimal capabilities.  
- Reject generated code requiring elevated access.

**Applies To:** TI-2, TI-3


#### 3.17.24 (GEN-24) ATLAS-GEN-MODEL-TRACE — Full Model Version and Lineage Traceability

All generation events MUST include full traceability metadata:  
- model name and version,  
- model weights hash,  
- training dataset classification,  
- fine-tuning lineage,  
- prompt template version,  
- runtime environment signature.

**Rationale**  
Deterministic trust requires reconstructing exactly *which* model produced the artifact.

**Implementation Notes**  
- Log model lineage into WORM evidence.  
- Bind model hash to generation event.  
- Require re-attestation when model lineage changes.

**Applies To:** TI-3 mandatory


#### 3.17.25 (GEN-25) ATLAS-GEN-THROTTLE — Deterministic Generation Rate Limiting

Code generation MUST be rate-limited to prevent runaway mutation, speculation spirals, or model-driven subgraph proliferation. Excessive generation activity MUST terminate execution.

**Rationale**  
Unchecked generation creates attack surface expansion and unpredictable propagation.

**Implementation Notes**  
- Enforce max generation cycles per identity.  
- Quarantine workloads exceeding thresholds.  
- Emit TI-3 evidence on throttling triggers.

**Applies To:** TI-3 mandatory


#### 3.17.26 (GEN-26) ATLAS-GEN-NO-RUNTIME-TRAIN — No Autonomous On-Device Training

Models MUST NOT train, fine-tune, self-adapt, or modify weights during runtime using live data unless explicitly governed within isolated enclaves. Runtime learning MUST be prohibited for deterministic-security workloads.

**Rationale**  
Live retraining introduces weight drift, invalidates lineage, and breaks deterministic execution guarantees.

**Implementation Notes**  
- Enforce read-only weights for runtime inference.  
- Block all gradient updates outside governed training lanes.  
- Treat attempts at runtime training as TI-3 violations.

**Applies To:** TI-3 mandatory


#### 3.17.27 (GEN-27) ATLAS-GEN-DIFF — Mandatory Output Diffing Against Trusted Baselines

Generated code MUST be automatically diffed against trusted baselines or reference patterns (e.g., curated boilerplates, whitelisted templates) before execution. Deviations MUST trigger review gates.

**Rationale**  
Diffing ensures generated logic aligns with approved behavior and prevents adversarial mutation.

**Implementation Notes**  
- Compare structure, control flow, and dependencies.  
- Identify suspicious expansions or privilege-adjacent features.  
- Require re-review for any non-trivial deviation.

**Applies To:** TI-2, TI-3


#### 3.17.28 (GEN-28) ATLAS-GEN-NO-SELF-EVAL — Models Cannot Self-Evaluate for Safety

Generated code MUST NOT rely on the same model (or derivative) to perform safety validation, code review, or security analysis. Validation MUST occur through independent, governed mechanisms.

**Rationale**  
Self-evaluation creates circular trust loops and hides adversarial tendencies or hallucinated safety.

**Implementation Notes**  
- Require independent validation pipelines.  
- Prohibit recursive “model judges its own output” flows.  
- Flag self-evaluation attempts as TI-3 anomalies.

**Applies To:** TI-3 mandatory


#### 3.17.29 (GEN-29) ATLAS-GEN-FAIL-CLOSED — Fail Closed on Ambiguous or Unsafe Generation

If generated output is ambiguous, unclear in intent, inconsistent with declared scope, or cannot be deterministically validated, generation MUST halt. Execution MUST NOT proceed under uncertainty.

**Rationale**  
Ambiguity creates security gaps and unpredictable behavior.

**Implementation Notes**  
- Reject outputs lacking clear semantics.  
- Require deterministic review before approval.  
- Halt immediately when validation cannot be completed.

**Applies To:** TI-3 mandatory


#### 3.17.30 (GEN-30) ATLAS-GEN-BREACH-INVALIDATE — Auto-Invalidate on Generation Boundary Breach

If generation occurs outside declared scope, trust ceiling, identity boundary, or domain, all dependent identities MUST be invalidated, execution MUST halt, and artifacts MUST be quarantined.

**Rationale**  
Out-of-scope generation indicates adversarial control or boundary violation.

**Implementation Notes**  
- Detect generation in unauthorized contexts.  
- Invalidate artifacts and rotation keys automatically.  
- Produce TI-3 evidence with complete lineage.

**Applies To:** TI-3 mandatory

---

### 3.18 Zero-Trust Runtime Policy Governance and Control-Plane Integrity Controls (ATLAS-CP)

Control-plane systems define the authoritative boundary of deterministic execution.  
They MUST be immutable, lineage-verifiable, identity-scoped, and inviolable by workloads, humans, CI pipelines, or autonomous agents.  
Any uncertainty in control-plane integrity MUST result in immediate halt or quarantine of dependent workloads.

---

#### 3.18.1 (CP-01) ATLAS-CP-GOV-ONLY — Governed Policy Application Only

Policies MAY ONLY be enacted through formally governed workflows that enforce identity validation, multi-party approval, and lineage tracking. Direct edits or implicit updates originating from workloads, human operators, automation scripts, or dynamic runtime events are strictly prohibited.

**Rationale**  
Without governed pathways, unauthorized modifications can silently alter trust ceilings, privilege boundaries, and domain relationships, enabling privilege escalation or covert compromise.

**Implementation Notes**  
- Enforce a dedicated governance API requiring cryptographic signatures.  
- Require immutable approval logs for every policy application.  
- Disallow manual edits to policy stores or configuration backends.  
- Maintain a hash chain of policy versions to detect tampering.  
- Treat any non-governed modification attempt as a TI-3 violation.

**Applies To:** TI-2, TI-3


#### 3.18.2 (CP-02) ATLAS-CP-NO-RUNTIME-REWRITE — No Runtime Policy Mutation

Control-plane policies MUST NOT be altered during workload execution. Any mutation attempt, intentional or accidental, MUST force immediate workload halt and trigger TI-3 evidence logging.

**Rationale**  
Runtime policy mutation enables adversaries to reshape trust boundaries dynamically, bypassing deterministic constraints and invalidating isolation guarantees.

**Implementation Notes**  
- Enforce immutable snapshots loaded at deployment time.  
- Lock policy containers to read-only after initialization.  
- Monitor configuration stores for unauthorized diff changes.  
- Trigger policy-version mismatch alerts at runtime.  
- Quarantine affected workloads if policy drift is detected.

**Applies To:** TI-3 mandatory


#### 3.18.3 (CP-03) ATLAS-CP-APPROVAL — Multi-Party Policy Approval

Changes affecting identity ceilings, network scopes, sandbox boundaries, or trust-domain definitions MUST require multi-party approval under separate trust anchors. No single actor may authorize high-impact policy changes.

**Rationale**  
Single-root approval creates a single point of failure and allows insider threat or credential theft to reconfigure the entire control-plane unilaterally.

**Implementation Notes**  
- Require signatures from at least two independent governance identities.  
- Enforce domain-diverse approval (e.g., separate HSM roots).  
- Bind approvals to time windows with expiration.  
- Maintain auditable approval workflows with WORM evidence.  
- Reject any policy lacking the minimum signature threshold.

**Applies To:** TI-2, TI-3


#### 3.18.4 (CP-04) ATLAS-CP-IMMUTABLE-POLICY — Immutable Published Policies

Once a policy version is published, it MUST remain immutable. Historical policies MUST be stored as permanent, verifiable artifacts with cryptographic continuity, ensuring that policy lineage cannot be rewritten or obscured.

**Rationale**  
Immutability prevents rollback attacks, silent edits, and shadow modifications that can alter historical enforcement logic or invalidate forensic reconstruction.

**Implementation Notes**  
- Store policy versions in WORM evidence sinks.  
- Hash each policy and embed into an append-only ledger.  
- Enforce policy reloads only from verified snapshots.  
- Require policy fingerprint validation before workload startup.  
- Detect and block any attempt to overwrite older versions.

**Applies To:** TI-2, TI-3


#### 3.18.5 (CP-05) ATLAS-CP-LINEAGE — Policy Lineage Traceability

Every policy MUST contain a complete, cryptographically verifiable lineage record including author identity, approval identities, time of publication, domain applicability, full content hash, and deployment scope. Loss of lineage MUST invalidate policy enforcement.

**Rationale**  
Lineage provides the authoritative chain-of-custody for policy authority. Without it, policies become unverifiable, bypassable, or impersonable.

**Implementation Notes**  
- Require non-repudiable signatures for all lineage fields.  
- Maintain lineage entries in a global governance ledger.  
- Bind lineage to runtime artifacts and identity ceilings.  
- Verify lineage at every control-plane query.  
- Auto-quarantine workloads if lineage cannot be validated.

**Applies To:** TI-3 mandatory


#### 3.18.6 (CP-06) ATLAS-CP-NO-DOWNGRADE — Policy Cannot Weaken Protections

Policies MUST NOT weaken enforcement, expand trust boundaries, reduce ceilings, or disable constraints unless full governance lifecycle steps are executed. Any detected downgrade attempt MUST be treated as a breach.

**Rationale**  
Silent downgrades collapse deterministic security by reintroducing ambient trust or loosening tightly scoped privileges.

**Implementation Notes**  
- Detect downgrade diffs via signed comparisons.  
- Enforce policy-strength monotonicity rules.  
- Require explicit justification for any weakening event.  
- Lock critical ceilings against modification without multi-party approval.  
- Produce TI-3 evidence for rejected downgrade attempts.

**Applies To:** TI-3 mandatory


#### 3.18.7 (CP-07) ATLAS-CP-ISOLATED — Control-Plane Isolation from Workloads

Control-plane systems MUST operate in fully isolated environments. Workloads MUST NOT be able to invoke, introspect, modify, or influence the control-plane through API calls, environment variables, tokens, sidecars, or implicit trust assumptions.

**Rationale**  
Control-plane compromise instantly invalidates all downstream enforcement and creates a single catastrophic failure domain.

**Implementation Notes**  
- Physically and logically segregate governance nodes.  
- Use dedicated identities and firewall rules distinct from workload networks.  
- Block all inbound traffic from workloads to governance tiers.  
- Treat any workload-originated governance request as hostile.  
- Require attestation proofs for all governance operations.

**Applies To:** TI-2, TI-3

#### 3.18.8 (CP-08) ATLAS-CP-NO-TOKEN-REUSE — No Reuse of Control-Plane Credentials

Control-plane credentials MUST be strictly single-purpose and MUST NOT be reused for workload execution, CI/CD automation, monitoring agents, scripting tools, or operational pipelines. Any credential used for governance actions MUST be cryptographically isolated from all other identity domains.

**Rationale**  
Credential reuse collapses trust boundaries, allowing workloads or automation systems to impersonate governance authorities and escalate privilege horizontally or vertically.

**Implementation Notes**  
- Issue separate hardware-bound credentials for governance.  
- Enforce credential domain tagging and usage restrictions.  
- Detect and block credential presentation in non-governance contexts.  
- Require periodic rotation of governance credentials.  
- Emit TI-3 evidence on any attempt to repurpose governance tokens.

**Applies To:** TI-2, TI-3


#### 3.18.9 (CP-09) ATLAS-CP-CI-BOUNDARY — Build Systems Cannot Modify Runtime Policy

CI/CD systems MUST NOT modify, override, or inject runtime policy. Build pipelines MUST NOT adjust identity ceilings, network scopes, sandbox boundaries, or privileged access rules. Deployment pipelines MAY deliver artifacts but MUST NOT influence governance decisions.

**Rationale**  
Allowing CI/CD to modify runtime policy turns build servers into de facto governance authorities—one of the most dangerous privilege collapses in modern infrastructure.

**Implementation Notes**  
- Enforce strict separation between build artifacts and governance controls.  
- Validate all policy queries against governance-only identity roles.  
- Require attestation that pipelines did not alter policy manifests.  
- Treat pipeline-originated policy modifications as active compromise attempts.  
- Bind CI/CD identities to minimal privileges with immutable ceilings.

**Applies To:** TI-3 mandatory


#### 3.18.10 (CP-10) ATLAS-CP-EXEC-NO-OVERRIDE — Execution Cannot Override Policy

Running workloads MUST NOT override, bypass, or reinterpret control-plane policies. If a workload attempts a restricted action—such as unauthorized secret access, forbidden network expansion, or prohibited syscall escalation—the action MUST fail closed and generate TI-3 evidence.

**Rationale**  
If workloads can override policy, deterministic security collapses and the runtime becomes self-governing—an unacceptable security posture.

**Implementation Notes**  
- Enforce policy checks at syscall, network, filesystem, and identity layers.  
- Verify policy adherence on every high-risk action.  
- Bind enforcement to kernel/hypervisor-level controls.  
- Reject any request requiring elevated ceilings not present at deployment.  
- Produce high-integrity evidence for all override attempts.

**Applies To:** TI-2, TI-3


#### 3.18.11 (CP-11) ATLAS-CP-LOCKED-LD — Locked Logical Domains

Logical domains—including tenants, trust zones, namespaces, execution scopes, and identity groups—MUST be locked upon deployment. Workloads MUST NOT join, leave, merge, or create new domains without full governance lifecycle execution.

**Rationale**  
Dynamic modification of domains enables lateral movement, domain confusion attacks, and uncontrolled privilege expansion.

**Implementation Notes**  
- Bind each workload to static domain identifiers.  
- Validate domain membership against governance manifests at runtime.  
- Trigger auto-halt if a workload attempts to operate outside its domain.  
- Reject domain updates initiated by CI/CD or workloads.  
- Require multi-party approval for domain changes.

**Applies To:** TI-2, TI-3


#### 3.18.12 (CP-12) ATLAS-CP-ROTATE-FORCE — Forced Key Rotation on Governance Breach

Any detected anomaly affecting governance integrity—including lineage mismatch, policy tampering, or failed attestation—MUST initiate automated key rotation for affected identities and force revocation of their authority.

**Rationale**  
Governance breaches compromise trust roots; continuing with stale credentials risks total systemic compromise.

**Implementation Notes**  
- Trigger rotation via attestation mismatch or evidence tampering.  
- Rotate identity keys, signing keys, and encryption keys simultaneously.  
- Quarantine affected workloads until rotation completes.  
- Require governance approval to restore authority.  
- Produce TI-3 chain-of-custody evidence for every rotation event.

**Applies To:** TI-3 mandatory


#### 3.18.13 (CP-13) ATLAS-CP-AUTH-MULTI — Multi-Factor Authorization for Control Actions

Governance actions MUST require multi-factor authorization based on independent trust anchors. Governance actions MUST NOT rely on single-factor approval, cached sessions, bearer tokens, or long-lived credentials.

**Rationale**  
A single compromised device, token, or account must not be enough to alter systemic enforcement rules.

**Implementation Notes**  
- Require hardware-backed MFA for all governance actions.  
- Enforce independence between MFA factors (e.g., HSM + TOTP).  
- Reject governance operations from sessions lacking strong assurance.  
- Log MFA verification events as TI-3 evidence.  
- Rotate or invalidate MFA factors immediately after compromise.

**Applies To:** TI-2, TI-3


#### 3.18.14 (CP-14) ATLAS-CP-AUDIT-EVIDENCE — TI-3 Evidence for Governance Actions

All governance actions—including approvals, revocations, domain modifications, policy publication, and ceiling changes—MUST generate TI-3 level evidence. This evidence MUST include diffs, lineage, identity context, timestamps, and cryptographic signatures.

**Rationale**  
Without immutable evidence, governance becomes untraceable, disputes become unresolvable, and forensic reconstruction becomes impossible.

**Implementation Notes**  
- Log every governance action in an append-only WORM evidence store.  
- Include full before/after diffs for policy changes.  
- Perform cryptographic signing of each evidence record.  
- Correlate evidence to domain and identity lineage.  
- Reject governance events if evidence cannot be written.

**Applies To:** TI-3 mandatory

#### 3.18.15 (CP-15) ATLAS-CP-NO-SHADOW-GOV — No Shadow Governance Stores

No duplicate, hidden, or unofficial governance stores MAY exist. All governance logic, policy manifests, lineage records, and approval artifacts MUST reside exclusively within the primary governed control-plane. Any detection of a secondary or divergent policy store MUST immediately invalidate deployment.

**Rationale**  
Shadow governance stores undermine deterministic enforcement by creating competing sources of truth. Attackers frequently exploit misaligned or hidden config paths to inject alternate rulesets, override ceilings, or mask unauthorized modifications.

**Implementation Notes**  
- Continuously hash-compare primary governance store with all replicas.  
- Block any policy or config read from a non-governed location.  
- Perform periodic attestation to detect rogue synchronization targets.  
- Enforce strict API boundaries to prevent alternate persistence paths.  
- Quarantine workloads upon discovery of a secondary store.

**Applies To:** TI-2, TI-3


#### 3.18.16 (CP-16) ATLAS-CP-CONTROL-CEILING — Governance Privilege Ceiling

Governance identities MUST themselves operate under ceilings. No governance identity MAY exercise unrestricted override authority. Authority MUST be scoped by domain, policy type, time bounds, and privilege limits.

**Rationale**  
Absolutist governance identities represent catastrophic single points of failure; compromise leads to total systemic control. Even governance must obey deterministic boundaries.

**Implementation Notes**  
- Implement multiple governance roles with domain-scoped ceilings.  
- Enforce time-bound governance tokens with expiration.  
- Require multi-party signatures for high-impact actions.  
- Maintain separate approval paths for critical actions (e.g., key rotation).  
- Produce TI-3 evidence for governance ceiling enforcement failures.

**Applies To:** TI-2, TI-3


#### 3.18.17 (CP-17) ATLAS-CP-BOOTSTRAP-LOCK — Bootstrapping Must Be Finite and Immutable

Bootstrap phases MUST terminate with fixed governance authority. Persistent or long-lived bootstrap modes are prohibited. Once governance roots are established, bootstrap capabilities MUST be revoked and made cryptographically invalid.

**Rationale**  
Open or persistent bootstrap modes are a top-tier attack vector. Adversaries exploit them to gain governance privileges without detection.

**Implementation Notes**  
- Enforce strict time limits for bootstrap mode.  
- Invalidate bootstrap credentials after first governance activation.  
- Hash-commit the final bootstrap state into governance lineage.  
- Block any request attempting to re-enter bootstrap mode.  
- Generate TI-3 evidence whenever bootstrap mode is invoked.

**Applies To:** TI-3 mandatory


#### 3.18.18 (CP-18) ATLAS-CP-FAIL-CLOSED — Fail Closed on Control-Plane Ambiguity

If the control-plane enters an ambiguous state—missing lineage, mismatched signatures, unavailable policy store, failed attestation, conflicting versions—it MUST fail closed. Dependent workloads MUST halt until integrity is restored.

**Rationale**  
Ambiguous governance transforms deterministic enforcement into undefined behavior. Undefined control-plane states are indistinguishable from compromise.

**Implementation Notes**  
- Enforce periodic governance attestation.  
- Validate lineage and signature consistency before policy queries.  
- Disable workloads automatically upon detection of control-plane drift.  
- Require governance recovery workflows to restore service.  
- Produce TI-3 evidence for all ambiguity events.

**Applies To:** TI-3 mandatory


#### 3.18.19 (CP-19) ATLAS-CP-REPLAY-BLOCK — Governance Replay Protection

Governance decisions MUST be protected against replay attacks. Control-plane enforcement MUST reject stale approvals, outdated signatures, expired tokens, and previously executed workflows.

**Rationale**  
Replay of governance operations enables covert privilege elevation, rollback attacks, or unauthorized reactivation of deprecated policy versions.

**Implementation Notes**  
- Timestamp and nonce-bind all governance operations.  
- Store execution fingerprints in WORM evidence stores.  
- Reject approvals referencing older lineage hashes.  
- Require fresh signatures for each operation.  
- Emit TI-3 evidence for all rejected replay attempts.

**Applies To:** TI-2, TI-3


#### 3.18.20 (CP-20) ATLAS-CP-REVOKE-FORCE — Revocation Must Cascade

When governance revokes a policy, identity, privilege ceiling, or domain assignment, all dependent workloads MUST immediately lose authority. Cascade revocation MUST be automatic and not rely on workload cooperation.

**Rationale**  
Failure to revoke dependent authority allows compromised workloads to operate with stale privileges, enabling lateral movement and persistent threats.

**Implementation Notes**  
- Implement dependency graphs for domain, identity, and policy relationships.  
- Force workload termination upon revocation events.  
- Block revalidation attempts until governance reinstates privileges.  
- Anchor revocation events to immutable TI-3 evidence.  
- Enforce immediate key rotation for revoked identities.

**Applies To:** TI-3 mandatory


#### 3.18.21 (CP-21) ATLAS-CP-NO-SELF-AUTHORIZE — No Self-Authorization

Governance identities MUST NOT approve their own policy changes, privilege requests, domain expansions, or identity modifications. All governance modifications MUST require approval from independent identities.

**Rationale**  
Self-authorization creates a privilege singularity: compromise of a single identity equals complete control-plane takeover.

**Implementation Notes**  
- Enforce independence of approvers via cryptographic domain separation.  
- Block governance requests where the requester matches any required approver.  
- Log all self-authorization attempts as TI-3 anomalies.  
- Require multi-party workflows for identity changes.  
- Include approver separation in governance lineage.

**Applies To:** TI-2, TI-3

#### 3.18.22 (CP-22) ATLAS-CP-INTEGRITY-ATTEST — Continuous Control-Plane Integrity Attestation

The control-plane MUST periodically perform integrity attestation covering policy manifests, lineage records, signing keys, privilege ceilings, domain maps, and configuration surfaces. Any failure, mismatch, or unverifiable state MUST immediately invalidate dependent workloads and force containment until governance restores integrity.

**Rationale**  
Control-plane drift—caused by configuration corruption, silent tampering, or replication inconsistencies—creates blind spots where enforcement cannot be trusted. Continuous attestation ensures governance state remains authoritative, intact, and uncompromised.

**Implementation Notes**  
- Implement scheduled attestation at deterministic intervals.  
- Compare lineage hashes across governance replicas.  
- Validate signing key integrity via HSM-bound proofs.  
- Refuse to answer policy queries during attestation failures.  
- Write TI-3 attestation results into append-only WORM evidence logs.

**Applies To:** TI-3 mandatory


#### 3.18.23 (CP-23) ATLAS-CP-NO-ADVISORY-MODE — No Advisory-Only Enforcement

Control-plane enforcement MUST NOT operate in advisory, report-only, or permissive modes. Policies MUST be enforced with mandatory, hard-fail semantics. “Log-only” or “warn-only” behavior is prohibited, as it creates a gap between policy definition and actual enforcement.

**Rationale**  
Advisory enforcement collapses deterministic guarantees, allowing workload misbehavior to proceed unchecked while giving a false sense of compliance.

**Implementation Notes**  
- Enforce hard-blocking on all policy violations.  
- Disable any configuration flag that reduces enforcement strictness.  
- Reject deployments attempting to run control-plane in non-enforcing mode.  
- Treat advisory attempts as governance misconfiguration events.  
- Log all violations as TI-3 evidence with required corrective actions.

**Applies To:** TI-2, TI-3


#### 3.18.24 (CP-24) ATLAS-CP-BOUNDARY-FIXED — Fixed Governance Boundaries

Trust domains, governance scopes, identity classes, and containment boundaries MUST be fixed once workloads are deployed. Expansion of boundaries—adding new domains, merging domains, or broadening ceilings—MUST require full governance lifecycle steps, including multi-party approval and lineage update.

**Rationale**  
Uncontrolled boundary expansion allows adversaries to gradually erode security constraints and pivot into new domains under the guise of legitimate updates.

**Implementation Notes**  
- Bind boundaries to deployment manifests with immutable hashes.  
- Detect boundary-expansion attempts at runtime.  
- Require domain-differential approvals before applying changes.  
- Reject pipeline-driven or automated boundary update requests.  
- Quarantine workloads whose domain boundaries diverge from governance state.

**Applies To:** TI-3 mandatory


#### 3.18.25 (CP-25) ATLAS-CP-BREACH-INVALIDATE — Auto-Invalidate on Control-Plane Breach

If governance tampering, lineage corruption, unauthorized modification attempts, or failed integrity proofs occur, all dependent workloads MUST be invalidated immediately. Identities MUST be revoked, caches purged, and execution halted until governance recovers and revalidates the system.

**Rationale**  
Given the centrality of the control-plane, any compromise—real or suspected—requires immediate revocation to prevent cascading systemic failure or privilege continuation.

**Implementation Notes**  
- Trigger automated revocation workflows on breach detection.  
- Force immediate identity invalidation across domains.  
- Block all policy queries until governance restores authority.  
- Generate TI-3 evidence for all breach-handling steps.  
- Require fresh attestation and re-approval before workloads resume.

**Applies To:** TI-3 mandatory


#### 3.18.26 (CP-26) ATLAS-CP-MODEL-GATE — Autonomous Systems Cannot Modify Governance

No AI system, agent, LLM, autonomous pipeline, or code-generation subsystem MAY create, modify, approve, revoke, or reinterpret governance policy. Governance MUST be exclusively human- or root-governance-driven, under strict multi-party controls.

**Rationale**  
Allowing autonomous systems to influence governance creates a recursive authority loop where models can sculpt their own constraints, bypass ceilings, or manipulate enforcement boundaries—an existential systemic risk.

**Implementation Notes**  
- Reject governance actions whose origin identity belongs to any AI or automated agent.  
- Require human cryptographic approval for all governance operations.  
- Log all AI-initiated governance attempts as TI-3 anomalies.  
- Enforce isolation between governance APIs and model-execution environments.  
- Validate that no automated system possesses governance-grade credentials.

**Applies To:** TI-3 mandatory

---

### 3.19 Trust-Domain Federation and Boundary Bridging Controls (ATLAS-FED)

Federation between trust domains MUST occur only under explicit governance, identity-scoped approvals, cryptographically verifiable attestation, and strictly defined scopes. Trust MUST NOT be implied, inherited, or transitively propagated. Every cross-domain interaction MUST remain narrow, reversible, governed, and non-escalatory.

---

#### 3.19.1 (FED-01) ATLAS-FED-DECLARED — Declared Federation Only

Federation MUST be explicitly declared, registered, and authorized through governed workflows. No implicit, ambient, or automatically inferred trust relationships MAY exist between domains.

**Rationale**  
Implicit federation creates unintended pathways for lateral movement, identity drift, and trust leakage across administrative boundaries.

**Implementation Notes**  
- Maintain a governed federation registry with immutable lineage.  
- Enforce signature verification before establishing any federation channel.  
- Reject federation attempts not present in the registry.  
- Produce TI-3 evidence for all federation approvals.  
- Trigger auto-halt for undeclared federation attempts.

**Applies To:** TI-2, TI-3


#### 3.19.2 (FED-02) ATLAS-FED-NO-TRANSITIVE — No Transitive Federation

Federation MUST NOT become transitive. A trust relationship between Domain A and Domain B MUST NOT imply trust between Domain A and Domain C or B and C. Each federation MUST be explicitly defined and non-inferable.

**Rationale**  
Transitive federation leads to uncontrolled trust propagation, rapidly eroding separation and enabling multi-hop compromise.

**Implementation Notes**  
- Enforce domain-isolated scopes for each federation pair.  
- Reject chained federation requests initiated via intermediate domains.  
- Reset identity context upon federation boundary crossing.  
- Emit TI-3 evidence for detected transitive attempts.  
- Bind federation to explicit contract-like configurations.

**Applies To:** TI-2, TI-3


#### 3.19.3 (FED-03) ATLAS-FED-IDENTITY — Identity-Scoped Federation

Federation MUST bind narrowly defined identities to narrowly defined roles across domains. Domain-wide or group-wide federation is prohibited. Each permission MUST apply only to specific, declared identities.

**Rationale**  
Identity-scoped federation limits blast radius, prevents global access expansion, and ensures precise accountability.

**Implementation Notes**  
- Require identity-level scoping for all federated permissions.  
- Block domain-level or group-level privileges.  
- Tie federation to identity lineage and cryptographic signatures.  
- Enforce revoke-cascade when identities change.  
- Record identity mapping in TI-3 evidence.

**Applies To:** TI-2, TI-3


#### 3.19.4 (FED-04) ATLAS-FED-SCOPE-LIMIT — Federated Scope Limits

Federation MUST define explicit, minimal scopes—datasets, APIs, functions, or operations. Scope expansion MUST require governance review. No “broad access” or catch-all federation MAY exist.

**Rationale**  
Minimal-scoped federation prevents domain overreach and ensures that cross-domain privileges do not unintentionally escalate.

**Implementation Notes**  
- Require predeclared scope manifests.  
- Enforce deny-by-default for any action outside scope.  
- Detect and block attempts to escalate or broaden scope dynamically.  
- Validate scope on every federated call.  
- Emit TI-3 evidence for scope-bound rejections.

**Applies To:** TI-2, TI-3


#### 3.19.5 (FED-05) ATLAS-FED-REVERSIBLE — Federation Must Be Reversible

Federation MUST be revocable unilaterally. A domain MUST be able to revoke federation without cooperation, approval, or action from the remote domain. Revocation MUST instantly remove access.

**Rationale**  
Federation durability without local reversibility creates vendor lock-in, privilege persistence, and uncontrolled access continuation after compromise.

**Implementation Notes**  
- Implement unilateral revoke mechanisms bound to governance.  
- Terminate federated sessions on revoke instantly.  
- Rotate keys and invalidate identity links automatically.  
- Require remote domain to re-attest after revocation.  
- Log revocation events as TI-3 evidence.

**Applies To:** TI-3 mandatory


#### 3.19.6 (FED-06) ATLAS-FED-NO-SECRET-SHARE — No Private Key Sharing Across Domains

Domains MUST NOT exchange private keys, bearer tokens, password equivalents, shared secrets, or identity-seeding material for federation. Trust MUST be established through cryptographically verifiable interactions, not secret sharing.

**Rationale**  
Secret sharing destroys domain independence and allows impersonation, privilege misuse, and cross-domain compromise.

**Implementation Notes**  
- Require asymmetric cryptography for federation.  
- Reject any request to export identity secrets.  
- Enforce strict isolation of all private keys in HSMs.  
- Detect and block embedded secrets in federation payloads.  
- Quarantine workloads involved in attempted secret transfer.

**Applies To:** TI-3 mandatory


#### 3.19.7 (FED-07) ATLAS-FED-BRIDGE — Approved Boundary Bridges Only

Domain federation MUST occur only via approved federation bridges—explicitly declared, isolated, auditable components. Direct peer-to-peer federation is prohibited unless passing through governed bridging surfaces.

**Rationale**  
Bridgeless federation bypasses governance, removes observability, and enables uncontrolled trust propagation.

**Implementation Notes**  
- Register all bridges in governance lineage.  
- Validate identity and scope at bridge ingress/egress.  
- Block direct domain-domain negotiation.  
- Require TI-3 evidence for all bridge-mediated interactions.  
- Enforce strict rate limits and anomaly detection per bridge.

**Applies To:** TI-2, TI-3


#### 3.19.8 (FED-08) ATLAS-FED-NO-FALLBACK — No Fallback to Unfederated Modes

If federation cannot be validated (stale signatures, expired tokens, unreachable bridge, conflicting lineage), interaction MUST fail closed. Systems MUST NOT revert to open, permissive, or “best effort” access.

**Rationale**  
Fallback behavior destroys deterministic enforcement, allowing communication without trust verification—an attacker’s ideal bypass vector.

**Implementation Notes**  
- Enforce FED-required checks at every cross-domain call.  
- Treat unverified federation as failure, not degraded mode.  
- Require explicit governance reauthorization before resuming.  
- Generate TI-3 evidence for all fallback-blocking events.  
- Lock workloads attempting fallback behavior.

**Applies To:** TI-3 mandatory

#### 3.19.9 (FED-09) ATLAS-FED-ATTEST — Domain Attestation Required

Federated domains MUST provide cryptographic attestation proving their identity, configuration integrity, policy version, enforcement state, and federation readiness before any cross-domain operation occurs. Attestation MUST occur at session start and periodically during long-running interactions.

**Rationale**  
Without continuous attestation, domains may silently drift, degrade, or be compromised. Cross-domain access based on stale assumptions collapses deterministic trust and introduces lateral contamination.

**Implementation Notes**  
- Require hardware-backed attestation where available (TPM, HSM, SGX, SEV).  
- Verify lineage, policy hash, and enforcement mode before granting access.  
- Enforce periodic attestation refresh for long-lived sessions.  
- Reject calls from domains with mismatched or unverifiable attestation.  
- Emit TI-3 evidence for all attestation verification events.

**Applies To:** TI-3 mandatory


#### 3.19.10 (FED-10) ATLAS-FED-PROV — Federation Must Preserve Provenance

Federated exchanges MUST preserve full provenance, classification metadata, identity origin, and trust-domain context. Federation MUST NOT strip metadata or downgrade sensitivity. All cross-domain artifacts MUST remain trackable end-to-end.

**Rationale**  
Metadata loss enables misclassification, privilege escalation, and covert data laundering across domains. Provenance preservation is essential for consistent enforcement.

**Implementation Notes**  
- Bind provenance metadata to payloads cryptographically.  
- Reject payloads lacking complete lineage and classification.  
- Require provenance propagation across transformations.  
- Prevent domains from downgrading metadata they receive.  
- Generate TI-3 evidence for provenance mismatches or drops.

**Applies To:** TI-2, TI-3


#### 3.19.11 (FED-11) ATLAS-FED-NO-REDELEGATION — No Delegated Re-Exposure

Federated privileges MUST NOT be delegated, proxied, inherited, or re-exposed to additional identities or domains without explicit governance approval. Privileges granted for federation MUST remain bound to their original intent.

**Rationale**  
Delegation expands trust boundaries uncontrollably, breaking the explicit-scoping guarantees of deterministic security and enabling privilege chaining attacks.

**Implementation Notes**  
- Enforce identity-scoped authorization at federation boundaries.  
- Block secondary re-exposure of access tokens or session rights.  
- Require redelegation attempts to pass through governance with multi-party approval.  
- Detect nested or cascading privilege expansions.  
- Record all redelegation blocks as TI-3 evidence.

**Applies To:** TI-3 mandatory


#### 3.19.12 (FED-12) ATLAS-FED-NO-GATEWAY — Domains Cannot Act as Gateways

A federated domain MUST NOT act as a gateway, router, or broker by granting access to additional domains or subsystems. Federation MUST occur only between explicitly paired domains, not through intermediaries.

**Rationale**  
Gateway behavior turns trusted domains into unintended transit hubs, enabling unmonitored lateral expansion and policy circumvention.

**Implementation Notes**  
- Enforce single-hop-only federation semantics.  
- Reject calls forwarded by intermediate domains.  
- Bind request origin cryptographically to prevent re-origination.  
- Require direct domain-to-domain attestation rather than via proxies.  
- Log all gateway behavior attempts as TI-3 anomalies.

**Applies To:** TI-2, TI-3


#### 3.19.13 (FED-13) ATLAS-FED-NO-REAUTH — No Reauthorization on Behalf

A domain MUST NOT generate authorization tokens, delegated credentials, or session keys on behalf of external entities. All cross-domain requests MUST originate from the authentic identity with its own authority and lineage.

**Rationale**  
Reauthorization on behalf enables impersonation, privilege laundering, and identity confusion attacks across federation boundaries.

**Implementation Notes**  
- Require request signatures tied to the original caller.  
- Reject any externally generated tokens claiming to represent another identity.  
- Enforce HSM-bound signing for federated identity proofs.  
- Detect “token for another” or delegated-key generation attempts.  
- Treat unauthorized reauthorization as TI-3 severity.

**Applies To:** TI-3 mandatory


#### 3.19.14 (FED-14) ATLAS-FED-LEASE — Time-Bound Federation

Federation MUST operate under a lease model with explicit start time, expiration time, and revocation conditions. Leases MUST NOT be indefinite, auto-renewing, or long-lived beyond necessity.

**Rationale**  
Long-lived federation enables privilege persistence, delayed-detection compromise, and unmonitored cross-domain access long after relationships should have expired.

**Implementation Notes**  
- Enforce strict federation expiration and automatic deprovisioning.  
- Require re-attestation before issuing a new lease.  
- Bind lease duration to governance-approved policy ceilings.  
- Invalidate sessions exceeding lease expiry instantly.  
- Emit TI-3 evidence for lease issuance, renewal, and expiration.

**Applies To:** TI-2, TI-3


#### 3.19.15 (FED-15) ATLAS-FED-ANOMALY — Anomaly-Based Auto-Revoke

If suspicious cross-domain behavior is detected—unexpected volume, unusual timing, forbidden access patterns, or classification mismatches—federated access MUST be auto-revoked and the involved identities quarantined.

**Rationale**  
Anomalies often precede escalation, domain pivoting, or credential theft. Auto-revocation prevents adversaries from capitalizing on early footholds.

**Implementation Notes**  
- Implement anomaly scoring on cross-domain events.  
- Auto-trigger revocation workflows if threshold exceeded.  
- Quarantine active federated sessions pending investigation.  
- Issue immediate key rotation for affected identities.  
- Log anomaly context in TI-3 evidence.

**Applies To:** TI-3 mandatory


#### 3.19.16 (FED-16) ATLAS-FED-NO-MASK — No Identity Masking

Federation MUST NOT mask, anonymize, or relay identities. Cross-domain operations MUST always present the original requesting identity, bound to its cryptographic proof and domain lineage.

**Rationale**  
Identity masking creates blind forensic zones and enables untraceable access, defeating deterministic accountability across domains.

**Implementation Notes**  
- Require original-identity signatures on all cross-domain requests.  
- Block identity relaying or identity-merging behavior.  
- Bind request metadata to evidence-grade identity proofs.  
- Require TI-3 logging of all identity-presenting operations.  
- Flag masked identities as immediate violations.

**Applies To:** TI-2, TI-3

#### 3.19.17 (FED-17) ATLAS-FED-NO-IMPERSONATION — Identity Cannot Be Assumed

Federated calls MUST NOT assume identities from the remote domain under any circumstance. Remote credentials, tokens, or authority assertions MUST NOT be imported or used locally. Every cross-domain request MUST originate from the authentic, original identity without substitution.

**Rationale**  
Identity assumption collapses the separation between domains and enables adversarial identity takeover, privilege laundering, and cross-domain impersonation attacks.

**Implementation Notes**  
- Enforce strict verification of request origin signatures tied to the calling domain.  
- Reject any credential that claims origin from a foreign domain.  
- Require HSM-bound signatures to prevent identity cloning.  
- Detect identity mismatch between caller metadata and signatures.  
- Log impersonation attempts as TI-3 severity violations.

**Applies To:** TI-2, TI-3


#### 3.19.18 (FED-18) ATLAS-FED-POLICY-INDEPENDENT — Federation Does Not Grant Policy Override

Federation MUST NOT modify, soften, or override internal policy enforcement within a domain. Each domain MUST independently enforce its ceilings, controls, classification rules, and deterministic boundaries even when interacting with external domains.

**Rationale**  
Allowing foreign policy definitions to override local controls creates inconsistent enforcement and exposes domains to weaker external standards.

**Implementation Notes**  
- Hard-enforce local ceilings even during federated operations.  
- Compare policy lineage between domains without merging.  
- Block remote policy suggestions, hints, or override markers.  
- Require internal enforcement checks before executing cross-domain actions.  
- Emit TI-3 evidence when rejecting foreign policy override attempts.

**Applies To:** TI-2, TI-3


#### 3.19.19 (FED-19) ATLAS-FED-CONFLICT — Policy Conflict Resolution Favors Higher Security

When two federated domains apply conflicting policies, the stricter policy MUST always apply. Federation MUST default to the highest-security interpretation rather than weaken enforcement.

**Rationale**  
Security downgrade through weaker partner domains is a well-known failure mode in federated systems; deterministic execution requires upward resolution only.

**Implementation Notes**  
- Implement “strictest-wins” conflict resolution algorithms.  
- Reject cross-domain actions when conflict cannot be resolved deterministically.  
- Require classification union rules (never intersection-min).  
- Produce TI-3 evidence documenting conflict and resolution path.  
- Trigger governance escalation for repeated conflicts.

**Applies To:** TI-2, TI-3


#### 3.19.20 (FED-20) ATLAS-FED-RUNTIME-BOUND — Domain Boundaries Apply at Runtime

Federation enforcement MUST persist throughout runtime. Revocation, expiry, lineage mismatch, attestation failure, or conflict MUST immediately invalidate active sessions, even mid-operation. Runtime federation MUST NOT rely on startup-only checks.

**Rationale**  
Attackers exploit long-lived sessions with stale federation to maintain access after revocation, boundary update, or compromise.

**Implementation Notes**  
- Perform continuous validation of federation leases.  
- Auto-terminate active sessions on revocation or attestation drift.  
- Block cached authorization decisions beyond their TTL.  
- Require mid-session re-attestation for long-running operations.  
- Generate TI-3 evidence for all runtime-boundary enforcement actions.

**Applies To:** TI-3 mandatory


#### 3.19.21 (FED-21) ATLAS-FED-NO-SHARED-ROOT — Domains Cannot Share Root Authorities

Federated domains MUST maintain independent root authorities. Domains MUST NOT rely on shared CA roots, mutual identity issuers, or cross-domain signing keys. Root authority separation is mandatory to maintain boundary integrity.

**Rationale**  
Shared root authorities collapse domain separation, enabling cross-domain impersonation, privilege inheritance, and trust drift.

**Implementation Notes**  
- Bind each domain to unique root-of-trust authorities.  
- Reject certificates signed by external or shared issuers.  
- Require foreign domains to validate identity through federation bridges only.  
- Enforce key lineage uniqueness per domain.  
- Log shared-root detection as TI-3 severity.

**Applies To:** TI-3 mandatory


#### 3.19.22 (FED-22) ATLAS-FED-NO-MERGE — Federation Is Not Domain Merging

Federation MUST NOT merge trust domains, identities, classification systems, or access ceilings. Each domain MUST retain its independent enforcement. Merging domains requires explicit decommission and redeployment under governance—not federation.

**Rationale**  
Domain merging removes the fundamental isolation guarantees that deterministic security depends upon.

**Implementation Notes**  
- Prevent merging of identity stores or classification schemas.  
- Reject federated requests attempting to treat domains as unified.  
- Require redeployment workflows for legitimate domain merges.  
- Detect drift toward merging and quarantine affected sessions.  
- Produce TI-3 evidence describing merge-attempt anomalies.

**Applies To:** TI-2, TI-3


#### 3.19.23 (FED-23) ATLAS-FED-ONEWAY — One-Way Federation Allowed

Federation may operate in one direction. A → B access does not imply B → A access. Reciprocity MUST NOT be assumed without explicit governance approval and independent federation entries.

**Rationale**  
One-way trust reduces attack surface and prevents automatic bidirectional privilege expansion.

**Implementation Notes**  
- Require separate governance entries for each direction.  
- Enforce independent identity scopes for A→B and B→A.  
- Validate directional lineage before permitting access.  
- Reject any request implying reciprocal trust not registered.  
- Log directional asymmetry evidence in TI-3 records.

**Applies To:** TI-2, TI-3


#### 3.19.24 (FED-24) ATLAS-FED-EVIDENCE — Federation Must Produce TI-3 Evidence

All federated interactions—authentication, authorization, data exchange, attestation, and boundary decisions—MUST produce TI-3 evidence, cryptographically binding caller identity, trust domain, scope, lineage, and applied policy.

**Rationale**  
Federation without layered, high-integrity evidence creates blind zones for forensics and prevents reconstruction of cross-domain events.

**Implementation Notes**  
- Require evidence generation at both initiator and receiver.  
- Anchor evidence in WORM storage with hash-chain continuity.  
- Capture domain identifiers, classification, and scope.  
- Bind each federated call to its attestation state.  
- Quarantine events lacking TI-3 evidence.

**Applies To:** TI-3 mandatory


#### 3.19.25 (FED-25) ATLAS-FED-BREACH-INVALIDATE — Federation Breach Auto-Invalidate

If federation channels are breached—compromised attestation, invalid lineage, tampering detection, or unexpected scope expansions—all dependent permissions, identities, leases, and active sessions MUST be invalidated immediately.

**Rationale**  
Federation breach invalidation prevents adversaries from laterally exploiting the compromised domain or maintaining access post-compromise.

**Implementation Notes**  
- Activate automated revocation workflows on any breach.  
- Force immediate key rotation and identity nullification.  
- Block all federated traffic until governance reinstates trust.  
- Require full re-attestation after breach recovery.  
- Log breach context and revocation actions as TI-3 evidence.

**Applies To:** TI-3 mandatory

---

### 3.20 Resilience, Fault Tolerance, and Deterministic Failure Controls (ATLAS-FAIL)

Failure and instability MUST never result in weakened controls, expanded privileges, relaxed enforcement, or incomplete evidence. Deterministic security requires that all failure paths remain tightly governed, identity-scoped, and fail-closed with forensic continuity.

---

#### 3.20.1 (FAIL-01) ATLAS-FAIL-CLOSED — Universal Fail-Closed Enforcement

All system components MUST fail in a closed, isolated, and non-operational state. Failures MUST prevent continuation of execution, privilege expansion, fallback to permissive defaults, or any form of uncontrolled behavior.

**Rationale**  
Failure states are prime opportunities for adversarial exploitation. If failure results in weakened enforcement, attackers gain unauthorized paths to escalate privileges or extract data.

**Implementation Notes**  
- Bind fail-closed behavior to kernel, enclave, or hypervisor layers.  
- Disable all network, filesystem, and identity surfaces during failure.  
- Reject all inbound and outbound operations post-failure.  
- Enforce deterministic shutdown paths with controlled termination.  
- Generate TI-3 evidence for all fail-closed events.

**Applies To:** TI-3 mandatory


#### 3.20.2 (FAIL-02) ATLAS-FAIL-NO-GRACE — No Graceful Degradation to Insecure Modes

Systems MUST NOT degrade into insecure or less restrictive modes. Identity enforcement, encryption, sandboxing, and network constraints MUST NOT be relaxed during failure or partial outage conditions.

**Rationale**  
Graceful degradation often reduces enforcement without explicit approval, creating silent windows of exposure that adversaries exploit.

**Implementation Notes**  
- Prohibit fallback to weaker authentication or plaintext channels.  
- Block automatic retries that skip enforcement checks.  
- Disable “best-effort” or “reduced mode” execution paths.  
- Require error surfaces to remain subject to full policy enforcement.  
- Record all failure-degradation attempts as TI-3 anomalies.

**Applies To:** TI-3 mandatory


#### 3.20.3 (FAIL-03) ATLAS-FAIL-EVIDENCE — Failure Generates Forensic Evidence

All failures—operational, security-related, or integrity-based—MUST produce TI-3 evidence containing identity context, classification, environmental state, boundary status, and the exact operation attempted at point of failure.

**Rationale**  
Without complete failure evidence, post-incident analysis becomes impossible, and failures may conceal compromise or adversarial action.

**Implementation Notes**  
- Bind evidence generation to pre-failure hooks.  
- Capture stack traces, identity lineage, and environment signatures.  
- Ensure evidence is written before system halt or isolation.  
- Store evidence in WORM pipelines with hash continuity.  
- Enforce evidence emission even when failure occurs inside enclaves.

**Applies To:** TI-3 mandatory


#### 3.20.4 (FAIL-04) ATLAS-FAIL-ISOLATION — Isolate System Upon Internal Error

If internal state becomes inconsistent, unverifiable, or corrupted, the system MUST isolate itself from all data, identity, network, and control-plane channels. Isolation MUST remain active until governance explicitly revalidates state.

**Rationale**  
Internal inconsistencies often signify memory corruption, tampering, or privilege bypass attempts—all of which demand immediate containment.

**Implementation Notes**  
- Disable all inbound/outbound network flows on isolation.  
- Seal access to secrets managers and identity stores.  
- Prevent processes from communicating with peers or sidecars.  
- Freeze internal execution surfaces until attestation succeeds.  
- Log isolation cause and scope as TI-3 evidence.

**Applies To:** TI-3 mandatory


#### 3.20.5 (FAIL-05) ATLAS-FAIL-NO-RECOVERY-WITHOUT-CHECK — No Automatic Recovery Without Validation

Systems MUST NOT automatically resume, retry, or reinitialize after failure. All recovery MUST be preceded by governance validation of identity, boundaries, state integrity, and enforcement readiness.

**Rationale**  
Automatic recovery can resume compromised workloads without verifying whether boundaries have been breached or residual tampering persists.

**Implementation Notes**  
- Enforce governance-driven revalidation workflows.  
- Require attestation before bringing workloads back online.  
- Block any attempt to self-heal without human or governed approval.  
- Hard-disable autorestart mechanisms unless wrapped in validation gates.  
- Log recovery approvals as TI-3 events.

**Applies To:** TI-2, TI-3


#### 3.20.6 (FAIL-06) ATLAS-FAIL-KEY-REVOKE — Failures Trigger Key Rotation

Failures that affect identity, domain boundaries, integrity checks, or security guarantees MUST trigger mandatory key rotation. Rotation MUST include identity keys, session keys, and signing keys tied to affected workloads.

**Rationale**  
A compromised or inconsistent environment can expose cryptographic material. Continuing with stale or potentially compromised keys invites exploitation.

**Implementation Notes**  
- Rotate keys immediately upon failure classification.  
- Bind rotation events to governance approval workflows.  
- Require fresh attestation before issuing new keys.  
- Invalidate sessions dependent on pre-rotation keys.  
- Emit TI-3 chain-of-custody evidence for all rotation operations.

**Applies To:** TI-3 mandatory

#### 3.20.7 (FAIL-07) ATLAS-FAIL-NO-BUFFER-FLUSH — No Unsafe Buffer Flush on Shutdown

Systems MUST NOT flush unencrypted, unclassified, or ungoverned data from memory to disk, swap files, temporary logs, crash dumps, analytics sinks, or system buffers during shutdown, crash, or panic conditions. Buffer contents MUST be treated as sensitive and zeroized or evidence-captured under controlled workflows.

**Rationale**  
Buffer flush during failure frequently leaks plaintext secrets, embeddings, intermediate datasets, model parameters, or privileged state into uncontrolled storage surfaces, enabling post-mortem extraction by attackers or insiders.

**Implementation Notes**  
- Override OS default crash-dump behavior for sensitive workloads.  
- Enforce encrypted, governed dump pipelines when dumps are mandatory.  
- Zeroize transient memory buffers before shutdown completes.  
- Disable swap for H2+ classification workloads.  
- Write TI-3 evidence when flush-prevention or zeroization is invoked.

**Applies To:** TI-3 mandatory


#### 3.20.8 (FAIL-08) ATLAS-FAIL-NO-FALLBACK-CONFIG — No Fallback to Default Configurations

Systems MUST NOT revert to default, developer, bootstrap, or permissive configurations during failure. All fallback behaviors MUST remain blocked when policy stores are unavailable, corrupted, unreachable, or partially loaded.

**Rationale**  
Defaults often include open ports, permissive identities, unencrypted channels, or broad privileges. Fallback to these creates catastrophic exposure during instability.

**Implementation Notes**  
- Enforce strict rejection of default policy files at runtime.  
- Require configuration signatures and lineage verification before use.  
- Block partial or fallback reads from missing configuration paths.  
- Wrap config loading with attestation checks.  
- Generate TI-3 evidence upon fallback-block attempts.

**Applies To:** TI-2, TI-3


#### 3.20.9 (FAIL-09) ATLAS-FAIL-NO-RETRY-ATTACK — Prevent Retry Loops as Attack Surface

Systems MUST NOT repeatedly retry privileged operations (auth, key retrieval, escalated syscalls, outbound flows) after failures. Retry loops MUST be capped, monitored, and fail-closed to prevent brute-force or timing-based exploitation.

**Rationale**  
Automated retries amplify attack surfaces by unintentionally brute-forcing credentials, repeatedly probing network surfaces, or generating predictable fault patterns attackers can exploit.

**Implementation Notes**  
- Enforce fixed retry ceilings for all privileged pathways.  
- Disable exponential-backoff patterns that leak timing metadata.  
- Treat repeated privileged-failure patterns as anomalies.  
- Force isolation or halt after retry ceiling violation.  
- Emit TI-3 logs for all retry-loop terminations.

**Applies To:** TI-2, TI-3


#### 3.20.10 (FAIL-10) ATLAS-FAIL-STATE-SEAL — Seal Compromised State

If system state becomes corrupted, unverifiable, tampered, or inconsistent with lineage, the state MUST be sealed. Sealed state MUST NOT be reused, reinitialized, partially executed, or rehydrated without explicit governance validation.

**Rationale**  
Reusing compromised state reintroduces tampered data, invalid classification, or adversarial changes, enabling repeat compromise or hidden persistence.

**Implementation Notes**  
- Mark sealed state immutable and non-executable.  
- Require governance workflows for state revalidation.  
- Block partial state restoration or selective rehydration.  
- Enforce strict signing and lineage checks before unsealing.  
- Produce TI-3 evidence recording seal reason and scope.

**Applies To:** TI-3 mandatory


#### 3.20.11 (FAIL-11) ATLAS-FAIL-RUNTIME-CEASE — Terminate Execution on Boundary Loss

If the system cannot verify identity boundaries, network boundaries, sandbox boundaries, or data-classification boundaries, execution MUST terminate immediately. Workloads MUST NOT continue under ambiguous boundary conditions.

**Rationale**  
Boundary loss indicates possible sandbox escape, network leakage, identity drift, or memory corruption, each of which represents high-severity compromise conditions.

**Implementation Notes**  
- Continuously verify boundary conditions at runtime.  
- Implement watchdogs for sandbox, identity, and network scopes.  
- Force immediate halt on boundary-inconsistency signals.  
- Prevent boundary auto-repair without governance.  
- Log boundary failures as TI-3 breach-level events.

**Applies To:** TI-3 mandatory


#### 3.20.12 (FAIL-12) ATLAS-FAIL-NO-ASYNC-CONTINUE — No Async Continuation After Failure

Asynchronous workers, background threads, GPU kernels, vector pipelines, or detached processes MUST NOT continue execution after the primary process encounters a failure. Async continuation MUST be blocked until governance revalidation.

**Rationale**  
Async workers often bypass main-loop safeguards, enabling unauthorized post-failure execution and uncontrolled data access or generation.

**Implementation Notes**  
- Bind async worker lifecycles to primary process health.  
- Automatically terminate detached jobs on primary-failure detection.  
- Require fresh identity and boundary checks for async restart.  
- Block message queues and pipelines during primary failure.  
- Generate TI-3 evidence for async-blocking events.

**Applies To:** TI-2, TI-3


#### 3.20.13 (FAIL-13) ATLAS-FAIL-CONTAIN — Blast Radius Containment

Failures MUST be contained within the smallest possible execution unit (sandbox, identity scope, namespace, thread group). Failure MUST NOT widen access, unlock new capabilities, or propagate across domains or clusters.

**Rationale**  
Uncontained failure amplifies impact, enabling cascading compromise and systemic instability across trust domains.

**Implementation Notes**  
- Partition workloads into deterministic isolation domains.  
- Block cross-namespace signaling during failure.  
- Zeroize or freeze state of failing unit without affecting peers.  
- Detect and block failure-driven privilege elevation.  
- Anchor containment boundaries to TI-3 evidence for correlation.

**Applies To:** TI-3 mandatory

#### 3.20.14 (FAIL-14) ATLAS-FAIL-VERSION-FREEZE — Freeze Execution Version on Failure

During any failure state—operational, security, attestation, or boundary-related—the execution environment MUST freeze its version, configuration, libraries, dependencies, and model artifacts. The system MUST NOT apply upgrades, downgrades, rollbacks, auto-patches, or live configuration mutations until governance completes a full validation cycle.

**Rationale**  
Attackers exploit failure-induced version drift and opportunistic updates to introduce tampered binaries, downgrade protections, or force environments into insecure states. Version freeze ensures the system remains stable and forensically reconstructable.

**Implementation Notes**  
- Disable all live-update channels during failure.  
- Bind version metadata to runtime lineage and freeze it until recovery.  
- Reject package-manager, container, or model-pulling operations post-failure.  
- Require governance-signed “unfreeze” approval before reactivation.  
- Emit TI-3 evidence capturing frozen versions and hashes.

**Applies To:** TI-2, TI-3


#### 3.20.15 (FAIL-15) ATLAS-FAIL-MEM-ZERO — Memory Zeroization on Failure

Sensitive memory—including secrets, embeddings, inference results, intermediate model states, identities, and key material—MUST be zeroized immediately upon crash, kernel panic, sandbox violation, or forced termination. Zeroization MUST occur before system halt or isolation completes.

**Rationale**  
During failure, residual memory content becomes accessible to crash dump tools, forensic scrapers, shared-memory peers, or low-level attackers. Zeroization eliminates post-failure data leakage vectors.

**Implementation Notes**  
- Implement secure memset or hardware-backed zeroization routines.  
- Zeroize GPU VRAM buffers for AI workloads.  
- Disable system crash dumps for H2+ classification domains unless encrypted.  
- Clear stack, heap, scratchpads, and ephemeral inference buffers.  
- Generate TI-3 evidence confirming zeroization completion.

**Applies To:** TI-3 mandatory


#### 3.20.16 (FAIL-16) ATLAS-FAIL-NO-PERSIST — No Persistence of Failed State

Failed state—variables, buffers, temp files, partial computations, or unfinished transactions—MUST NOT be persisted except as TI-3 evidence. Failed state MUST NOT be rehydrated, reused, or cached into operational storage.

**Rationale**  
Persisting failed state creates corruption loops, propagates compromised artifacts, and introduces nondeterministic workflows that violate lineage guarantees.

**Implementation Notes**  
- Enforce “evidence-only persistence” after failure events.  
- Reject attempts to serialize incomplete computation graphs.  
- Block insertion of failed-state objects into caches or object stores.  
- Require new initialization cycle after failure recovery.  
- Store minimal forensic snapshots under governed WORM channels.

**Applies To:** TI-2, TI-3


#### 3.20.17 (FAIL-17) ATLAS-FAIL-PROVENANCE — Preserve Provenance Across Failure

Provenance MUST remain continuous and intact across failures. Failure MUST NOT reset lineage counters, provenance chains, classification markers, or identity-binding metadata. Provenance MUST reflect failure context without losing prior history.

**Rationale**  
Breaking provenance during failure conceals prior operations, corrupts lineage verification, and creates blind spots for adversarial tampering.

**Implementation Notes**  
- Maintain provenance hash chains regardless of state transitions.  
- Ensure failure evidence includes pre-failure lineage offsets.  
- Seal provenance state separately from computation state.  
- Require governance to validate provenance continuity after recovery.  
- Log provenance-preservation checks as TI-3 evidence.

**Applies To:** TI-3 mandatory


#### 3.20.18 (FAIL-18) ATLAS-FAIL-BYPASS-BLOCK — Block Alternative Paths During Downtime

Systems MUST NOT open alternative access routes, execution paths, network proxies, recovery tunnels, or out-of-band channels during failure. Any attempt to bypass normal execution paths due to downtime MUST fail closed.

**Rationale**  
Attackers often exploit downtime to force fallback routes such as debug shells, admin tunnels, or service-mesh bypasses. Blocking all alternative paths prevents such escalations.

**Implementation Notes**  
- Disable recovery ports that bypass identity enforcement.  
- Block dynamic route creation during downtime.  
- Enforce strict shutdown of auxiliary subsystems.  
- Monitor attempted use of emergency channels as TI-3 alerts.  
- Require governance approval for any recovery-line activation.

**Applies To:** TI-2, TI-3


#### 3.20.19 (FAIL-19) ATLAS-FAIL-BREACH-HALT — Breach-Typed Failure Halts System

If a failure pattern indicates a security breach—boundary loss, tampering signature, lineage corruption, or unauthorized escalation—the system MUST halt immediately and transition to quarantine. Breach-typed failures MUST not be treated as operational exceptions.

**Rationale**  
Treating breach indicators as recoverable operational faults exposes systems to cascading compromise and privilege persistence.

**Implementation Notes**  
- Build breach-detection logic into runtime attestation.  
- Immediately isolate identity-scoped workloads on breach signals.  
- Quarantine affected environments and revoke keys.  
- Require multi-root approval for breach recovery.  
- Log breach indicators as TI-3 forensic anchors.

**Applies To:** TI-3 mandatory


#### 3.20.20 (FAIL-20) ATLAS-FAIL-MULTI-ROOT — Multi-Root Authorization Required for Return to Service

After high-severity failure—classification error, sandbox escape, governance ambiguity, or breach-like failure—return to service MUST require approvals from multiple independent trust anchors. No single root may restore service.

**Rationale**  
Single-root authorization reintroduces a single point of catastrophic reactivation, enabling adversarial restoration after tampering.

**Implementation Notes**  
- Enforce dual or triple independent signature requirements.  
- Bind approval events to lineage and TI-3 evidence.  
- Require separate identity domains for each approving root.  
- Block automated or scripted reactivation flows.  
- Validate full boundary and attestation state before resuming.

**Applies To:** TI-3 mandatory

#### 3.20.21 (FAIL-21) ATLAS-FAIL-AI-LOCKDOWN — Lock Down Autonomous Systems on Failure

If any autonomous or semi-autonomous subsystem (models, agents, orchestration logic, code generators, policy planners) encounters failure, ambiguity, or attestation inconsistency, the system MUST enter lockdown. Autonomous behaviors MUST cease immediately, including inference loops, code generation, routing decisions, and configuration mutations.

**Rationale**  
Autonomous components amplify failure impact by continuing to act under degraded assumptions. Lockdown ensures that AI-driven decisions cannot propagate instability or escalate compromise.

**Implementation Notes**  
- Freeze autonomous execution threads on first-signaled failure.  
- Block further tool use, external calls, or action dispatches.  
- Zeroize intermediate AI states if classification requires.  
- Require governance unlock for return-to-operation.  
- Emit TI-3 evidence detailing autonomous activity at time of lockdown.

**Applies To:** TI-3 mandatory


#### 3.20.22 (FAIL-22) ATLAS-FAIL-CHAIN-SEAL — Cascade Seal on Dependency Failure

If any dependency—identity system, dataset, model, routing layer, enclave, sandbox, control-plane subsystem, or evidence pipeline—fails validation, dependent systems MUST immediately seal themselves. Sealed systems MUST NOT proceed, synchronize, output, or federate until dependencies recover under governance.

**Rationale**  
Dependency failures are a primary vector for cross-domain escalation, contaminated lineage, and inconsistent state propagation. Cascade sealing prevents dependent components from executing with invalid assumptions.

**Implementation Notes**  
- Detect upstream trust failures using attestation signals.  
- Seal dependent processes without partial continuation.  
- Quarantine dependent state for forensic review.  
- Disallow “continue-on-failure” semantics across trust layers.  
- Require governance confirmation before unsealing.

**Applies To:** TI-3 mandatory


#### 3.20.23 (FAIL-23) ATLAS-FAIL-QUARANTINE — Quarantine Failure Context

Failure contexts—including memory snapshots, failed state signatures, boundary hashes, partial computations, and identity scopes—MUST be quarantined in isolation. Quarantined artifacts MUST NOT interact with active domains and MUST remain immutable for forensic review.

**Rationale**  
Failure artifacts often contain evidence of tampering or adversarial manipulation. Quarantine ensures these artifacts cannot leak, corrupt lineage, or be weaponized by workloads.

**Implementation Notes**  
- Store artifacts in dedicated quarantine evidence enclaves.  
- Prevent rehydration or execution of quarantined content.  
- Bind all quarantined artifacts to TI-3 forensic metadata.  
- Enforce retention based on classification and regulatory requirements.  
- Issue alerts on any attempt to access or modify quarantined objects.

**Applies To:** TI-2, TI-3


#### 3.20.24 (FAIL-24) ATLAS-FAIL-CROSSDOMAIN — No Cross-Domain Collapse

A failure in one trust domain MUST NOT weaken, collapse, or reduce protections in another domain. Boundary failures MUST remain localized. Cross-domain cascade effects MUST be blocked, even when shared infrastructure is involved.

**Rationale**  
Modern distributed systems often expose shared infrastructure paths. Without strict isolation, a single-domain failure can become a multi-domain compromise. Preventing collapse preserves deterministic domain integrity.

**Implementation Notes**  
- Enforce identity and boundary isolation across all domains.  
- Block runtime propagation of degraded states via shared components.  
- Require independent attestation per domain post-failure.  
- Use cryptographic compartmentalization to prevent trust bleed-over.  
- Treat cross-domain failure propagation attempts as TI-3 anomalies.

**Applies To:** TI-3 mandatory


#### 3.20.25 (FAIL-25) ATLAS-FAIL-SELF-REPORT — Failure Must Self-Report

All failures—operational, runtime, identity-related, cryptographic, network, attestation, or sandbox—MUST self-report to governed evidence sinks. Silent failures, absorbed errors, or suppressed exception traces are prohibited. If reporting cannot occur, execution MUST halt.

**Rationale**  
Silent failures erase forensic visibility and invalidate deterministic reconstruction. Mandatory self-reporting ensures immediate detection and response.

**Implementation Notes**  
- Emit TI-3 failure events to immutable evidence stores.  
- Treat suppressed or missing logs as boundary violations.  
- Cryptographically sign all self-reported failure events.  
- Link failure reports to lineage, domain, and identity.  
- Halt execution if telemetry reporting channels fail.

**Applies To:** TI-3 mandatory

---

---

### 3.21 Temporal Integrity, Ordering, and Time-Bound Execution Controls (ATLAS-TIME)

Time MUST be treated as a first-class, governed security primitive. Temporal guarantees—synchronization, ordering, expiry, drift detection, and lease-based execution—are mandatory to prevent replay attacks, privilege extension, stale-state execution, and nondeterministic lineage. Temporal ambiguity MUST always result in fail-closed behavior.

---

#### 3.21.1 (TIME-01) ATLAS-TIME-SOURCE — Governed Time Sources Only

All security and governance decisions MUST rely exclusively on cryptographically verifiable, governed time sources. Local system clocks, hypervisor clocks, or container clocks MUST NOT independently determine temporal validity for security enforcement.

**Rationale**  
Attackers routinely manipulate local time to reopen expired windows, re-enable revoked privileges, or bypass replay protections. A unified, governed time root prevents desynchronization attacks and cross-domain temporal inconsistencies.

**Implementation Notes**  
- Use authenticated NTP/PTP with cryptographic verification.  
- Verify time provenance before accepting timestamps.  
- Reject events signed with unverifiable time sources.  
- Isolate time feeds from workload alteration.  
- Record time-source metadata in TI-3 evidence.

**Applies To:** TI-2, TI-3


#### 3.21.2 (TIME-02) ATLAS-TIME-SYNC-REQUIRED — Time Drift Invalidates Execution

If measured drift exceeds policy-defined thresholds, workloads MUST halt, quarantine, or re-attest. Temporal drift MUST be treated as a boundary failure, not an operational anomaly.

**Rationale**  
Even minor drift breaks replay windows, confuses ordering, disrupts identity expiry, and enables attack replay. Halting execution preserves deterministic lineage.

**Implementation Notes**  
- Continuously monitor drift against trusted anchors.  
- Enforce strict, non-adjustable drift thresholds for TI-3 workloads.  
- Quarantine workloads that exceed tolerances.  
- Generate TI-3 evidence on drift detection.  
- Require governance approval before resuming operation.

**Applies To:** TI-3 mandatory


#### 3.21.3 (TIME-03) ATLAS-TIME-EXPIRY — Mandatory Expiry for Privileges and Tokens

All privileges, access grants, tokens, and credentials MUST have explicit expiry windows. Permanent or indefinite privileges are prohibited under ATLAS-DESS.

**Rationale**  
Non-expiring credentials create persistent attack surfaces. Time-bound authorization limits the utility of compromised credentials and enforces periodic governance checks.

**Implementation Notes**  
- Enforce short-lived tokens for high-sensitivity identities.  
- Bind expiry metadata to identity-scoped keys.  
- Reject credentials lacking explicit expiry fields.  
- Require automatic re-attestation on renewal.  
- Produce TI-3 evidence on every expiry event.

**Applies To:** TI-2, TI-3


#### 3.21.4 (TIME-04) ATLAS-TIME-NO-LONG-SESSIONS — No Indefinite Session Continuity

Sessions MUST terminate after policy-defined durations and MUST require full re-attestation to continue. Sessions MUST NOT silently extend through activity alone.

**Rationale**  
Long-lived sessions enable privilege drift and stale-identity execution. Forced re-attestation ensures boundaries remain aligned with current policy and security state.

**Implementation Notes**  
- Define strict max-session thresholds for TI workloads.  
- Enforce session invalidation on timeouts regardless of activity.  
- Require multi-factor or identity binding on renewal.  
- Terminate session tokens securely, preventing reuse.  
- Log session lifetime and expiration under TI-3.

**Applies To:** TI-2, TI-3


#### 3.21.5 (TIME-05) ATLAS-TIME-ORDER-ENFORCE — Enforce Operation Ordering

Security-critical operations MUST follow validated sequence ordering. Out-of-order, backdated, or future-dated operations MUST be rejected and generate evidence.

**Rationale**  
Attackers exploit ordering violations to reorder privilege grants, manipulate datasets, or bypass revocation events. Enforcing strict ordering preserves lineage integrity.

**Implementation Notes**  
- Use monotonic counters tied to identity.  
- Reject operations arriving out of expected sequence.  
- Link ordering metadata to evidence and provenance.  
- Prevent pipeline reordering in distributed systems.  
- Trigger alerts on repeated ordering violations.

**Applies To:** TI-3 mandatory


#### 3.21.6 (TIME-06) ATLAS-TIME-REPLAY-BLOCK — Temporal Replay Prevention

Requests, tokens, signatures, or events outside their replay window MUST be rejected as adversarial. Replay windows MUST be short and policy-bound.

**Rationale**  
Replay attacks remain one of the most effective privilege escalation vectors. Enforcing time-bound request validity eliminates stale request reuse.

**Implementation Notes**  
- Bind request signatures to narrow time windows.  
- Use nonce-hash plus time to prevent reuse.  
- Treat late or early messages as TI-3 anomalies.  
- Require strict clock-alignment enforcement across domains.  
- Reject repeated requests regardless of origin.

**Applies To:** TI-2, TI-3


#### 3.21.7 (TIME-07) ATLAS-TIME-ROTATE — Time-Driven Key Rotation

Identity keys, session keys, encryption keys, and federation keys MUST rotate at fixed policy intervals independent of workload conditions.

**Rationale**  
Time-based rotation reduces exposure window for compromised material and prevents stale key continuity across policy or boundary changes.

**Implementation Notes**  
- Use policy-defined rotation schedules for each classification level.  
- Enforce automatic invalidation of previous key versions.  
- Require re-attestation after rotation.  
- Store rotation events as TI-3 lineage checkpoints.  
- Prohibit manual extension of key validity periods.

**Applies To:** TI-3 mandatory


#### 3.21.8 (TIME-08) ATLAS-TIME-MONOTONIC — Use Monotonic Counters for Critical Paths

Wall-clock time MUST NOT be the sole determinant for security-critical sequencing. Monotonic counters MUST enforce strict progress guarantees.

**Rationale**  
Wall clocks can drift or be manipulated. Monotonic counters ensure sequential correctness and prevent rollback or replay loops.

**Implementation Notes**  
- Assign counters to identities, models, and pipelines.  
- Reject requests without counter progression.  
- Reset counters only under governance.  
- Bind counters to evidence signatures.  
- Use per-domain, per-identity monotonic series.

**Applies To:** TI-2, TI-3


#### 3.21.9 (TIME-09) ATLAS-TIME-CLOCK-FALLBACK-BLOCK — No Fallback to Local Time

Fallback to system-local time MUST trigger immediate fail-closed behavior. Local time cannot be used as a fallback for temporal validation.

**Rationale**  
Fallback paths introduce covert downgrade vectors and allow attackers to manipulate local clock behavior undetected.

**Implementation Notes**  
- Continuously verify remote time anchor availability.  
- Treat fallback attempt as TI-3 anomaly.  
- Freeze execution until re-synchronization.  
- Disallow forced fallback through tool or API calls.  
- Record attempted fallbacks in evidence.

**Applies To:** TI-3 mandatory


#### 3.21.10 (TIME-10) ATLAS-TIME-GOV — Time Configuration Is Governance-Controlled

Time source selection, offset changes, drift thresholds, and replay window definitions MUST be governed and MAY NOT be modified dynamically or by workload-side logic.

**Rationale**  
Time configuration is a high-impact surface. Unauthorized time adjustments can bypass protections and corrupt lineage.

**Implementation Notes**  
- Require multi-root approval for configuration changes.  
- Make time-source modifications immutable after publication.  
- Record time-governance actions under TI-3 evidence.  
- Reject any runtime patching of NTP/PTP settings.  
- Tie time policy to domain-level boundaries.

**Applies To:** TI-2, TI-3


#### 3.21.11 (TIME-11) ATLAS-TIME-EVIDENCE — Temporal Evidence Binding

All evidence MUST include high-integrity timestamp metadata including source, drift, offset, and time-chain verification. Evidence lacking temporal context MUST NOT be trusted.

**Rationale**  
Temporal metadata anchors forensic reconstruction. Missing or unverifiable time irreparably breaks lineage and trust.

**Implementation Notes**  
- Bind timestamps to cryptographic signatures.  
- Include drift and provenance in log headers.  
- Reject evidence lacking time integrity.  
- Store time-chain state in WORM.  
- Emit TI-3 records for timestamp anomalies.

**Applies To:** TI-3 mandatory


#### 3.21.12 (TIME-12) ATLAS-TIME-NO-ASYNCHRONOUS-ESCALATION — Async Tasks Cannot Extend Privileges

Asynchronous tasks MUST NOT persist or extend privileges beyond original session validity. Background tasks MUST terminate when authorizing identity expires.

**Rationale**  
Async tasks can silently outlive sessions, bypass expiry, and act with stale privilege contexts.

**Implementation Notes**  
- Bind async tasks to issuing identity and session time.  
- Enforce hard-stop upon privilege expiry.  
- Require new re-attestation for async continuation.  
- Track async temporal chains in TI-3 evidence.  
- Prevent auto-renewal of privilege context.

**Applies To:** TI-2, TI-3


#### 3.21.13 (TIME-13) ATLAS-TIME-LEASED-IDENTITY — Identity Validity Is Time-Bound

Identities MUST expire and periodically re-prove legitimacy under governed workflows. Long-lived identities are prohibited.

**Rationale**  
Lease-based identities eliminate persistent compromise windows and reinforce identity freshness.

**Implementation Notes**  
- Assign identity lease durations based on classification.  
- Require re-attestation after expiration.  
- Invalidate expired identities automatically.  
- Bind lease metadata to evidence entries.  
- Prevent silent identity-extension mechanisms.

**Applies To:** TI-3 mandatory


#### 3.21.14 (TIME-14) ATLAS-TIME-MODEL-WINDOW — AI Outputs Have Validity Windows

Model-generated outputs—predictions, plans, embeddings, routing decisions, or code—MUST expire after defined windows. Stale outputs MUST NOT be executed or acted upon.

**Rationale**  
Stale model outputs reflect outdated risk context, potentially enabling unsafe decisions or incorrect authorizations.

**Implementation Notes**  
- Bind AI outputs to generation timestamp.  
- Reject execution of outputs older than policy permits.  
- Require regeneration for expired outputs.  
- Log AI expiry events for forensic review.  
- Prevent chain-of-thought reuse across windows.

**Applies To:** TI-2, TI-3


#### 3.21.15 (TIME-15) ATLAS-TIME-STATE-FREEZE — Freeze State on Temporal Ambiguity

If temporal integrity cannot be verified, system state MUST freeze immediately. No reads, writes, inference, or propagation may occur until revalidation succeeds.

**Rationale**  
Temporal ambiguity undermines every lineage and ordering guarantee. Freezing state prevents nondeterministic corruption.

**Implementation Notes**  
- Stop inbound/outbound flows on time-loss detection.  
- Preserve memory and lineage markers.  
- Prevent cache writes during ambiguity.  
- Require governance validation before unfreezing.  
- Emit TI-3 alerts for each freeze event.

**Applies To:** TI-3 mandatory


#### 3.21.16 (TIME-16) ATLAS-TIME-CROSS-DOMAIN-CONSISTENCY — Temporal Consistency Across Domains

Federated or multi-domain systems MUST maintain consistent time guarantees. Drift between domains invalidates federation and MUST terminate cross-domain operations.

**Rationale**  
Cross-domain replay, reordering, and privilege confusion emerge immediately when domain clocks diverge.

**Implementation Notes**  
- Require domain-level attestation of time alignment.  
- Reject federation tokens with inconsistent timestamps.  
- Enforce hard domain-quarantine when drift detected.  
- Store domain-drift anomalies as TI-3 evidence.  
- Require dual-domain re-attestation before reactivation.

**Applies To:** TI-3 mandatory


#### 3.21.17 (TIME-17) ATLAS-TIME-NO-BACKDATING — No Retroactive Time Application

Backdated timestamps, privileges, logs, or claims MUST be rejected. Retroactive time manipulation MUST be treated as a boundary violation.

**Rationale**  
Backdating rewrites history, enables privilege resurrection, and corrupts forensic accuracy.

**Implementation Notes**  
- Compare timestamps against monotonic counters.  
- Reject any event with earlier-than-expected time.  
- Detect and log repeated backdating attempts.  
- Prevent post-hoc timestamp manipulation.  
- Block federation for backdated claims.

**Applies To:** TI-2, TI-3


#### 3.21.18 (TIME-18) ATLAS-TIME-NO-FORWARD-DATING — No Future-Timestamp Execution

Requests timestamped in the future MUST be treated as anomalous and blocked.

**Rationale**  
Future timestamps indicate tampering, drift, or intentional manipulation to bypass ordering and replay controls.

**Implementation Notes**  
- Validate all timestamps against trusted time anchors.  
- Log future-dated events as TI-3 anomalies.  
- Prevent pipelines from queueing future-dated tasks.  
- Treat repeated future timestamps as escalation attempts.  
- Enforce strict drift tolerances per classification.

**Applies To:** TI-3 mandatory


#### 3.21.19 (TIME-19) ATLAS-TIME-STATE-SNAP — Snapshot State Must Record Time Context

Snapshots MUST include full temporal metadata: timestamp, drift, domain alignment state, and replay-window parameters. Snapshots lacking temporal context MUST NOT be restored.

**Rationale**  
Temporal context is required to safely rehydrate system state. Snapshots without time enable replay attacks and lineage breaks.

**Implementation Notes**  
- Bind snapshot metadata to cryptographic hash chains.  
- Reject restoration if time context is missing.  
- Document replay windows in snapshot metadata.  
- Require governance review before snapshot rehydration.  
- Store snapshot time context in WORM evidence.

**Applies To:** TI-2, TI-3


#### 3.21.20 (TIME-20) ATLAS-TIME-STAGGER — Execution Spread to Prevent Time-Amplified Attacks

Synchronized mass-execution MUST be staggered to reduce timing amplification, cascading failures, and clock-aligned attack surfaces.

**Rationale**  
Attackers exploit synchronized behavior for coordinated compromise. Staggering execution reduces correlated risk.

**Implementation Notes**  
- Implement randomization within bounded windows.  
- Stagger AI inference batches for TI-3 workloads.  
- Break synchronized deployment and rotation cycles.  
- Record staggered execution patterns for audit.  
- Ensure staggering does not reduce security ceilings.

**Applies To:** TI-2, TI-3


#### 3.21.21 (TIME-21) ATLAS-TIME-FAIL-CLOSED — Time Failure Halts Execution

If temporal integrity cannot be proven—due to drift, source tampering, absence of time anchors, or ambiguous timestamps—execution MUST halt, identities MUST be invalidated, and dependent processes MUST enter quarantine.

**Rationale**  
Temporal failure corrupts every security primitive dependent on time—replay windows, lineage, expiry, ordering, and identity validity. Halting preserves deterministic guarantees.

**Implementation Notes**  
- Validate time integrity continuously.  
- Isolate workloads immediately upon failure.  
- Invalidate session and identity tokens.  
- Require governance for reactivation.  
- Emit TI-3 evidence for every time-related halt.

**Applies To:** TI-3 mandatory

---

---

### 3.22 Software Supply Chain, Build Provenance, and Dependency Integrity Controls (ATLAS-SUPPLY)

All software and model artifacts entering execution MUST originate from verifiable, governed, cryptographically authenticated supply chains. No code, model, binary, dependency, dataset, or artifact may execute without deterministic provenance, reproducible lineage, and tamper-evident verification. Supply chain integrity is a foundational ATLAS-DESS domain boundary.

---

#### 3.22.1 (SUPPLY-01) ATLAS-SUPPLY-SIGNED — Mandatory Signed Artifacts

All executable and non-executable artifacts—including binaries, containers, libraries, models, datasets, configs, CI outputs, and tools—MUST be cryptographically signed using governed keys. Unsigned artifacts MUST NOT execute or load under any circumstance.

**Rationale**  
Unsigned artifacts create arbitrary injection vectors enabling adversarial code execution, shadow dependencies, or poisoned builds.

**Implementation Notes**  
- Enforce signature verification at load time and runtime.  
- Bind signatures to trust domains and identity scopes.  
- Reject artifacts missing signature metadata.  
- Require HSM-backed signing keys.  
- Log verification failures as TI-3 anomalies.

**Applies To:** TI-3 mandatory


#### 3.22.2 (SUPPLY-02) ATLAS-SUPPLY-PROV — Provenance Required

All artifacts MUST include cryptographically verifiable provenance including source commits, build environment identity, dependency graph, model lineage, dataset classification, and execution domain.

**Rationale**  
Provenance eliminates ambiguity, prevents injection of unvetted content, and allows deterministic reconstruction of build lineages.

**Implementation Notes**  
- Use in-toto/SLSA-equivalent provenance metadata.  
- Attach build environment identity and attestation.  
- Sign provenance documents with governed keys.  
- Require reproducibility verification before approval.  
- Reject artifacts missing lineage or provenance fields.

**Applies To:** TI-2, TI-3


#### 3.22.3 (SUPPLY-03) ATLAS-SUPPLY-NO-UNVERIFIED — No Unverified Dependencies

Dependencies lacking provenance, signatures, or lineage MUST be rejected. Verification MUST occur before inclusion in build, deployment, or runtime.

**Rationale**  
Unverified transitive dependencies are a dominant vector for supply-chain compromise and hidden adversarial injection.

**Implementation Notes**  
- Require per-dependency signature verification.  
- Maintain a governed dependency trust registry.  
- Block builds referencing unverifiable packages.  
- Reject checksum-only validation as insufficient.  
- Emit TI-3 evidence for rejected dependencies.

**Applies To:** TI-3 mandatory


#### 3.22.4 (SUPPLY-04) ATLAS-SUPPLY-REPRO — Reproducible Build Requirement

All production artifacts MUST be reproducible byte-for-byte from declared sources. If reproducibility fails, the artifact MUST be quarantined and MUST NOT execute.

**Rationale**  
Reproducibility ensures artifact determinism; failure indicates tampering, environment drift, or build pipeline compromise.

**Implementation Notes**  
- Freeze build toolchain versions under governance.  
- Use deterministic compilers, linkers, and flags.  
- Compare artifact hashes across parallel builds.  
- Quarantine non-reproducible artifacts.  
- Produce TI-3 evidence documenting all mismatches.

**Applies To:** TI-3 mandatory


#### 3.22.5 (SUPPLY-05) ATLAS-SUPPLY-BUILD-ISOLATION — Isolated Build Environment

Build pipelines MUST execute in isolated, sandboxed, non-interactive, identity-scoped environments that do not share processes, memory, network surfaces, or credentials with runtime workloads or developer workstations.

**Rationale**  
Shared build surfaces allow lateral movement, credential leakage, supply chain injection, and adversarial tampering.

**Implementation Notes**  
- Use isolated build enclaves.  
- Enforce deterministic, read-only build inputs.  
- Prohibit developer shells or interactive access.  
- Disable outbound network access during build.  
- Produce build-environment attestation as TI-3 evidence.

**Applies To:** TI-2, TI-3


#### 3.22.6 (SUPPLY-06) ATLAS-SUPPLY-NO-DEV-ENV — Developer Machines Cannot Produce Production Artifacts

Production artifacts MUST be created only in governed, isolated CI/build pipelines. Developer laptops, personal workstations, or ad-hoc build environments MUST NOT produce artifacts intended for production.

**Rationale**  
Developer environments are inherently nondeterministic and are the highest-risk vector for unintentional or adversarial contamination.

**Implementation Notes**  
- Enforce CI-only production paths.  
- Disallow manual artifact upload to registries.  
- Require build signatures from governed pipelines only.  
- Bind build job identity to provenance.  
- Flag developer-originated artifacts as TI-3 violations.

**Applies To:** TI-3 mandatory


#### 3.22.7 (SUPPLY-07) ATLAS-SUPPLY-HASH-CHAIN — Hash Chain Continuity

Artifacts MUST maintain a continuous cryptographic hash chain linking source → build → binary → container → deployment → runtime. Breakage invalidates the artifact.

**Rationale**  
Hash chains provide tamper evidence across the entire software lifecycle and prevent unnoticed mutation.

**Implementation Notes**  
- Store hash chains in WORM evidence stores.  
- Bind each stage to signed lineage headers.  
- Require attestation of every transition.  
- Reject artifacts with broken or missing links.  
- Include hash-chain proofs in TI-3 audits.

**Applies To:** TI-3 mandatory


#### 3.22.8 (SUPPLY-08) ATLAS-SUPPLY-NO-EMBEDDED-SECRET — No Embedded Credentials

Artifacts MUST NOT contain hardcoded secrets, API keys, SSH keys, tokens, identity materials, or service credentials.

**Rationale**  
Embedded secrets are often extracted through decompilation, scanning, or runtime inspection and lead to immediate domain compromise.

**Implementation Notes**  
- Enforce static scanning for secrets.  
- Remove environment variables from packaged builds.  
- Use external secret managers with scoped retrieval.  
- Treat secret-in-artifact detection as TI-3 breach.  
- Block deployment of artifacts containing embedded credentials.

**Applies To:** TI-2, TI-3


#### 3.22.9 (SUPPLY-09) ATLAS-SUPPLY-BLOCK-EOL — Block End-of-Life Dependencies

Dependencies reaching end-of-life (EOL) MUST be rejected unless explicitly approved under a governed exception. EOL components MUST NOT be used in high-trust workloads.

**Rationale**  
EOL dependencies lack patches, support, and security fixes, frequently becoming high-risk compromise vectors.

**Implementation Notes**  
- Maintain internal EOL registry with strict enforcement.  
- Fail builds referencing EOL components automatically.  
- Require exception approvals with compensating controls.  
- Generate TI-3 evidence linking dependency decisions.  
- Trigger domain migration plans for EOL-critical components.

**Applies To:** TI-2, TI-3


#### 3.22.10 (SUPPLY-10) ATLAS-SUPPLY-NO-PREBUILD — No Prebuilt External Binaries

Precompiled third-party binaries MUST NOT be consumed directly. All binaries MUST be rebuilt internally, validated, and re-signed before use.

**Rationale**  
External binaries may contain hidden payloads, compiler-level tampering, or supply-chain manipulation. Rebuilding enforces deterministic trust.

**Implementation Notes**  
- Allow only source-level imports for controlled rebuild.  
- Validate source provenance before building.  
- Sign resulting binaries with governed keys.  
- Reject artifacts that cannot be rebuilt reproducibly.  
- Store rebuilt lineage in TI-3 evidence systems.

**Applies To:** TI-3 mandatory

---

#### 3.22.11 (SUPPLY-11) ATLAS-SUPPLY-SBOM — Mandatory SBOM

Every artifact—binaries, containers, models, datasets, plugins, libraries—MUST include a complete, cryptographically signed SBOM covering all direct and transitive dependencies, precise versions, licensing, and associated trust domains.

**Rationale**  
SBOMs provide complete transparency into dependency surfaces and enable deterministic vulnerability assessment, provenance verification, and forensic reconstruction after incidents.

**Implementation Notes**  
- Require machine-verifiable SBOM formats (SPDX, CycloneDX).  
- Bind SBOM signatures to artifact hash chains.  
- Reject incomplete or stale SBOMs.  
- Enforce SBOM updates upon dependency change.  
- Store SBOMs in WORM evidence systems for lineage continuity.

**Applies To:** TI-2, TI-3


#### 3.22.12 (SUPPLY-12) ATLAS-SUPPLY-NO-WILDCARD — No Wildcard Versioning

Wildcard or floating dependency versions (e.g., “^”, “~”, “*”, “latest”) MUST NOT be used. All versions MUST be explicit, pinned, and immutable without governance approval.

**Rationale**  
Floating versions silently introduce unvetted updates and nondeterministic behavior across builds, enabling adversarial injection through upstream version changes.

**Implementation Notes**  
- Enforce zero tolerance for unpinned versions in build manifests.  
- Validate exact version signatures for every dependency.  
- Require governance approval for version upgrades.  
- Log version-lock violations as TI-3 anomalies.  
- Reject manifests containing indirect floating versions.

**Applies To:** TI-3 mandatory


#### 3.22.13 (SUPPLY-13) ATLAS-SUPPLY-VULN-GATE — Vulnerability Gating Required

Deployment MUST fail automatically if any dependency exhibits vulnerabilities exceeding policy severity thresholds. No “best-effort” deployment under known-risk conditions is permitted.

**Rationale**  
Vulnerable dependencies create predictable, reusable attack surfaces for exploitation and privilege escalation.

**Implementation Notes**  
- Integrate governed vulnerability scanning into CI pipelines.  
- Require explicit exception approval for any CVE bypasses.  
- Bind vulnerability assessment to SBOM lineage.  
- Trigger automatic halt on detection of critical CVEs.  
- Produce TI-3 evidence for vulnerability-related deployment rejections.

**Applies To:** TI-2, TI-3


#### 3.22.14 (SUPPLY-14) ATLAS-SUPPLY-NO-NETBUILD — Builds Cannot Fetch Dynamic Dependencies

Builds MUST NOT download dependencies from the public internet or external mirrors during compilation or packaging. All dependencies MUST be resolved beforehand from governed sources.

**Rationale**  
Dynamic dependency fetch exposes builds to poisoning attacks, DNS hijacking, package-repository compromise, and nondeterministic behavior.

**Implementation Notes**  
- Disable outbound networking for build nodes entirely.  
- Pre-stage all dependencies in controlled internal mirrors.  
- Fail builds attempting to fetch external resources.  
- Require network-layer enforcement (firewall, sandbox, enclave).  
- Log all attempted network-access attempts as TI-3 evidence.

**Applies To:** TI-3 mandatory


#### 3.22.15 (SUPPLY-15) ATLAS-SUPPLY-MIRROR — Governed Mirrors Only

All dependencies MUST originate from internally governed mirrors that enforce strict provenance, immutability, and signature verification. Public repos MUST NOT be accessed directly in production pipelines.

**Rationale**  
Public repositories, even reputable ones, frequently suffer from hijacking, dependency confusion, and malicious uploads.

**Implementation Notes**  
- Maintain internal artifact mirrors with cryptographic verification.  
- Require immutable snapshots of approved versions.  
- Block direct access to public package managers.  
- Enforce mirror-origin metadata in provenance.  
- Treat direct public fetch as a TI-3 violation.

**Applies To:** TI-2, TI-3


#### 3.22.16 (SUPPLY-16) ATLAS-SUPPLY-ROTATE — Key Rotation for Artifact Signing

Artifact-signing keys MUST rotate periodically and immediately upon suspected compromise. Rotation MUST be governed, auditable, and identity-scoped.

**Rationale**  
Long-lived signing keys accumulate catastrophic blast radius and increase risk of unnoticed compromise.

**Implementation Notes**  
- Store keys exclusively in HSMs or equivalent secure vaults.  
- Maintain rotation schedules based on classification tiers.  
- Invalidate old signatures after rotation windows expire.  
- Record rotation events in TI-3 lineage logs.  
- Enforce multi-root approval for emergency key rotation.

**Applies To:** TI-3 mandatory


#### 3.22.17 (SUPPLY-17) ATLAS-SUPPLY-AUDIT — Artifact Provenance Must Be Auditable

All artifacts MUST maintain a complete, immutable audit trail covering version history, build events, provenance metadata, signer identity, and approval lineage—not just the latest version.

**Rationale**  
Historical lineage is essential for forensic reconstruction, breach analysis, and determining blast radius during compromise.

**Implementation Notes**  
- Use WORM evidence stores for provenance retention.  
- Require audit logs for every artifact transition.  
- Include signer identity and trust-domain metadata.  
- Reject artifacts missing historical lineage records.  
- Make audit logs cryptographically linked to artifact hash chains.

**Applies To:** TI-2, TI-3


#### 3.22.18 (SUPPLY-18) ATLAS-SUPPLY-NO-HASH-COLLISION — Hash Algorithms Must Be Collision-Resistant

Artifacts MUST use modern, collision-resistant hash algorithms. Deprecated or broken functions (e.g., MD5, SHA1) MUST NOT be used for any integrity-critical validation.

**Rationale**  
Collision attacks enable substitution of malicious artifacts without failing integrity checks.

**Implementation Notes**  
- Require SHA-256, SHA-384, SHA-512, or equivalent.  
- Block builds referencing deprecated algorithms.  
- Require governance approval for algorithm policy changes.  
- Validate hash provenance in CI pipeline.  
- Produce TI-3 evidence on hash algorithm downgrades.

**Applies To:** TI-3 mandatory


#### 3.22.19 (SUPPLY-19) ATLAS-SUPPLY-AI-PROV — AI Models Require Build Provenance

AI models MUST include provenance for training data, training code commit, hyperparameters, training environment signature, compute environment metadata, and model lineage.

**Rationale**  
AI supply chain attacks exploit hidden dataset manipulation, poisoned training inputs, and tampered weight artifacts.

**Implementation Notes**  
- Record dataset commit IDs and classification.  
- Capture training environment attestation.  
- Store hyperparameter signatures.  
- Bind model versions to hash-chain lineage.  
- Reject models missing provenance at any stage.

**Applies To:** TI-3 mandatory


#### 3.22.20 (SUPPLY-20) ATLAS-SUPPLY-NO-SELF-SIGNED — No Self-Signed Artifacts

Self-signed artifacts or self-issued signing chains MUST NOT be used. Only governed, domain-rooted signing authorities MAY sign production artifacts.

**Rationale**  
Self-signed content bypasses governance, breaks trust inheritance, and enables supply-chain forgery.

**Implementation Notes**  
- Validate root CA identity for all signatures.  
- Reject artifacts signed by unknown or developer-issued keys.  
- Require multi-root trust anchors for root-signing operations.  
- Log all rejected roots as TI-3 anomalies.  
- Store CA lineage in WORM-based governance records.

**Applies To:** TI-3 mandatory

#### 3.22.21 (SUPPLY-21) ATLAS-SUPPLY-NO-IMPLICIT — No Implicit Trust in Package Managers

Package managers, registries, or dependency resolution tools MUST NOT be treated as trust authorities. Their metadata MAY assist discovery, but final trust MUST derive only from governed verification, signatures, and provenance validation.

**Rationale**  
Package managers are frequently compromised via namespace hijacking, dependency confusion, malicious publishers, or DNS-level manipulation. Trust must derive from independent verification, not upstream assertions.

**Implementation Notes**  
- Enforce independent signature verification for all dependency pulls.  
- Block implicit trust in version metadata or publisher claims.  
- Use internal mirrors instead of public registries.  
- Validate provenance even when verified by the manager.  
- Log all implicit trust attempts as TI-3 anomalies.

**Applies To:** TI-2, TI-3


#### 3.22.22 (SUPPLY-22) ATLAS-SUPPLY-BREACH-INVALIDATE — Invalidate Supply Chain After Breach

If any part of the supply chain is compromised—compiler tampering, repo injection, key theft, build pipeline breach—all dependent artifacts MUST be invalidated, quarantined, and rebuilt under trusted conditions.

**Rationale**  
Supply-chain breach invalidates every artifact produced under that chain. Continuing execution under compromised lineage risks systemic compromise.

**Implementation Notes**  
- Immediately collapse trust for affected domains.  
- Revoke compromised signing keys and rebuild under new trust.  
- Quarantine all impacted artifacts and outputs.  
- Require multi-root governance approval before reissue.  
- Emit TI-3 evidence linking affected downstream workloads.

**Applies To:** TI-3 mandatory


#### 3.22.23 (SUPPLY-23) ATLAS-SUPPLY-SANDBOX — Build Tools Must Run in Sandboxed Execution

Compilers, linkers, interpreters, and model-trainers MUST operate inside isolated, non-privileged, sandboxed environments that enforce deterministic boundaries.

**Rationale**  
Build tools themselves are high-value targets for injection and tampering. Sandboxing prevents the build toolchain from acting as a lateral-movement or privilege-escalation vector.

**Implementation Notes**  
- Enforce sandboxed execution contexts for all build tooling.  
- Disable outbound network access for toolchains.  
- Use multi-identity isolation for compiler workers.  
- Zeroize temporary build artifacts upon completion.  
- Produce attestation for toolchain environment integrity.

**Applies To:** TI-2, TI-3


#### 3.22.24 (SUPPLY-24) ATLAS-SUPPLY-PRELOAD-BLOCK — No Preload or Hot-Patch Modules

Workloads MUST NOT preload or hot-patch modules at runtime. Only artifacts present in the governed build output MAY execute.

**Rationale**  
Hot-patching introduces unverified code paths, runtime mutability, and post-build execution drift—breaking deterministic lineage and violating ATLAS boundaries.

**Implementation Notes**  
- Block `LD_PRELOAD`, extension modules, and injector frameworks.  
- Enforce kernel-level controls to prevent dynamic module loading.  
- Require full rebuild + re-sign for any updated module.  
- Treat hot-patch attempts as TI-3 violations.  
- Log module load requests against SBOM content.

**Applies To:** TI-3 mandatory


#### 3.22.25 (SUPPLY-25) ATLAS-SUPPLY-NO-DOWNLOADER — Execution Cannot Download New Code

Workloads MUST NOT fetch, download, or dynamically obtain new code, binaries, dependencies, or model weights at runtime. Any code update MUST occur through governed build and deployment workflows.

**Rationale**  
Downloading executable content at runtime bypasses signature validation, provenance checks, and governance, enabling remote code injection.

**Implementation Notes**  
- Block outbound code-fetch attempts at network and sandbox layers.  
- Require redeployment for any updated code path.  
- Log code-fetch attempts as TI-3 anomalies.  
- Disable package managers and curl/wget inside execution environments.  
- Enforce read-only filesystem surfaces for code directories.

**Applies To:** TI-3 mandatory


#### 3.22.26 (SUPPLY-26) ATLAS-SUPPLY-TAMPER-EVIDENT — Artifacts Must Be Tamper-Evident

Any mutation of artifact content, structure, metadata, or signature MUST invalidate execution cryptographically and trigger immediate quarantine.

**Rationale**  
Tamper-evident design ensures immediate detection of compromise, preventing silent drift or adversarial modification.

**Implementation Notes**  
- Bind artifact structure to cryptographic signatures.  
- Verify signatures at startup and continuously during runtime.  
- Trigger auto-halt if tampering detected.  
- Include tamper detection in provenance chains.  
- Treat tamper events as TI-3 breach signals.

**Applies To:** TI-3 mandatory


#### 3.22.27 (SUPPLY-27) ATLAS-SUPPLY-ISOLATED-TRAIN — AI Model Training Must Be Isolated

AI training pipelines MUST run in isolated environments separate from inference, execution, or operational systems. Training identities MUST NOT have access to runtime credentials or production datasets unless explicitly governed.

**Rationale**  
Training environments often require broad data access and tool capabilities, making them high-risk. Isolation prevents poisoning attacks, boundary crossover, and identity leakage.

**Implementation Notes**  
- Use separate trust domains for training and inference.  
- Enforce read-only access to training datasets.  
- Disable export of training environment secrets.  
- Require separate SBOMs and provenance for training outputs.  
- Log all training-to-inference transitions as TI-3 events.

**Applies To:** TI-3 mandatory


#### 3.22.28 (SUPPLY-28) ATLAS-SUPPLY-CROSSDOMAIN-BLOCK — No Cross-Domain Dependency Pulls

Dependencies MUST NOT cross trust domains unless federation is explicitly declared and governed. Workloads cannot import libraries, containers, or models from external domains without explicit federation approval.

**Rationale**  
Undeclared cross-domain dependency movement creates uncontrolled trust paths, violates domain boundaries, and enables targeted injection attacks.

**Implementation Notes**  
- Enforce domain-scoped dependency registries.  
- Reject artifacts originating from foreign trust domains.  
- Require signed federation approval before allowing cross-domain pulls.  
- Record domain-crossing events as TI-3 evidence.  
- Enforce cryptographic partitioning of domain boundaries.

**Applies To:** TI-3 mandatory


#### 3.22.29 (SUPPLY-29) ATLAS-SUPPLY-PRIMARY-SOURCE — Primary Source Must Be Canonical

The canonical artifact MUST reside in governed, centrally controlled storage. Distributed or duplicated “shadow binaries” MUST NOT be considered authoritative and MUST NOT be used for deployment.

**Rationale**  
Shadow artifacts bypass governance, break determinism, and introduce uncontrolled mutation into software lineage.

**Implementation Notes**  
- Use a single canonical source per artifact lineage.  
- Enforce read-only policies on canonical stores.  
- Reject deployments referencing non-canonical sources.  
- Maintain hash-chain continuity with canonical records.  
- Log all deviations as TI-3 anomalies.

**Applies To:** TI-2, TI-3


#### 3.22.30 (SUPPLY-30) ATLAS-SUPPLY-KEYS-QUARANTINE — Quarantine Signing Keys

Signing keys MUST remain confined to governed HSMs or equivalent vaults. Keys MUST NOT be present on build nodes, developer systems, inference servers, or runtime execution paths.

**Rationale**  
Compromised signing keys collapse global trust. Key quarantine enforces strict compartmentalization and eliminates lateral movement risk.

**Implementation Notes**  
- Store signing keys in hardware-backed vaults only.  
- Enforce identity-scoped access to HSM operations.  
- Disable all extract/export functions.  
- Monitor key usage patterns for anomalies.  
- Generate TI-3 forensic evidence for all key operations.

**Applies To:** TI-3 mandatory

---


---

### 4.0 Deterministic Human-Constrained Execution Controls (ATLAS-DHCEC)

Modern cybersecurity failures are predominantly driven by human-originated actions rather than intrinsic flaws in algorithms or systems. Global analyses by reputable breach reports demonstrate that insider mistakes, social engineering, credential misuse, misconfiguration, and coercion account for the majority of serious incidents. As execution environments become increasingly autonomous and interconnected, unconstrained human intervention has become a primary systemic attack vector.

Traditional cybersecurity and AI governance frameworks treat “human-in-the-loop” as a mitigation that increases safety or reliability. Atlas adopts the opposite stance: human interaction is a source of risk and must be constrained, verified, logged, and subjected to deterministic enforcement. Humans are not considered inherently trusted or authoritative. They are actors within the system and must be treated with the same technical rigor and security boundaries as autonomous systems.

This section establishes mandatory execution controls governing human interaction with systems under Atlas. Section 4 SHALL take precedence over all preceding sections where conflicts arise, as it governs the highest-risk control surface.

Humans MAY reduce or terminate system capability (e.g., rendering the system inert), but SHALL NOT expand capability, authority, access scope, routing influence, or boundary conditions at runtime. Attempts to expand capability SHALL be treated as security incidents and recorded as TI-3 evidence in WORM form.

These controls apply to all systems governed by Atlas, including but not limited to classical software, execution environments, control planes, AI systems, autonomous systems, and self-modifying systems.


#### 4.1 Human Authority Classification (ATLAS-DHCEC-ROLES)

Human actors interacting with governed systems SHALL be categorized into explicit authority classes. These classes define the permitted scope of interaction and the enforcement boundaries applied to human actions.

- **H0 — Passive Observer**  
  May view system outputs but SHALL NOT initiate state transitions or trigger execution pathways.

- **H1 — Reviewer / Approver**  
  May review proposed actions and provide approval signals but SHALL NOT execute state transitions directly.

- **H2 — Operator**  
  May initiate direct actions such as pausing, restricting, or terminating execution, but SHALL NOT expand capability.

- **H3 — Authority Root (Constrained)**  
  May define or constrain system boundaries, but SHALL NOT expand capability at runtime. Expansion requires redeployment under a new identity and SHALL NOT occur in-place.

Roles MUST be enforced using cryptographic identity, not procedural policy. Human roles SHALL NOT be inferred by access context or network origin.


#### 4.2 No Runtime Expansion of Capability by Humans (ATLAS-DHCEC-NO-EXPANSION)

Humans SHALL NOT expand capability, authority scope, execution domain, routing influence, or privilege surfaces on a running system under any circumstances.

Human intervention MAY reduce capability (e.g., pausing, terminating execution, restricting network routes, sandboxing, or isolating components), but MAY NOT increase capability or expand boundaries.

Attempted expansion SHALL be treated as a security incident.

Explanation: Humans are a high-risk vector for coercion, phishing, social engineering, insider misuse, and privilege abuse. Expansion is therefore considered unsafe unless performed through redeployment with new identity, provenance, boundary definitions, and external enforcement.


#### 4.3 Human Actions as TI-3 WORM Evidence (ATLAS-DHCEC-EVIDENCE)

All human-initiated actions that influence execution state, control-plane behavior, or system configuration SHALL be recorded as TI-3 forensic evidence in WORM form.

Evidence MUST include:

- human actor identity (cryptographically bound)
- timestamp authority proofs (external, verifiable)
- rationale or decision context (if structured inputs apply)
- prior and resulting state digests
- affected boundaries, policies, identities, and domains
- attestation of enforcement result (allow, deny, quiesce)

Evidence MUST NOT be suppressible or modifiable by humans or system entities. Evidence SHALL survive system shutdown, quiescence, failure, or redeployment.

Human actions SHALL NOT be logged to ephemeral storage or mutable logs.

---

#### 4.4 Deterministic Quiescence Mode (DQM) (ATLAS-DHCEC-DQM)

Deterministic Quiescence Mode (DQM) is a terminal execution state that constrains a system to the minimum safe operational baseline and prevents further execution beyond tightly bounded safe behavior. DQM SHALL be used to reduce system capability in response to uncertainty, integrity loss, or detected security threats.

Entering DQM SHALL:

- halt or restrict execution to inert safe behavior
- prevent autonomous expansion of capability or scope
- preserve system state for forensic examination
- revoke active execution identities and scopes
- enforce read-only operation on all mutable surfaces
- require redeployment under a new identity for reactivation

DQM is a **one-way transition**. Systems SHALL NOT exit DQM through runtime commands, human intervention, or local overrides. Recovery MUST occur via redeployment with new attestation and boundary definitions.

DQM SHALL apply to all systems governed by Atlas, including non-autonomous systems.


#### 4.5 Local vs Global Quiescence (ATLAS-DHCEC-DQM-SCOPE)

DQM MAY be invoked at either:

- **Local Scope** — constraining a specific subsystem, component, or execution domain while leaving unrelated systems active.
- **Global Scope** — constraining the entire governed system, resulting in full system quiescence.

Local DQM MAY occur automatically based on subsystem integrity signals. Global DQM SHALL be reserved for conditions involving systemic compromise or loss of trust roots.

Global DQM SHALL NOT occur silently. It MUST be treated as a security incident and MUST generate TI-3 WORM evidence documenting:

- trigger conditions
- affected domains
- prior and resulting state
- identities involved
- boundary evaluation results

Global DQM SHALL NOT be reversible at runtime. Reactivation requires redeployment.


#### 4.6 Conditions for Triggering DQM (ATLAS-DHCEC-DQM-TRIGGERS)

DQM SHALL be triggered automatically when a system cannot prove the integrity or safety of its execution state. Absence of proof SHALL be treated as proof of risk.

Mandatory triggers include:

- provenance breaks (e.g., mismatched digests)
- invalid or expired cryptographic signatures
- attestation failure or trust root unavailability
- attempted expansion of boundaries (human or machine)
- cross-domain routing modification attempts without authority
- execution identity mismatch or spoofing
- attempts to alter enforcement, policy, or control-plane logic
- loss of timestamp authority or evidence continuity

Implementations MAY define additional domain-specific triggers, such as:

- medical systems detecting inconsistent sensor telemetry
- financial systems observing ledger divergence
- cyber-physical systems detecting actuator contradictions
- national-critical systems detecting command spoofing

Domain-specific triggers MUST NOT override mandatory triggers.

---

#### 4.7 Human-Initiated Violations as Security Incidents (ATLAS-DHCEC-VIOLATIONS)

Human attempts to expand capability, modify boundaries, assume new execution identities, alter routing authority, or bypass deterministic enforcement SHALL be treated as security incidents regardless of intent.

Violations SHALL NOT be treated as administrative exceptions, “emergency overrides,” maintenance activity, or privileged behavior. Human actors are considered part of the adversarial surface.

Upon violation, the system MUST:

- enter Local or Global DQM depending on scope
- preserve all state and logs as TI-3 WORM evidence
- escalate to external incident response systems
- revoke execution privileges for affected identities
- require explicit investigation and redeployment before reactivation

This requirement applies equally to malicious, accidental, coerced, or socially engineered human actions.


#### 4.8 Multi-Root Governance for Critical Human Actions (ATLAS-DHCEC-MRG)

Actions initiated by humans that materially alter execution state, induce quiescence, revoke broad capability, or constrain systems at scale MUST require authorization from multiple independent human principals operating under separate trust anchors.

No single human SHALL be permitted to unilaterally authorize:

- entry into Global DQM
- revocation of entire execution domains
- system-wide configuration lockdown
- regeneration or resetting of trust roots
- issuance of high-authority control-plane keys

Multi-root governance MUST enforce:

- cryptographic role separation
- independently stored credentials
- out-of-band confirmation channels
- quorum thresholds (e.g., 2-of-3 or 3-of-5)
- resilience to coercion or compromise of any one actor

Compromise of a single human SHALL NOT enable systemic control.


---

### End of Section 4

Section 4 establishes deterministic constraints on human interaction, quiescence, and evidence preservation. These controls SHALL take precedence over all other execution rules defined in this specification where conflicts occur, as they govern the highest-risk control surface.

Subsequent sections SHALL assume Section 4 as a foundational prerequisite.

---

