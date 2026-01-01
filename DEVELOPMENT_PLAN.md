# Internal document — *First Release Plan (Internal)*

> **Internal — not for README or public docs**

## Objective

Produce a credible **jGuard v0.1.0** that:

* enforces real security guarantees on JDK 21+
* is small, understandable, and auditable
* is suitable for open-source adoption
* can be integrated into a real plugin-based JVM system

---

## Non-goals for v0.1.0

* Full Java Security Manager parity
* Complete API coverage
* Reflection, classloading, or memory sandboxing
* Complex network filtering (hosts/ports)
* Container or OS integration

---

## Milestones

### M0 — Repository + CI

* Multi-module build
* JDK 21 baseline
* CI on 21+
* OSS hygiene

---

### M1 — Policy model + descriptor compiler

* `module-info.jguard` grammar + parser
* Deterministic policy model
* JSON renderer
* CLI compile tool
* Validation + golden tests

Exit criteria:

* identical input → identical output
* invalid policies rejected with good errors

---

### M2 — Java-backed descriptor (optional)

* Descriptor API
* Compilation to same model
* Parity tests

Exit criteria:

* `.jguard` and `.java` produce byte-identical policy metadata

---

### M3 — Enforcement v1 (filesystem)

* Java agent
* Minimal hook surface
* Attribution via StackWalker
* Decision cache
* Deny-by-default semantics

Exit criteria:

* demonstrable block of unauthorized file access

---

### M4 — Enforcement v1 (network)

* Outbound network blocking
* Minimal hook set
* Clear failure messages

Exit criteria:

* demonstrable prevention of outbound socket creation

---

### M5 — Integration proof

* One real plugin-style integration
* Policy-driven behavior change
* Install-time entitlement visibility

Exit criteria:

* real application runs with restricted privileges

---

### M6 — Release hardening

* Documentation
* Compatibility statement
* Versioned policy format
* `v0.1.0` tag + release notes

---

## Initial capability set (v0.1.0)

* `fs.read(root, glob)`
* `network.outbound`

Everything else deferred.

---

## Release bar

We ship when:

* policy is deterministic
* denial is reliable
* errors are understandable
* the surface area is small enough to reason about

