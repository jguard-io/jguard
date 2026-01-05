# The jGuard Policy Descriptor Specification

**Version 1.0 (Draft)**

## 1. Introduction

This document specifies the syntax and semantics of the **jGuard policy descriptor**, a declarative format used to define security entitlements for Java modules.

A jGuard policy descriptor declares which **capabilities** are granted to a Java module and, optionally, to specific packages within that module.

A jGuard policy descriptor:

* is **not executable code**
* has no side effects
* is evaluated at build or installation time
* is enforced at runtime by a jGuard implementation

---

## 2. Goals and non-goals

### 2.1 Goals

The policy descriptor is designed to:

* support **least-privilege execution**
* be **deterministic and reviewable**
* integrate naturally with the Java Platform Module System (JPMS)
* remain stable across Java versions

### 2.2 Non-goals

The policy descriptor does **not**:

* replace the Java Security Manager
* provide a general language sandbox
* support arbitrary computation or expressions
* permit conditional or dynamic logic

---

## 3. Lexical structure

### 3.1 Whitespace

Whitespace consists of spaces, tabs, carriage returns, line terminators, and comments.

Whitespace may appear between any lexical tokens unless otherwise stated.

### 3.2 Comments

The following comment forms are recognized:

* Line comments begin with `//` and extend to the end of the line.
* Block comments begin with `/*` and end with `*/`.

Comments are treated as whitespace.

### 3.3 Identifiers

An **identifier** consists of:

* a letter (`A–Z`, `a–z`) or underscore (`_`) as the first character
* followed by any number of letters, digits (`0–9`), or underscores

Identifiers are case-sensitive.

### 3.4 String literals

A **string literal** is enclosed in double quotes (`"`).

Escape sequences follow JSON-style conventions, including:

* `\"`, `\\`, `\n`, `\t`
* Unicode escapes of the form `\uXXXX`

String literals MUST be fully resolved at policy compile time.

---

## 4. Grammar

The grammar below is expressed in Extended Backus–Naur Form (EBNF).

### 4.1 Policy file

A policy file consists of exactly one security module declaration.

```
PolicyFile:
    SecurityModuleDeclaration
```

### 4.2 Security module declaration

```
SecurityModuleDeclaration:
    security module ModuleName { EntitlementDeclaration* }
```

The keywords `security` and `module` are reserved and may not be used as identifiers.

### 4.3 Module name

```
ModuleName:
    Identifier ( . Identifier )*
```

The module name identifies the Java module to which the policy applies.

### 4.4 Entitlement declarations

```
EntitlementDeclaration:
    entitle Subject to Capability ;
```

Each entitlement declaration grants a capability to a subject.

### 4.5 Subject

```
Subject:
    module
    PackagePattern
```

* The keyword `module` refers to the entire module.
* A package pattern refers to code within matching packages.

### 4.6 Package patterns

```
PackagePattern:
    PackageName
    PackageName .*
    PackageName ..
```

```
PackageName:
    Identifier ( . Identifier )*
```

Package patterns have the following meanings:

| Pattern | Meaning                         |
| ------- | ------------------------------- |
| `p`     | exactly package `p`             |
| `p.*`   | direct subpackages of `p`       |
| `p..`   | package `p` and all descendants |

---

### 4.7 Capabilities

```
Capability:
    CapabilityName
    CapabilityName ( CapabilityArguments? )
```

```
CapabilityName:
    Identifier ( . Identifier )*
```

```
CapabilityArguments:
    Argument ( , Argument )*
```

```
Argument:
    Identifier
    StringLiteral
    IntegerLiteral
```

The meaning and validity of arguments depend on the capability.

---

## 5. Well-formedness rules

A policy file is **ill-formed** if any of the following conditions hold.

### 5.1 Structural constraints

1. The policy file contains zero or more than one security module declaration.
2. An entitlement declaration omits a subject, capability, or terminating semicolon.
3. An entitlement declaration appears outside a security module declaration.

### 5.2 Module constraints

4. The declared module name is not a syntactically valid Java module name.
5. The declared module name does not match the module to which the policy is applied.

### 5.3 Package constraints

6. A package pattern contains empty or malformed segments.
7. A package wildcard appears anywhere other than the end of the pattern.
8. The pattern `..` or `.*` is used without a package name prefix.

### 5.4 Capability constraints

9. A capability name is unknown to the implementation.
10. A capability is invoked with an invalid number or type of arguments.
11. A capability argument fails validation (e.g., invalid glob syntax).

---

## 6. Static semantics

### 6.1 Capability signatures

Each capability has a fixed signature that determines:

* whether arguments are required
* the type and meaning of each argument

The following capabilities are defined in jGuard version 1:

| Capability              | Signature                    | Description                              |
| ----------------------- | ---------------------------- | ---------------------------------------- |
| `fs.read`               | `(root, glob)`               | Read files matching glob under root      |
| `fs.write`              | `(root, glob)`               | Write files matching glob under root     |
| `network.outbound`      | `(hostPattern?, portSpec?)`  | Open outbound network connections        |
| `network.listen`        | `(portSpec?)`                | Bind server sockets (optional port/range)|
| `threads.create`        | (no arguments)               | Create new threads                       |
| `native.load`           | `(pattern?)`                 | Load native libraries (optional pattern) |
| `env.read`              | `(pattern?)`                 | Read environment variables               |
| `system.property.read`  | `(pattern?)`                 | Read system properties                   |
| `system.property.write` | `(pattern?)`                 | Write system properties                  |

#### Argument details

**`fs.read(root, glob)` / `fs.write(root, glob)`**

* `root` — base directory path (string)
* `glob` — glob pattern for matching files (string, e.g., `"**/*"`, `"*.txt"`)

**`network.outbound(hostPattern?, portSpec?)`**

* `hostPattern` — optional host glob pattern (string); if omitted, allows any host
* `portSpec` — optional port or port range (integer or string); if omitted, allows any port

Host pattern syntax:
* `*` — matches exactly one DNS segment (e.g., `*.example.com` matches `api.example.com` but not `a.b.example.com`)
* `**` — matches one or more DNS segments (e.g., `**.example.com` matches `api.example.com` and `a.b.c.example.com`)
* Literal segments for exact matching

Port spec can be:
* Integer: `443` — specific port
* String range: `"80-443"` — port range (inclusive)

Examples:
```
entitle module to network.outbound;                           // Any host, any port
entitle module to network.outbound("*.example.com");          // Any port to matching hosts
entitle module to network.outbound("*", 443);                 // Port 443 to any host
entitle module to network.outbound("*.example.com", "80-443"); // Port range to matching hosts
```

**`network.listen(portSpec?)`**

* `portSpec` — optional port or port range (integer or string); if omitted, allows binding to any port

Examples:
```
entitle module to network.listen;           // Any port
entitle module to network.listen(8080);     // Specific port
entitle module to network.listen("8080-8090"); // Port range
```

**`native.load(pattern?)`**

* `pattern` — optional library name pattern (string); if omitted, allows loading any library

**`env.read(pattern?)`**

* `pattern` — optional environment variable name pattern (string); if omitted, allows reading any env var

Pattern syntax:
* No argument or `*` — matches any env var (also grants bulk access via `System.getenv()`)
* `HOME` — exact match for specific variable
* Bulk API `System.getenv()` requires no-arg or `*` entitlement

Examples:
```
entitle module to env.read;              // Any env var, including bulk access
entitle module to env.read("HOME");      // Only HOME variable
entitle module to env.read("*");         // Any env var, including bulk access
```

**`system.property.read(pattern?)` / `system.property.write(pattern?)`**

* `pattern` — optional property key pattern (string); if omitted, allows any property

Pattern syntax:
* No argument or `*` — matches any property (also grants bulk access)
* `java.home` — exact match for specific property
* `app.**` — matches `app` and all descendants (e.g., `app.config.setting`)
* `app.*` — matches direct children only (e.g., `app.config` but not `app.config.setting`)

Bulk APIs:
* `System.getProperties()` requires `system.property.read` with no-arg or `*`
* `System.setProperties(Properties)` requires `system.property.write` with no-arg or `*`
* `System.clearProperty(String)` requires `system.property.write` for that key

Examples:
```
entitle module to system.property.read;                    // Any property, including bulk
entitle module to system.property.read("java.home");       // Only java.home
entitle module to system.property.write("app.**");         // Write app.* hierarchy
```

Implementations MUST reject entitlement declarations whose arguments do not conform to the capability's signature.

### 6.2 Accumulation of entitlements

* Multiple entitlements for the same subject are cumulative.
* Duplicate entitlements are permitted but SHOULD be deduplicated internally.
* No entitlement negation or revocation exists in this version.

### 6.3 Default behavior

If no entitlement grants a capability to a subject, that capability is denied.

---

## 7. Execution semantics

At runtime, when a guarded operation is attempted:

1. The operation is classified as a capability.
2. The calling code is attributed to a `(module, package)`.
3. The policy is consulted to determine whether the capability is granted.
4. If granted, execution proceeds.
5. If not granted, execution fails.

An implementation MUST fail deterministically when a capability is denied.

---

## 8. Error handling

When a policy violation occurs, an implementation SHOULD provide:

* the attempted capability
* the calling module
* the calling package
* the reason for denial

Policy parsing and validation errors MUST identify:

* the error location (line and column)
* the nature of the error

---

## 9. Versioning and compatibility

This specification defines **policy format version 1**.

Future versions MAY:

* introduce new capabilities
* extend capability argument forms
* add optional policy constructs

Future versions MUST NOT change the meaning of valid version-1 policies.

---

## 10. Relationship to Java modules

A jGuard policy descriptor is conceptually analogous to `module-info.java`:

* both declare metadata about a module
* both are non-executable
* both define boundaries enforced by the runtime

However, a jGuard policy descriptor:

* does not participate in Java compilation
* does not affect module resolution
* is enforced solely by jGuard implementations

---

## 11. Summary

The jGuard policy descriptor provides:

* a minimal, declarative security language
* clear separation of syntax, validation, and enforcement
* a stable foundation for capability-based security on the JVM

