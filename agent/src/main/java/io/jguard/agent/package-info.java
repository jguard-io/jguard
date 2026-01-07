/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

/**
 * jGuard Java agent for capability-based security enforcement.
 *
 * <p>This package contains the Java agent that enforces jGuard security policies at runtime. The
 * agent uses ByteBuddy to instrument JDK classes and intercept sensitive operations.
 *
 * <h2>Key Components</h2>
 *
 * <ul>
 *   <li>{@link io.jguard.agent.JGuardAgent} - Agent entry point (premain/agentmain)
 *   <li>{@link io.jguard.agent.PolicyEnforcer} - Core decision engine
 *   <li>{@link io.jguard.agent.CallerAttribution} - StackWalker-based caller identification
 *   <li>{@link io.jguard.agent.FilesystemInterceptor} - ByteBuddy advice for fs.read
 * </ul>
 *
 * <h2>Usage</h2>
 *
 * <pre>{@code
 * java -javaagent:jguard-agent.jar=policy.bin -jar myapp.jar
 * }</pre>
 *
 * @see io.jguard.agent.JGuardAgent
 */
package io.jguard.agent;
