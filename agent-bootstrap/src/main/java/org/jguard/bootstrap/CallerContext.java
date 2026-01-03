/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.jguard.bootstrap;

/**
 * Context information about the caller making a capability request.
 *
 * <p>This record is passed to the enforcement callback and contains the caller's package name and
 * module name. It is the public API for caller information exposed to the agent layer.
 *
 * <h2>Thread Safety</h2>
 *
 * <p>This is an immutable record and is inherently thread-safe.
 *
 * @param packageName the caller's package name
 * @param moduleName the caller's module name, or "unnamed" for unnamed modules
 */
public record CallerContext(String packageName, String moduleName) {}
