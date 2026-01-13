/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

/**
 * Demo application module that uses a legacy (non-jGuard) library.
 *
 * <p>Note: The library module name is "legacy.library" - auto-derived from the JAR filename
 * (legacy-library.jar). Java converts hyphens to dots in automatic module names.
 */
module io.jguard.samples.legacy.app {
  requires legacy.library;
}
