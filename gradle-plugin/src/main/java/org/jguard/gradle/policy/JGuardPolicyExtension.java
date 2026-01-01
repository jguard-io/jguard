/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.jguard.gradle.policy;

import org.gradle.api.file.DirectoryProperty;
import org.gradle.api.file.RegularFileProperty;
import org.gradle.api.provider.Property;

/**
 * Configuration extension for the jGuard policy plugin.
 *
 * <p>Example usage in build.gradle:
 * <pre>
 * jguardPolicy {
 *     sourceFile = file("src/main/jguard/module-info.jguard")
 *     outputDir = layout.buildDirectory.dir("generated/jguard")
 *     includeJson = true
 * }
 * </pre>
 */
public abstract class JGuardPolicyExtension {

    /**
     * The source policy descriptor file.
     * <p>Default: {@code src/main/jguard/module-info.jguard}
     */
    public abstract RegularFileProperty getSourceFile();

    /**
     * The output directory for compiled policy files.
     * <p>Default: {@code build/generated/jguard/}
     */
    public abstract DirectoryProperty getOutputDir();

    /**
     * Whether to generate a JSON representation alongside the binary.
     * <p>Default: {@code true}
     */
    public abstract Property<Boolean> getIncludeJson();

    /**
     * The name of the binary policy file.
     * <p>Default: {@code policy.bin}
     */
    public abstract Property<String> getBinName();

    /**
     * The name of the JSON policy file.
     * <p>Default: {@code policy.json}
     */
    public abstract Property<String> getJsonName();

    /**
     * The path within the JAR where policy files are placed.
     * <p>Default: {@code META-INF/jguard}
     */
    public abstract Property<String> getJarPath();
}
