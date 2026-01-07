/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.agent;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.jar.JarFile;

/**
 * jGuard Java agent entry point.
 *
 * <p>This agent enforces capability-based security policies by instrumenting JDK classes to check
 * entitlements before sensitive operations.
 *
 * <p><b>IMPORTANT:</b> This class must NOT import any types from io.jguard.bootstrap.* because
 * those types are not available until after bootstrap injection. All bootstrap-dependent logic is
 * in {@link AgentInitializer}, which is loaded via reflection after injection.
 *
 * <h2>Usage</h2>
 *
 * <pre>{@code
 * java -javaagent:jguard-agent.jar=policy.bin -jar myapp.jar
 * }</pre>
 *
 * <h2>Agent Arguments</h2>
 *
 * <p>The agent accepts the path to a compiled policy file (.bin) as its argument.
 *
 * <h2>System Properties</h2>
 *
 * <ul>
 *   <li>{@code jguard.policy} - Path to policy file (alternative to agent argument)
 *   <li>{@code jguard.mode} - Enforcement mode: strict, permissive, or audit
 *   <li>{@code jguard.log.level} - Log level: error, warn, info, debug, trace
 *   <li>{@code jguard.log.denied} - Log denied operations (default: true)
 *   <li>{@code jguard.log.allowed} - Log allowed operations (default: false)
 * </ul>
 *
 * <h2>Two-Phase Initialization</h2>
 *
 * <p>The agent uses two-phase initialization to solve the classloader chicken-and-egg problem:
 *
 * <ol>
 *   <li>JGuardAgent.premain() injects bootstrap.jar into the bootstrap classloader
 *   <li>AgentInitializer.initialize() is called via reflection (can now use bootstrap types)
 * </ol>
 *
 * <p>This separation is necessary because JVM class loading resolves all imported types when a
 * class is loaded. If JGuardAgent imported bootstrap types directly, the JVM would try to resolve
 * them before premain() runs, causing NoClassDefFoundError.
 */
public final class JGuardAgent {

  /** Resource path for the embedded bootstrap JAR. */
  private static final String BOOTSTRAP_JAR_RESOURCE = "/jguard/bootstrap.jar";

  private JGuardAgent() {
    // Entry point class
  }

  /**
   * Agent premain entry point.
   *
   * @param agentArgs the path to the policy file
   * @param inst the instrumentation instance
   */
  public static void premain(String agentArgs, Instrumentation inst) {
    try {
      // Phase 1: Inject bootstrap classes FIRST - before anything that uses them
      injectBootstrapClasses(inst);

      // Phase 2: Call AgentInitializer via reflection (it can now use bootstrap types)
      initializeAgent(agentArgs, inst);

    } catch (Exception e) {
      // Can't use AgentLogger here - bootstrap may not be loaded
      System.err.println("[jGuard] FATAL: Agent initialization failed: " + e.getMessage());
      e.printStackTrace(System.err);

      // Check if we should fail hard or continue
      String mode = System.getProperty("jguard.mode", "strict");
      if ("strict".equalsIgnoreCase(mode)) {
        throw new RuntimeException("jGuard agent initialization failed", e);
      } else {
        System.err.println("[jGuard] Continuing without enforcement (mode=" + mode + ")");
      }
    }
  }

  /**
   * Agent agentmain entry point (for dynamic attach).
   *
   * @param agentArgs the path to the policy file
   * @param inst the instrumentation instance
   */
  public static void agentmain(String agentArgs, Instrumentation inst) {
    premain(agentArgs, inst);
  }

  /**
   * Injects bootstrap classes into the bootstrap classloader.
   *
   * <p>This uses the production-grade approach: extract the embedded bootstrap JAR and use {@link
   * Instrumentation#appendToBootstrapClassLoaderSearch(JarFile)} to add it to the bootstrap
   * classpath.
   */
  private static void injectBootstrapClasses(Instrumentation inst) throws IOException {
    // Extract embedded bootstrap JAR to temp file
    File bootstrapJar = extractBootstrapJar();

    // Add to bootstrap classloader search path
    inst.appendToBootstrapClassLoaderSearch(new JarFile(bootstrapJar));
  }

  /**
   * Extracts the embedded bootstrap JAR from the agent JAR to a temp file.
   *
   * @return the path to the extracted JAR file
   * @throws IOException if extraction fails
   */
  private static File extractBootstrapJar() throws IOException {
    try (InputStream is = JGuardAgent.class.getResourceAsStream(BOOTSTRAP_JAR_RESOURCE)) {
      if (is == null) {
        throw new IOException(
            "Bootstrap JAR not found in agent: "
                + BOOTSTRAP_JAR_RESOURCE
                + ". The agent JAR may be corrupted or built incorrectly.");
      }

      // Create temp file with .jar extension (required for JarFile)
      Path tempJar = Files.createTempFile("jguard-bootstrap-", ".jar");
      File tempFile = tempJar.toFile();
      tempFile.deleteOnExit();

      // Copy resource to temp file
      Files.copy(is, tempJar, StandardCopyOption.REPLACE_EXISTING);

      return tempFile;
    }
  }

  /**
   * Initializes the agent via reflection.
   *
   * <p>This method uses reflection to call AgentInitializer.initialize() because:
   *
   * <ul>
   *   <li>AgentInitializer imports bootstrap types
   *   <li>Those types are now available (after injectBootstrapClasses)
   *   <li>Using reflection defers class loading until this method runs
   * </ul>
   */
  private static void initializeAgent(String agentArgs, Instrumentation inst) throws Exception {
    Class<?> initClass = Class.forName("io.jguard.agent.AgentInitializer");
    Method initMethod = initClass.getMethod("initialize", String.class, Instrumentation.class);
    initMethod.invoke(null, agentArgs, inst);
  }
}
