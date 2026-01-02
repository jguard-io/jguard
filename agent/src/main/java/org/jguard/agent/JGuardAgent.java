/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.jguard.agent;

import static net.bytebuddy.matcher.ElementMatchers.isConstructor;
import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.none;
import static net.bytebuddy.matcher.ElementMatchers.takesArgument;
import static net.bytebuddy.matcher.ElementMatchers.takesArguments;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.lang.instrument.Instrumentation;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.jar.JarFile;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.utility.JavaModule;
import org.jguard.bootstrap.AgentConfig;
import org.jguard.bootstrap.AgentLogger;
import org.jguard.bootstrap.EnforcementMode;
import org.jguard.policy.model.PolicyDescriptor;
import org.jguard.policy.serialization.BinaryPolicyReader;

/**
 * jGuard Java agent entry point.
 *
 * <p>This agent enforces capability-based security policies by instrumenting JDK classes to check
 * entitlements before sensitive operations.
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
 */
public final class JGuardAgent {

  private static final AgentLogger LOG = AgentLogger.getLogger(JGuardAgent.class);

  /** Resource path for the embedded bootstrap JAR. */
  private static final String BOOTSTRAP_JAR_RESOURCE = "/jguard/bootstrap.jar";

  private static volatile PolicyEnforcer enforcer;
  private static volatile AgentConfig config;
  private static volatile boolean initialized;

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
      // Parse configuration first to set up logging
      config = AgentConfig.fromSystemProperties(agentArgs);
      AgentLogger.setLevel(config.logLevel());

      LOG.info("jGuard agent starting (mode={})", config.mode());

      // Inject bootstrap classes FIRST - before any other operations
      injectBootstrapClasses(inst);

      // Load policy
      PolicyDescriptor policy = loadPolicy(config.policyPath());
      enforcer = new PolicyEnforcer(policy, config);

      // Configure the bootstrap enforcer
      configureBootstrapEnforcer();

      // Install instrumentation
      installInstrumentation(inst);

      initialized = true;
      LOG.info(
          "jGuard agent initialized successfully for module: {} (mode={})",
          policy.moduleName(),
          config.mode());

    } catch (Exception e) {
      handleInitializationError(e);
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
   * Returns true if the agent is initialized and enforcing policies.
   *
   * @return true if initialized
   */
  public static boolean isInitialized() {
    return initialized;
  }

  /**
   * Returns the current enforcement mode, or STRICT if not initialized.
   *
   * @return the enforcement mode
   */
  public static EnforcementMode getMode() {
    return config != null ? config.mode() : EnforcementMode.STRICT;
  }

  private static PolicyDescriptor loadPolicy(Path path) throws IOException {
    if (!Files.exists(path)) {
      throw new IOException("Policy file not found: " + path);
    }
    LOG.info("Loading policy from: {}", path);
    return BinaryPolicyReader.fromFile(path);
  }

  /**
   * Injects bootstrap classes into the bootstrap classloader.
   *
   * <p>This uses the production-grade approach: extract the embedded bootstrap JAR and use {@link
   * Instrumentation#appendToBootstrapClassLoaderSearch(JarFile)} to add it to the bootstrap
   * classpath.
   *
   * <p>This is more robust than the temp-directory class injection approach because:
   *
   * <ul>
   *   <li>The JAR is a proper artifact that can be verified
   *   <li>All classes are loaded atomically from the JAR
   *   <li>No need to manually inject individual class files
   *   <li>The Instrumentation API handles all edge cases
   * </ul>
   */
  private static void injectBootstrapClasses(Instrumentation inst) throws IOException {
    LOG.debug("Injecting bootstrap classes...");

    // Extract embedded bootstrap JAR to temp file
    File bootstrapJar = extractBootstrapJar();

    // Add to bootstrap classloader search path
    inst.appendToBootstrapClassLoaderSearch(new JarFile(bootstrapJar));

    LOG.debug("Bootstrap classes injected successfully from: {}", bootstrapJar);
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

      LOG.trace("Extracted bootstrap JAR to: {}", tempJar);
      return tempFile;
    }
  }

  /**
   * Configures the bootstrap enforcer with the callback and settings.
   *
   * <p>We must use reflection because:
   *
   * <ul>
   *   <li>BootstrapEnforcer was loaded by the bootstrap classloader
   *   <li>The class visible to us is from the agent classloader
   *   <li>These are different Class objects with separate static fields
   * </ul>
   */
  private static void configureBootstrapEnforcer() {
    try {
      // Load BootstrapEnforcer from bootstrap classloader
      Class<?> enforcerClass = Class.forName("org.jguard.bootstrap.BootstrapEnforcer", true, null);

      // Load EnforcementMode from bootstrap classloader
      Class<?> modeClass = Class.forName("org.jguard.bootstrap.EnforcementMode", true, null);

      // Get CallerContext class from bootstrap classloader
      Class<?> callerContextClass =
          Class.forName("org.jguard.bootstrap.BootstrapEnforcer$CallerContext", true, null);

      // Set the enforcement callback
      java.lang.reflect.Method setCallback =
          enforcerClass.getMethod("setFsReadCallback", java.util.function.BiFunction.class);

      // The callback receives CallerContext from bootstrap classloader, so we need to
      // extract its fields via reflection and create our own CallerContext
      java.util.function.BiFunction<Object, Path, SecurityException> readCallback =
          (bootstrapContext, path) -> {
            try {
              // Extract package and module from the bootstrap CallerContext
              java.lang.reflect.Method getPackage = callerContextClass.getMethod("packageName");
              java.lang.reflect.Method getModule = callerContextClass.getMethod("moduleName");
              String packageName = (String) getPackage.invoke(bootstrapContext);
              String moduleName = (String) getModule.invoke(bootstrapContext);

              // Create our CallerContext (from agent classloader) with the same values
              org.jguard.bootstrap.BootstrapEnforcer.CallerContext context =
                  new org.jguard.bootstrap.BootstrapEnforcer.CallerContext(packageName, moduleName);

              return enforcer.checkFsReadReturningException(context, path);
            } catch (Exception e) {
              throw new RuntimeException("Failed to extract caller context", e);
            }
          };

      setCallback.invoke(null, readCallback);

      // Set up fs.write callback
      java.lang.reflect.Method setWriteCallback =
          enforcerClass.getMethod("setFsWriteCallback", java.util.function.BiFunction.class);

      java.util.function.BiFunction<Object, Path, SecurityException> writeCallback =
          (bootstrapContext, path) -> {
            try {
              java.lang.reflect.Method getPackage = callerContextClass.getMethod("packageName");
              java.lang.reflect.Method getModule = callerContextClass.getMethod("moduleName");
              String packageName = (String) getPackage.invoke(bootstrapContext);
              String moduleName = (String) getModule.invoke(bootstrapContext);

              org.jguard.bootstrap.BootstrapEnforcer.CallerContext context =
                  new org.jguard.bootstrap.BootstrapEnforcer.CallerContext(packageName, moduleName);

              return enforcer.checkFsWriteReturningException(context, path);
            } catch (Exception e) {
              throw new RuntimeException("Failed to extract caller context", e);
            }
          };

      setWriteCallback.invoke(null, writeCallback);

      // Set up network.outbound callback
      java.lang.reflect.Method setNetworkCallback =
          enforcerClass.getMethod("setNetworkOutboundCallback", java.util.function.Function.class);

      java.util.function.Function<Object, SecurityException> networkCallback =
          (bootstrapContext) -> {
            try {
              java.lang.reflect.Method getPackage = callerContextClass.getMethod("packageName");
              java.lang.reflect.Method getModule = callerContextClass.getMethod("moduleName");
              String packageName = (String) getPackage.invoke(bootstrapContext);
              String moduleName = (String) getModule.invoke(bootstrapContext);

              org.jguard.bootstrap.BootstrapEnforcer.CallerContext context =
                  new org.jguard.bootstrap.BootstrapEnforcer.CallerContext(packageName, moduleName);

              return enforcer.checkNetworkOutboundReturningException(context);
            } catch (Exception e) {
              throw new RuntimeException("Failed to extract caller context", e);
            }
          };

      setNetworkCallback.invoke(null, networkCallback);

      // Set up network.listen callback
      java.lang.reflect.Method setNetworkListenCallback =
          enforcerClass.getMethod("setNetworkListenCallback", java.util.function.BiFunction.class);

      java.util.function.BiFunction<Object, Integer, SecurityException> networkListenCallback =
          (bootstrapContext, port) -> {
            try {
              java.lang.reflect.Method getPackage = callerContextClass.getMethod("packageName");
              java.lang.reflect.Method getModule = callerContextClass.getMethod("moduleName");
              String packageName = (String) getPackage.invoke(bootstrapContext);
              String moduleName = (String) getModule.invoke(bootstrapContext);

              org.jguard.bootstrap.BootstrapEnforcer.CallerContext context =
                  new org.jguard.bootstrap.BootstrapEnforcer.CallerContext(packageName, moduleName);

              return enforcer.checkNetworkListenReturningException(context, port);
            } catch (Exception e) {
              throw new RuntimeException("Failed to extract caller context", e);
            }
          };

      setNetworkListenCallback.invoke(null, networkListenCallback);

      // Set enforcement mode
      java.lang.reflect.Method setMode = enforcerClass.getMethod("setMode", modeClass);
      Object bootstrapMode = getEnumConstant(modeClass, config.mode().name());
      setMode.invoke(null, bootstrapMode);

      // Set logging configuration
      java.lang.reflect.Method setLogging =
          enforcerClass.getMethod("setLogging", boolean.class, boolean.class);
      setLogging.invoke(null, config.logDenied(), config.logAllowed());

      LOG.debug("Bootstrap enforcer configured successfully");

    } catch (Exception e) {
      throw new RuntimeException("Failed to configure bootstrap enforcer", e);
    }
  }

  private static void installInstrumentation(Instrumentation inst) {
    LOG.debug("Installing instrumentation...");

    // Check if retransformation is supported
    if (!inst.isRetransformClassesSupported()) {
      LOG.warn("Retransformation not supported - network instrumentation may not work");
    }

    new AgentBuilder.Default()
        .disableClassFormatChanges()
        .with(AgentBuilder.RedefinitionStrategy.RETRANSFORMATION)
        .with(AgentBuilder.RedefinitionStrategy.DiscoveryStrategy.Reiterating.INSTANCE)
        .with(AgentBuilder.TypeStrategy.Default.REDEFINE)
        .with(new LoggingListener())
        .ignore(none())
        // Instrument java.nio.file.Files - the primary NIO filesystem API
        .type(named("java.nio.file.Files"))
        .transform(
            (builder, typeDescription, classLoader, module, protectionDomain) ->
                builder
                    .visit(
                        Advice.to(FilesystemInterceptor.PathAdvice.class)
                            .on(named("newInputStream").and(takesArgument(0, Path.class))))
                    .visit(
                        Advice.to(FilesystemInterceptor.PathAdvice.class)
                            .on(named("newBufferedReader").and(takesArgument(0, Path.class))))
                    .visit(
                        Advice.to(FilesystemInterceptor.PathAdvice.class)
                            .on(named("readAllBytes").and(takesArgument(0, Path.class))))
                    .visit(
                        Advice.to(FilesystemInterceptor.PathAdvice.class)
                            .on(named("readAllLines").and(takesArgument(0, Path.class))))
                    .visit(
                        Advice.to(FilesystemInterceptor.PathAdvice.class)
                            .on(named("readString").and(takesArgument(0, Path.class))))
                    .visit(
                        Advice.to(FilesystemInterceptor.PathAdvice.class)
                            .on(named("lines").and(takesArgument(0, Path.class))))
                    .visit(
                        Advice.to(FilesystemInterceptor.PathAdvice.class)
                            .on(named("list").and(takesArgument(0, Path.class))))
                    .visit(
                        Advice.to(FilesystemInterceptor.PathAdvice.class)
                            .on(named("walk").and(takesArgument(0, Path.class))))
                    .visit(
                        Advice.to(FilesystemInterceptor.PathAdvice.class)
                            .on(named("find").and(takesArgument(0, Path.class))))
                    // Write operations
                    .visit(
                        Advice.to(FilesystemInterceptor.WritePathAdvice.class)
                            .on(named("write").and(takesArgument(0, Path.class))))
                    .visit(
                        Advice.to(FilesystemInterceptor.WritePathAdvice.class)
                            .on(named("writeString").and(takesArgument(0, Path.class))))
                    .visit(
                        Advice.to(FilesystemInterceptor.WritePathAdvice.class)
                            .on(named("newOutputStream").and(takesArgument(0, Path.class))))
                    .visit(
                        Advice.to(FilesystemInterceptor.WritePathAdvice.class)
                            .on(named("newBufferedWriter").and(takesArgument(0, Path.class))))
                    .visit(
                        Advice.to(FilesystemInterceptor.WritePathAdvice.class)
                            .on(named("createFile").and(takesArgument(0, Path.class))))
                    .visit(
                        Advice.to(FilesystemInterceptor.WritePathAdvice.class)
                            .on(named("createDirectory").and(takesArgument(0, Path.class))))
                    .visit(
                        Advice.to(FilesystemInterceptor.WritePathAdvice.class)
                            .on(named("createDirectories").and(takesArgument(0, Path.class))))
                    .visit(
                        Advice.to(FilesystemInterceptor.WritePathAdvice.class)
                            .on(named("delete").and(takesArgument(0, Path.class))))
                    .visit(
                        Advice.to(FilesystemInterceptor.WritePathAdvice.class)
                            .on(named("deleteIfExists").and(takesArgument(0, Path.class)))))
        // Instrument java.io.FileInputStream - legacy IO API
        .type(named("java.io.FileInputStream"))
        .transform(
            (builder, typeDescription, classLoader, module, protectionDomain) ->
                builder
                    .visit(
                        Advice.to(FilesystemInterceptor.FileAdvice.class)
                            .on(isConstructor().and(takesArgument(0, File.class))))
                    .visit(
                        Advice.to(FilesystemInterceptor.StringPathAdvice.class)
                            .on(isConstructor().and(takesArgument(0, String.class)))))
        // Instrument java.io.RandomAccessFile - direct file access
        .type(named("java.io.RandomAccessFile"))
        .transform(
            (builder, typeDescription, classLoader, module, protectionDomain) ->
                builder
                    .visit(
                        Advice.to(FilesystemInterceptor.FileAdvice.class)
                            .on(isConstructor().and(takesArgument(0, File.class))))
                    .visit(
                        Advice.to(FilesystemInterceptor.StringPathAdvice.class)
                            .on(isConstructor().and(takesArgument(0, String.class)))))
        // Instrument java.io.FileReader - character stream API
        .type(named("java.io.FileReader"))
        .transform(
            (builder, typeDescription, classLoader, module, protectionDomain) ->
                builder
                    .visit(
                        Advice.to(FilesystemInterceptor.FileAdvice.class)
                            .on(isConstructor().and(takesArgument(0, File.class))))
                    .visit(
                        Advice.to(FilesystemInterceptor.StringPathAdvice.class)
                            .on(isConstructor().and(takesArgument(0, String.class)))))
        // Instrument java.nio.channels.FileChannel - NIO channel API
        .type(named("java.nio.channels.FileChannel"))
        .transform(
            (builder, typeDescription, classLoader, module, protectionDomain) ->
                builder.visit(
                    Advice.to(FilesystemInterceptor.PathAdvice.class)
                        .on(named("open").and(takesArgument(0, Path.class)))))
        // Instrument java.io.FileOutputStream - legacy IO write API
        .type(named("java.io.FileOutputStream"))
        .transform(
            (builder, typeDescription, classLoader, module, protectionDomain) ->
                builder
                    .visit(
                        Advice.to(FilesystemInterceptor.WriteFileAdvice.class)
                            .on(isConstructor().and(takesArgument(0, File.class))))
                    .visit(
                        Advice.to(FilesystemInterceptor.WriteStringPathAdvice.class)
                            .on(isConstructor().and(takesArgument(0, String.class)))))
        // Instrument java.io.FileWriter - character stream write API
        .type(named("java.io.FileWriter"))
        .transform(
            (builder, typeDescription, classLoader, module, protectionDomain) ->
                builder
                    .visit(
                        Advice.to(FilesystemInterceptor.WriteFileAdvice.class)
                            .on(isConstructor().and(takesArgument(0, File.class))))
                    .visit(
                        Advice.to(FilesystemInterceptor.WriteStringPathAdvice.class)
                            .on(isConstructor().and(takesArgument(0, String.class)))))
        // ========== NETWORK INSTRUMENTATION ==========
        // Instrument java.net.Socket - the primary TCP socket API
        .type(named("java.net.Socket"))
        .transform(
            (builder, typeDescription, classLoader, module, protectionDomain) ->
                builder
                    // Socket(String host, int port)
                    .visit(
                        Advice.to(NetworkInterceptor.SocketHostPortAdvice.class)
                            .on(
                                isConstructor()
                                    .and(takesArgument(0, String.class))
                                    .and(takesArgument(1, int.class))
                                    .and(takesArguments(2))))
                    // Socket(InetAddress address, int port)
                    .visit(
                        Advice.to(NetworkInterceptor.SocketInetAddressPortAdvice.class)
                            .on(
                                isConstructor()
                                    .and(takesArgument(0, java.net.InetAddress.class))
                                    .and(takesArgument(1, int.class))
                                    .and(takesArguments(2))))
                    // Socket.connect(SocketAddress, int timeout)
                    .visit(
                        Advice.to(NetworkInterceptor.SocketConnectAdvice.class)
                            .on(
                                named("connect")
                                    .and(takesArgument(0, java.net.SocketAddress.class)))))
        // Instrument java.nio.channels.SocketChannel - NIO socket API
        .type(named("java.nio.channels.SocketChannel"))
        .transform(
            (builder, typeDescription, classLoader, module, protectionDomain) ->
                builder.visit(
                    Advice.to(NetworkInterceptor.SocketChannelConnectAdvice.class)
                        .on(named("connect").and(takesArgument(0, java.net.SocketAddress.class)))))
        // ========== SERVER SOCKET INSTRUMENTATION (network.listen) ==========
        // Instrument java.net.ServerSocket - the primary server socket API
        .type(named("java.net.ServerSocket"))
        .transform(
            (builder, typeDescription, classLoader, module, protectionDomain) ->
                builder
                    // ServerSocket(int port)
                    .visit(
                        Advice.to(NetworkInterceptor.ServerSocketPortAdvice.class)
                            .on(
                                isConstructor()
                                    .and(takesArgument(0, int.class))
                                    .and(takesArguments(1))))
                    // ServerSocket(int port, int backlog)
                    .visit(
                        Advice.to(NetworkInterceptor.ServerSocketPortAdvice.class)
                            .on(
                                isConstructor()
                                    .and(takesArgument(0, int.class))
                                    .and(takesArgument(1, int.class))
                                    .and(takesArguments(2))))
                    // ServerSocket(int port, int backlog, InetAddress bindAddr)
                    .visit(
                        Advice.to(NetworkInterceptor.ServerSocketPortAdvice.class)
                            .on(
                                isConstructor()
                                    .and(takesArgument(0, int.class))
                                    .and(takesArgument(1, int.class))
                                    .and(takesArgument(2, java.net.InetAddress.class))))
                    // ServerSocket.bind(SocketAddress)
                    .visit(
                        Advice.to(NetworkInterceptor.ServerSocketBindAdvice.class)
                            .on(named("bind").and(takesArgument(0, java.net.SocketAddress.class)))))
        // Instrument java.nio.channels.ServerSocketChannel - NIO server socket API
        .type(named("java.nio.channels.ServerSocketChannel"))
        .transform(
            (builder, typeDescription, classLoader, module, protectionDomain) ->
                builder.visit(
                    Advice.to(NetworkInterceptor.ServerSocketChannelBindAdvice.class)
                        .on(named("bind").and(takesArgument(0, java.net.SocketAddress.class)))))
        .installOn(inst);

    LOG.debug("Instrumentation installed");
  }

  /**
   * Gets an enum constant by name from a class loaded in a different classloader.
   *
   * <p>This avoids unchecked warnings from using Enum.valueOf with dynamic class types.
   */
  @SuppressWarnings("unchecked")
  private static <T extends Enum<T>> T getEnumConstant(Class<?> enumClass, String name) {
    return Enum.valueOf((Class<T>) enumClass, name);
  }

  private static void handleInitializationError(Exception e) {
    LOG.error("Failed to initialize jGuard agent", e);

    // In STRICT mode (or if we couldn't parse config), fail hard
    if (config == null || config.mode() == EnforcementMode.STRICT) {
      throw new RuntimeException("jGuard agent initialization failed", e);
    }

    // In PERMISSIVE or AUDIT mode, log and continue without enforcement
    LOG.warn(
        "jGuard agent failed to initialize but continuing without enforcement (mode={})",
        config.mode());
  }

  /** Listener for ByteBuddy transformation events. */
  private static class LoggingListener implements AgentBuilder.Listener {

    @Override
    public void onDiscovery(
        String typeName, ClassLoader classLoader, JavaModule module, boolean loaded) {
      // Log discovery of classes we're interested in
      if (typeName.contains("Socket")
          || typeName.contains("ServerSocket")
          || typeName.contains("Files")) {
        LOG.debug("Discovered: {} (loaded={})", typeName, loaded);
      }
    }

    @Override
    public void onTransformation(
        TypeDescription typeDescription,
        ClassLoader classLoader,
        JavaModule module,
        boolean loaded,
        DynamicType dynamicType) {
      LOG.info("Transformed: {} (loaded={})", typeDescription.getName(), loaded);
    }

    @Override
    public void onIgnored(
        TypeDescription typeDescription,
        ClassLoader classLoader,
        JavaModule module,
        boolean loaded) {
      // Log ignored classes we're interested in
      String name = typeDescription.getName();
      if (name.contains("Socket") || name.equals("java.nio.file.Files")) {
        LOG.debug("Ignored: {} (loaded={})", name, loaded);
      }
    }

    @Override
    public void onError(
        String typeName,
        ClassLoader classLoader,
        JavaModule module,
        boolean loaded,
        Throwable throwable) {
      LOG.error("Error transforming: {} - {}", typeName, throwable.getMessage());
      if (typeName.contains("Socket")) {
        LOG.error("Socket transformation error details:", throwable);
      }
    }

    @Override
    public void onComplete(
        String typeName, ClassLoader classLoader, JavaModule module, boolean loaded) {
      // Not logged to avoid noise
    }
  }
}
