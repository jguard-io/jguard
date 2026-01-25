/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.agent;

import static net.bytebuddy.matcher.ElementMatchers.isConstructor;
import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.none;
import static net.bytebuddy.matcher.ElementMatchers.takesArgument;
import static net.bytebuddy.matcher.ElementMatchers.takesArguments;
import static net.bytebuddy.matcher.ElementMatchers.takesNoArguments;

import io.jguard.bootstrap.AgentConfig;
import io.jguard.bootstrap.AgentLogger;
import io.jguard.bootstrap.EnforcementMode;
import io.jguard.policy.model.ApplicationPolicy;
import io.jguard.policy.serialization.BinaryPolicyReader;
import java.io.IOException;
import java.io.InputStream;
import java.lang.instrument.Instrumentation;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicReference;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.utility.JavaModule;

/**
 * Agent initialization logic that can freely reference bootstrap types.
 *
 * <p>This class is loaded via reflection AFTER bootstrap injection, ensuring all
 * io.jguard.bootstrap.* types are available from the bootstrap classloader.
 *
 * <p>The two-phase initialization solves the classloader chicken-and-egg problem:
 *
 * <ol>
 *   <li>JGuardAgent.premain() injects bootstrap.jar (no bootstrap imports allowed)
 *   <li>JGuardAgent calls AgentInitializer.initialize() via reflection
 *   <li>AgentInitializer can freely use bootstrap types (they're now on bootstrap classpath)
 * </ol>
 */
public final class AgentInitializer {

  private static final AgentLogger LOG = AgentLogger.getLogger(AgentInitializer.class);

  private static final AtomicReference<PolicyEnforcer> enforcerRef = new AtomicReference<>();
  private static volatile AgentConfig config;
  private static volatile PolicyReloader reloader;
  private static volatile boolean initialized;

  private AgentInitializer() {}

  /**
   * Initializes the agent after bootstrap injection.
   *
   * <p>Called via reflection from JGuardAgent.premain() after bootstrap.jar is injected.
   *
   * @param agentArgs the agent arguments (policy path)
   * @param inst the instrumentation instance
   * @throws Exception if initialization fails
   */
  public static void initialize(String agentArgs, Instrumentation inst) throws Exception {
    // Parse configuration and set up logging
    config = AgentConfig.fromSystemProperties(agentArgs);
    AgentLogger.setLevel(config.logLevel());

    LOG.info("jGuard agent starting (mode={})", config.mode());
    LOG.info(
        "Logging config: logDenied={}, logAllowed={}", config.logDenied(), config.logAllowed());

    // Load policy - either via discovery or from explicit path
    ApplicationPolicy policy;
    ApplicationPolicy basePolicy = null; // For hot reload in discovery mode
    if (config.discoveryEnabled()) {
      LOG.info("Policy discovery enabled - scanning for embedded policies");
      try {
        basePolicy = PolicyDiscovery.discoverEmbedded(config);
        policy = basePolicy;
      } catch (PolicyDiscovery.PolicyDiscoveryException e) {
        throw new RuntimeException("Policy discovery failed: " + e.getMessage(), e);
      }
    } else {
      LOG.info("Loading policy from explicit path: {}", config.policyPath());
      policy = loadPolicy(config.policyPath());
    }

    // Apply policy overrides if configured
    if (config.overrideDir() != null) {
      LOG.info("Applying policy overrides from: {}", config.overrideDir());
      policy = PolicyMerger.merge(policy, config.overrideDir());
    }

    PolicyEnforcer enforcer = new PolicyEnforcer(policy, config);
    enforcerRef.set(enforcer);

    // Configure the bootstrap enforcer
    configureBootstrapEnforcer();

    // Install instrumentation
    installInstrumentation(inst);

    // Start hot reload if enabled
    boolean hotReloadStarted = false;
    if (config.hotReloadEnabled()) {
      if (config.discoveryEnabled()) {
        // Discovery mode: hot reload external overrides only (base policy is cached)
        if (config.overrideDir() != null) {
          reloader =
              PolicyReloader.forDiscoveryMode(
                  basePolicy, enforcerRef, config, config.hotReloadIntervalSeconds());
          reloader.start();
          hotReloadStarted = true;
        } else {
          LOG.warn(
              "Hot reload in discovery mode requires an override directory "
                  + "(set -Djguard.policy.override=<dir>)");
        }
      } else {
        // Explicit path mode: hot reload policy file and/or overrides
        reloader =
            new PolicyReloader(
                config.policyPath(), enforcerRef, config, config.hotReloadIntervalSeconds());
        reloader.start();
        hotReloadStarted = true;
      }
    }

    initialized = true;
    LOG.info(
        "jGuard agent initialized successfully for {} module(s): {} (mode={}, hotReload={})",
        policy.modules().size(),
        enforcer.getModuleNames(),
        config.mode(),
        hotReloadStarted);
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

  private static ApplicationPolicy loadPolicy(Path path) throws IOException {
    if (!Files.exists(path)) {
      throw new IOException("Policy file not found: " + path);
    }
    LOG.info("Loading policy from: {}", path);
    // Use readApplicationPolicy to support both v1 and v2 formats
    try (InputStream is = Files.newInputStream(path)) {
      return BinaryPolicyReader.readApplicationPolicy(is);
    }
  }

  /**
   * Configures the bootstrap enforcer with the single callback and settings.
   *
   * <p>This uses a direct lambda (no Proxy) because bootstrap types have single identity at
   * runtime. The agent compiles against bootstrap types (compileOnly) but doesn't package them. At
   * runtime, when agent code references io.jguard.bootstrap.*, the app classloader delegates to the
   * bootstrap classloader, which finds the classes from the injected bootstrap.jar.
   *
   * <p>The callback uses enforcerRef.get() to support hot reload - when the policy is reloaded, the
   * new PolicyEnforcer is swapped into the AtomicReference and subsequent calls will use it.
   */
  private static void configureBootstrapEnforcer() {
    // Direct lambda using AtomicReference for hot reload support
    io.jguard.bootstrap.EnforcementCallback callback =
        (caller, op, arg0, arg1) -> enforcerRef.get().check(caller, op, arg0, arg1);

    io.jguard.bootstrap.BootstrapEnforcer.setCallback(callback);
    io.jguard.bootstrap.BootstrapEnforcer.setMode(config.mode());
    io.jguard.bootstrap.BootstrapEnforcer.setLogging(config.logDenied(), config.logAllowed());

    LOG.debug("Bootstrap enforcer configured successfully");
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
                            .on(named("deleteIfExists").and(takesArgument(0, Path.class))))
                    // Hard link creation (fs.hardlink)
                    .visit(
                        Advice.to(FilesystemInterceptor.HardLinkAdvice.class)
                            .on(
                                named("createLink")
                                    .and(takesArgument(0, Path.class))
                                    .and(takesArgument(1, Path.class)))))
        // Instrument java.io.FileInputStream - legacy IO API
        .type(named("java.io.FileInputStream"))
        .transform(
            (builder, typeDescription, classLoader, module, protectionDomain) ->
                builder
                    .visit(
                        Advice.to(FilesystemInterceptor.FileAdvice.class)
                            .on(isConstructor().and(takesArgument(0, java.io.File.class))))
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
                            .on(isConstructor().and(takesArgument(0, java.io.File.class))))
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
                            .on(isConstructor().and(takesArgument(0, java.io.File.class))))
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
                            .on(isConstructor().and(takesArgument(0, java.io.File.class))))
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
                            .on(isConstructor().and(takesArgument(0, java.io.File.class))))
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
        // ========== THREAD INSTRUMENTATION (threads.create) ==========
        // Instrument java.lang.Thread - thread creation
        .type(named("java.lang.Thread"))
        .transform(
            (builder, typeDescription, classLoader, module, protectionDomain) ->
                builder.visit(
                    Advice.to(ThreadInterceptor.ThreadStartAdvice.class)
                        .on(named("start").and(takesArguments(0)))))
        // ========== NATIVE LIBRARY INSTRUMENTATION (native.load) ==========
        // Instrument java.lang.System - native library loading, env, and property access
        .type(named("java.lang.System"))
        .transform(
            (builder, typeDescription, classLoader, module, protectionDomain) ->
                builder
                    // Native library loading
                    .visit(
                        Advice.to(NativeInterceptor.LoadLibraryAdvice.class)
                            .on(named("loadLibrary").and(takesArgument(0, String.class))))
                    .visit(
                        Advice.to(NativeInterceptor.LoadAdvice.class)
                            .on(named("load").and(takesArgument(0, String.class))))
                    // ========== ENVIRONMENT VARIABLE ACCESS (env.read) ==========
                    // System.getenv() - bulk read (returns Map<String, String>)
                    .visit(
                        Advice.to(EnvInterceptor.GetEnvAllAdvice.class)
                            .on(named("getenv").and(takesNoArguments())))
                    // System.getenv(String) - single variable read
                    .visit(
                        Advice.to(EnvInterceptor.GetEnvAdvice.class)
                            .on(named("getenv").and(takesArgument(0, String.class))))
                    // ========== SYSTEM PROPERTY ACCESS (system.property.read/write) ==========
                    // System.getProperty(String) - single property read
                    .visit(
                        Advice.to(PropertyInterceptor.GetPropertyAdvice.class)
                            .on(
                                named("getProperty")
                                    .and(takesArgument(0, String.class))
                                    .and(takesArguments(1))))
                    // System.getProperty(String, String) - single property read with default
                    .visit(
                        Advice.to(PropertyInterceptor.GetPropertyAdvice.class)
                            .on(
                                named("getProperty")
                                    .and(takesArgument(0, String.class))
                                    .and(takesArgument(1, String.class))))
                    // System.getProperties() - bulk property read
                    .visit(
                        Advice.to(PropertyInterceptor.GetPropertiesAdvice.class)
                            .on(named("getProperties").and(takesNoArguments())))
                    // System.setProperty(String, String) - single property write
                    .visit(
                        Advice.to(PropertyInterceptor.SetPropertyAdvice.class)
                            .on(
                                named("setProperty")
                                    .and(takesArgument(0, String.class))
                                    .and(takesArgument(1, String.class))))
                    // System.setProperties(Properties) - bulk property write
                    .visit(
                        Advice.to(PropertyInterceptor.SetPropertiesAdvice.class)
                            .on(
                                named("setProperties")
                                    .and(takesArguments(java.util.Properties.class))))
                    // System.clearProperty(String) - single property removal (write)
                    .visit(
                        Advice.to(PropertyInterceptor.ClearPropertyAdvice.class)
                            .on(named("clearProperty").and(takesArgument(0, String.class)))))
        // Instrument java.lang.Runtime - native library loading and process execution
        .type(named("java.lang.Runtime"))
        .transform(
            (builder, typeDescription, classLoader, module, protectionDomain) ->
                builder
                    // Native library loading
                    .visit(
                        Advice.to(NativeInterceptor.LoadLibraryAdvice.class)
                            .on(named("loadLibrary").and(takesArgument(0, String.class))))
                    .visit(
                        Advice.to(NativeInterceptor.LoadAdvice.class)
                            .on(named("load").and(takesArgument(0, String.class))))
                    // ========== PROCESS EXECUTION (process.exec) ==========
                    // Runtime.exec(String) - single command string
                    .visit(
                        Advice.to(ProcessInterceptor.ExecStringAdvice.class)
                            .on(
                                named("exec")
                                    .and(takesArgument(0, String.class))
                                    .and(takesArguments(1))))
                    // Runtime.exec(String, String[]) - command with env
                    .visit(
                        Advice.to(ProcessInterceptor.ExecStringAdvice.class)
                            .on(
                                named("exec")
                                    .and(takesArgument(0, String.class))
                                    .and(takesArgument(1, String[].class))
                                    .and(takesArguments(2))))
                    // Runtime.exec(String, String[], File) - command with env and dir
                    .visit(
                        Advice.to(ProcessInterceptor.ExecStringAdvice.class)
                            .on(
                                named("exec")
                                    .and(takesArgument(0, String.class))
                                    .and(takesArgument(1, String[].class))
                                    .and(takesArgument(2, java.io.File.class))))
                    // Runtime.exec(String[]) - command array
                    .visit(
                        Advice.to(ProcessInterceptor.ExecArrayAdvice.class)
                            .on(
                                named("exec")
                                    .and(takesArgument(0, String[].class))
                                    .and(takesArguments(1))))
                    // Runtime.exec(String[], String[]) - command array with env
                    .visit(
                        Advice.to(ProcessInterceptor.ExecArrayAdvice.class)
                            .on(
                                named("exec")
                                    .and(takesArgument(0, String[].class))
                                    .and(takesArgument(1, String[].class))
                                    .and(takesArguments(2))))
                    // Runtime.exec(String[], String[], File) - command array with env and dir
                    .visit(
                        Advice.to(ProcessInterceptor.ExecArrayAdvice.class)
                            .on(
                                named("exec")
                                    .and(takesArgument(0, String[].class))
                                    .and(takesArgument(1, String[].class))
                                    .and(takesArgument(2, java.io.File.class)))))
        // ========== PROCESS BUILDER INSTRUMENTATION (process.exec) ==========
        .type(named("java.lang.ProcessBuilder"))
        .transform(
            (builder, typeDescription, classLoader, module, protectionDomain) ->
                builder.visit(
                    Advice.to(ProcessInterceptor.ProcessBuilderStartAdvice.class)
                        .on(named("start").and(takesNoArguments()))))
        // ========== CRYPTO PROVIDER INSTRUMENTATION (crypto.provider) ==========
        .type(named("java.security.Security"))
        .transform(
            (builder, typeDescription, classLoader, module, protectionDomain) ->
                builder
                    // Security.addProvider(Provider)
                    .visit(
                        Advice.to(SecurityInterceptor.ProviderModificationAdvice.class)
                            .on(
                                named("addProvider")
                                    .and(takesArgument(0, java.security.Provider.class))))
                    // Security.insertProviderAt(Provider, int)
                    .visit(
                        Advice.to(SecurityInterceptor.ProviderModificationAdvice.class)
                            .on(
                                named("insertProviderAt")
                                    .and(takesArgument(0, java.security.Provider.class))
                                    .and(takesArgument(1, int.class))))
                    // Security.removeProvider(String)
                    .visit(
                        Advice.to(SecurityInterceptor.ProviderModificationAdvice.class)
                            .on(named("removeProvider").and(takesArgument(0, String.class))))
                    // Security.setProperty(String, String)
                    .visit(
                        Advice.to(SecurityInterceptor.ProviderModificationAdvice.class)
                            .on(
                                named("setProperty")
                                    .and(takesArgument(0, String.class))
                                    .and(takesArgument(1, String.class)))))
        .installOn(inst);

    LOG.debug("Instrumentation installed");
  }

  /** Listener for ByteBuddy transformation events. */
  private static class LoggingListener implements AgentBuilder.Listener {

    @Override
    public void onDiscovery(
        String typeName, ClassLoader classLoader, JavaModule module, boolean loaded) {
      // Log discovery of classes we're interested in
      if (typeName.contains("Socket")
          || typeName.contains("ServerSocket")
          || typeName.contains("Files")
          || typeName.equals("java.lang.System")) {
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
      if (name.contains("Socket")
          || name.equals("java.nio.file.Files")
          || name.equals("java.lang.System")) {
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
