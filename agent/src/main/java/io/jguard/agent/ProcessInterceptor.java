/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.agent;

import io.jguard.bootstrap.BootstrapEnforcer;
import java.util.List;
import net.bytebuddy.asm.Advice;

/**
 * ByteBuddy advice for intercepting process execution operations.
 *
 * <p>This class contains advice that is woven into JDK classes to enforce the {@code process.exec}
 * capability.
 *
 * <p>Instrumented methods:
 *
 * <ul>
 *   <li>{@code Runtime.exec(String)} - executes command string
 *   <li>{@code Runtime.exec(String[])} - executes command array
 *   <li>{@code Runtime.exec(String[], String[])} - with environment
 *   <li>{@code Runtime.exec(String[], String[], File)} - with environment and working dir
 *   <li>{@code Runtime.exec(String, String[])} - command string with environment
 *   <li>{@code Runtime.exec(String, String[], File)} - command string with environment and dir
 *   <li>{@code ProcessBuilder.start()} - starts process from builder
 * </ul>
 */
public final class ProcessInterceptor {

  private ProcessInterceptor() {}

  /**
   * Advice for Runtime.exec(String) and Runtime.exec(String, String[], File).
   *
   * <p>Intercepts command execution by string.
   */
  public static class ExecStringAdvice {

    private ExecStringAdvice() {}

    @Advice.OnMethodEnter
    public static void onEnter(@Advice.Argument(0) String command) {
      BootstrapEnforcer.onProcessExec(command);
    }
  }

  /**
   * Advice for Runtime.exec(String[]) and Runtime.exec(String[], String[], File).
   *
   * <p>Intercepts command execution by array. Uses the first element as the command.
   */
  public static class ExecArrayAdvice {

    private ExecArrayAdvice() {}

    @Advice.OnMethodEnter
    public static void onEnter(@Advice.Argument(0) String[] cmdarray) {
      String command = (cmdarray != null && cmdarray.length > 0) ? cmdarray[0] : null;
      BootstrapEnforcer.onProcessExec(command);
    }
  }

  /**
   * Advice for ProcessBuilder.start().
   *
   * <p>Intercepts process start by extracting the command from the builder.
   */
  public static class ProcessBuilderStartAdvice {

    private ProcessBuilderStartAdvice() {}

    @Advice.OnMethodEnter
    public static void onEnter(@Advice.This ProcessBuilder builder) {
      List<String> cmdList = builder.command();
      String command = (cmdList != null && !cmdList.isEmpty()) ? cmdList.get(0) : null;
      BootstrapEnforcer.onProcessExec(command);
    }
  }
}
