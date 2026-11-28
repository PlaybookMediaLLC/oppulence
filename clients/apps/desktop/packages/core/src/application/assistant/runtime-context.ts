import path from 'path';

export type RuntimeShellDialect = 'windows-cmd' | 'posix-sh';
export type RuntimeOsName = 'Windows' | 'macOS' | 'Linux' | 'Unknown';

export interface RuntimeContext {
  platform: NodeJS.Platform;
  osName: RuntimeOsName;
  shellDialect: RuntimeShellDialect;
  shellExecutable: string;
}

export function getExecutionShell(platform: NodeJS.Platform = process.platform): string {
  if (platform === 'win32') {
    const rawSystemRoot = process.env.SystemRoot?.trim() || 'C:\\Windows';
    const systemRoot = /^[a-zA-Z]:[\\/]/.test(rawSystemRoot)
      ? path.win32.resolve(rawSystemRoot)
      : 'C:\\Windows';
    const defaultCmd = path.win32.join(systemRoot, 'System32', 'cmd.exe');
    const comSpec = process.env.ComSpec?.trim();
    if (comSpec && /^[a-zA-Z]:[\\/]/.test(comSpec)) {
      const normalizedComSpec = path.win32.resolve(comSpec).toLowerCase();
      const allowed = [
        path.win32.join(systemRoot, 'System32', 'cmd.exe').toLowerCase(),
        path.win32.join(systemRoot, 'SysWOW64', 'cmd.exe').toLowerCase(),
        path.win32.join(systemRoot, 'Sysnative', 'cmd.exe').toLowerCase(),
      ];
      if (allowed.includes(normalizedComSpec)) {
        return path.win32.resolve(comSpec);
      }
    }
    return defaultCmd;
  }

  // Always execute POSIX commands with /bin/sh so the runtime shell matches
  // command-executor's posix-sh parser (never inheriting fish/tcsh/zsh syntax
  // differentials from process.env.SHELL).
  return '/bin/sh';
}

export function getRuntimeContext(platform: NodeJS.Platform = process.platform): RuntimeContext {
  if (platform === 'win32') {
    return {
      platform,
      osName: 'Windows',
      shellDialect: 'windows-cmd',
      shellExecutable: getExecutionShell(platform),
    };
  }

  if (platform === 'darwin') {
    return {
      platform,
      osName: 'macOS',
      shellDialect: 'posix-sh',
      shellExecutable: getExecutionShell(platform),
    };
  }

  if (platform === 'linux') {
    return {
      platform,
      osName: 'Linux',
      shellDialect: 'posix-sh',
      shellExecutable: getExecutionShell(platform),
    };
  }

  return {
    platform,
    osName: 'Unknown',
    shellDialect: 'posix-sh',
    shellExecutable: getExecutionShell(platform),
  };
}

export function getRuntimeContextPrompt(runtime: RuntimeContext): string {
  if (runtime.shellDialect === 'windows-cmd') {
    return `## Runtime Platform (CRITICAL)
- Detected platform: **${runtime.platform}**
- Detected OS: **${runtime.osName}**
- Shell used by executeCommand: **${runtime.shellExecutable}** (Windows Command Prompt / cmd syntax)
- Use Windows command syntax for executeCommand (for example: \`dir\`, \`type\`, \`copy\`, \`move\`, \`del\`, \`rmdir\`).
- Use Windows-style absolute paths when outside workspace (for example: \`C:\\Users\\...\`).
- Do not assume macOS/Linux command syntax when the runtime is Windows.`;
  }

  return `## Runtime Platform (CRITICAL)
- Detected platform: **${runtime.platform}**
- Detected OS: **${runtime.osName}**
- Shell used by executeCommand: **${runtime.shellExecutable}** (POSIX sh syntax)
- Use POSIX command syntax for executeCommand (for example: \`ls\`, \`cat\`, \`cp\`, \`mv\`, \`rm\`).
- Use POSIX paths when outside workspace (for example: \`~/Desktop\`, \`/Users/.../\` on macOS, \`/home/.../\` on Linux).
- Do not assume Windows command syntax when the runtime is POSIX.`;
}
