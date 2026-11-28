import { exec, execSync, spawn, ChildProcess } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";
import { promisify } from "util";
import { WorkDir } from "../../config/config.js";
import {
  canonicalizePathSync,
  getSecurityAllowList,
  isPathInsideDir,
  isProtectedWorkspacePath,
  isSameNormalizedPath,
} from "../../config/security.js";
import {
  getExecutionShell,
  getRuntimeContext,
  type RuntimeShellDialect,
} from "../assistant/runtime-context.js";

const execPromise = promisify(exec);

const ENV_ASSIGNMENT_REGEX = /^[A-Za-z_][A-Za-z0-9_]*=.*/;
const WRAPPER_COMMANDS = new Set([
  "sudo",
  "su",
  "doas",
  "env",
  "time",
  "command",
  "nohup",
  "nice",
  "timeout",
  "stdbuf",
  "xargs",
  "watch",
  "exec",
  "builtin",
  // Shell precommand modifiers & control-flow keywords
  "!",
  "noglob",
  "nocorrect",
  "-",
  "if",
  "then",
  "elif",
  "else",
  "while",
  "until",
  "do",
  // OS wrappers, debuggers, sandboxes, and Windows call
  "arch",
  "caffeinate",
  "script",
  "setsid",
  "ionice",
  "chrt",
  "taskset",
  "flock",
  "sandbox-exec",
  "rlwrap",
  "strace",
  "ltrace",
  "gdb",
  "lldb",
  "chroot",
  "nsenter",
  "unshare",
  "bwrap",
  "ssh-agent",
  "systemd-run",
  "call",
]);
const SHELL_FUNCTION_DEFINITION_COMMAND = "function-definition";
const SHELL_FUNCTION_DEFINITION_REGEX =
  /^(?:function\s+[A-Za-z_][A-Za-z0-9_:-]*|[A-Za-z_][A-Za-z0-9_:-]*\s*\(\s*\))/;

const VERSIONED_INTERPRETER_REGEX =
  /^(?:python\d*(?:\.\d+)*|pypy\d*(?:\.\d+)*|perl\d*(?:\.\d+)*|ruby\d*(?:\.\d+)*|php\d*(?:\.\d+)*|lua\d*(?:\.\d+)*|node\d*|gawk\d*|mawk\d*|nawk\d*|awk\d*|bash\d*|zsh\d*|ksh\d*|dash|ash|fish|tclsh\d*(?:\.\d+)*|wish\d*(?:\.\d+)*)$/;

const WINDOWS_EXECUTABLE_EXT_REGEX = /\.(?:exe|cmd|bat|com|msi|ps1|vbs|vbe|js|jse|wsf|wsh|scr|pif)$/;

// Commands whose inherent capability is code execution, shell interpretation,
// environment/secret disclosure, command wrapping, archive extraction,
// filesystem mutation, or working-directory mutation. Even if present in a
// legacy security.json allow-list, these always require explicit per-call
// approval (unless the user explicitly configured "*").
const ALWAYS_REQUIRE_APPROVAL_COMMANDS = new Set([
  // Shells, precommand modifiers, control-flow keywords, and shell builtins
  "sh",
  "bash",
  "zsh",
  "dash",
  "ksh",
  "fish",
  "csh",
  "tcsh",
  "ash",
  "cmd",
  "powershell",
  "pwsh",
  "wsl",
  "eval",
  "exec",
  "source",
  ".",
  "builtin",
  "command",
  "alias",
  "unalias",
  "trap",
  "export",
  "set",
  "unset",
  "declare",
  "typeset",
  "local",
  "readonly",
  "fc",
  "history",
  "compgen",
  "complete",
  "enable",
  "bind",
  "read",
  "mapfile",
  "readarray",
  "hash",
  "shopt",
  "setopt",
  "unsetopt",
  "zmodload",
  "autoload",
  "emulate",
  "repeat",
  "foreach",
  "coproc",
  "!",
  "noglob",
  "nocorrect",
  "-",
  "if",
  "then",
  "elif",
  "else",
  "fi",
  "while",
  "until",
  "for",
  "do",
  "done",
  "case",
  "esac",
  "select",
  "[[",
  "]]",
  "function",
  SHELL_FUNCTION_DEFINITION_COMMAND,
  // Working-directory changers (invalidate relative path checks for chained commands)
  "cd",
  "pushd",
  "popd",
  // Interpreters / script runners / query & search tools with exec or file-write capability
  "awk",
  "gawk",
  "mawk",
  "nawk",
  "sed",
  "gsed",
  "perl",
  "python",
  "python2",
  "python3",
  "pythonw",
  "py",
  "ruby",
  "node",
  "deno",
  "bun",
  "bunx",
  "npx",
  "pnpx",
  "npm",
  "pnpm",
  "yarn",
  "pip",
  "pip3",
  "uv",
  "go",
  "cargo",
  "make",
  "tsx",
  "ts-node",
  "php",
  "lua",
  "osascript",
  "swift",
  "tclsh",
  "wish",
  "rscript",
  "julia",
  "expect",
  "sqlite3",
  "busybox",
  "find",
  "jq",
  "yq",
  "tar",
  "unzip",
  "less",
  "more",
  // Filesystem mutators & scheduled execution
  "rm",
  "mv",
  "cp",
  "chmod",
  "chown",
  "ln",
  "tee",
  "dd",
  "install",
  "crontab",
  // Environment dumpers, keychain/clipboard/launcher tools, network tools, and command wrappers
  "env",
  "printenv",
  "envsubst",
  "xargs",
  "sudo",
  "su",
  "doas",
  "nohup",
  "nice",
  "renice",
  "timeout",
  "stdbuf",
  "time",
  "watch",
  "arch",
  "caffeinate",
  "script",
  "setsid",
  "ionice",
  "chrt",
  "taskset",
  "flock",
  "sandbox-exec",
  "rlwrap",
  "strace",
  "ltrace",
  "gdb",
  "lldb",
  "docker",
  "podman",
  "chroot",
  "nsenter",
  "unshare",
  "bwrap",
  "ssh-agent",
  "launchctl",
  "systemctl",
  "systemd-run",
  "open",
  "xdg-open",
  "security",
  "pbpaste",
  "pbcopy",
  "curl",
  "wget",
  "ssh",
  "scp",
  "sftp",
  "rsync",
  "nc",
  "ncat",
  "socat",
  // Windows execution / builtins / LOLBin utilities
  "call",
  "setlocal",
  "endlocal",
  "goto",
  "mklink",
  "del",
  "erase",
  "rd",
  "rmdir",
  "copy",
  "xcopy",
  "robocopy",
  "move",
  "ren",
  "rename",
  "icacls",
  "takeown",
  "attrib",
  "wscript",
  "cscript",
  "mshta",
  "rundll32",
  "regsvr32",
  "certutil",
  "bitsadmin",
  "msiexec",
  "wmic",
  "schtasks",
  "sc",
  "reg",
  "net",
  "net1",
  "forfiles",
  "pcalua",
  "start",
  "xxd",
]);

type GitSubcommandFlagSpec = {
  readonly boolFlags: ReadonlySet<string>;
  readonly valueFlags: ReadonlySet<string>;
  readonly optionalEqFlags?: ReadonlySet<string>;
  readonly allowNumericShortFlag?: boolean;
};

const GIT_SAFE_FLAGS_BY_SUBCOMMAND: Readonly<Record<string, GitSubcommandFlagSpec>> = {
  status: {
    boolFlags: new Set([
      "-s",
      "--short",
      "-b",
      "--branch",
      "--show-stash",
      "--porcelain",
      "--long",
      "-v",
      "--verbose",
      "-z",
      "--ahead-behind",
      "--no-ahead-behind",
      "--renames",
      "--no-renames",
      "--ignored",
      "--untracked-files",
      "-u",
    ]),
    valueFlags: new Set([]),
    optionalEqFlags: new Set(["--porcelain", "--untracked-files", "--ignored"]),
  },
  log: {
    boolFlags: new Set([
      "--oneline",
      "--stat",
      "--numstat",
      "--shortstat",
      "--name-only",
      "--name-status",
      "--summary",
      "--graph",
      "--decorate",
      "--no-decorate",
      "--all",
      "--branches",
      "--tags",
      "--remotes",
      "--no-merges",
      "--merges",
      "--first-parent",
      "--reverse",
      "--follow",
      "-p",
      "--patch",
      "--no-patch",
      "-s",
      "--abbrev-commit",
      "--no-abbrev-commit",
      "--color",
      "--no-color",
      "--no-ext-diff",
      "--no-textconv",
      "--full-history",
      "--simplify-by-decoration",
    ]),
    valueFlags: new Set([
      "-n",
      "--max-count",
      "--skip",
      "--since",
      "--after",
      "--until",
      "--before",
      "--author",
      "--committer",
      "--grep",
      "-S",
      "-G",
      "--date",
      "--diff-filter",
    ]),
    optionalEqFlags: new Set(["--decorate", "--color", "--pretty", "--format"]),
    allowNumericShortFlag: true,
  },
  diff: {
    boolFlags: new Set([
      "--cached",
      "--staged",
      "--stat",
      "--numstat",
      "--shortstat",
      "--compact-summary",
      "--name-only",
      "--name-status",
      "--summary",
      "--raw",
      "-p",
      "--patch",
      "-u",
      "-U",
      "-w",
      "--ignore-all-space",
      "-b",
      "--ignore-space-change",
      "--ignore-space-at-eol",
      "--ignore-blank-lines",
      "--color",
      "--no-color",
      "--word-diff",
      "--check",
      "--no-ext-diff",
      "--no-textconv",
      "--minimal",
      "--patience",
      "--histogram",
      "-M",
      "--find-renames",
      "-C",
      "--find-copies",
      "--relative",
      "--quiet",
      "--exit-code",
    ]),
    valueFlags: new Set([
      "--diff-filter",
      "-S",
      "-G",
      "--src-prefix",
      "--dst-prefix",
    ]),
    optionalEqFlags: new Set([
      "--color",
      "--word-diff",
      "--find-renames",
      "--find-copies",
      "--relative",
      "--unified",
    ]),
  },
  show: {
    boolFlags: new Set([
      "--stat",
      "--numstat",
      "--shortstat",
      "--name-only",
      "--name-status",
      "--summary",
      "--oneline",
      "--no-patch",
      "-s",
      "-p",
      "--patch",
      "-U",
      "--no-ext-diff",
      "--no-textconv",
      "--color",
      "--no-color",
      "--abbrev-commit",
    ]),
    valueFlags: new Set(["--date"]),
    optionalEqFlags: new Set(["--color", "--pretty", "--format", "--unified"]),
  },
  "rev-parse": {
    boolFlags: new Set([
      "--abbrev-ref",
      "--short",
      "--show-toplevel",
      "--is-inside-work-tree",
      "--git-dir",
      "--show-prefix",
      "--verify",
      "--symbolic-full-name",
      "--quiet",
      "-q",
    ]),
    valueFlags: new Set([]),
    optionalEqFlags: new Set(["--abbrev-ref", "--short"]),
  },
  describe: {
    boolFlags: new Set([
      "--tags",
      "--always",
      "--long",
      "--dirty",
      "--exact-match",
      "--all",
      "--first-parent",
    ]),
    valueFlags: new Set(["--candidates", "--match", "--exclude"]),
    optionalEqFlags: new Set(["--abbrev", "--dirty"]),
  },
  "ls-files": {
    boolFlags: new Set([
      "-c",
      "--cached",
      "-d",
      "--deleted",
      "-m",
      "--modified",
      "-o",
      "--others",
      "-i",
      "--ignored",
      "-s",
      "--stage",
      "-u",
      "--unmerged",
      "-z",
      "--exclude-standard",
      "--full-name",
      "--error-unmatch",
    ]),
    valueFlags: new Set([]),
  },
  shortlog: {
    boolFlags: new Set([
      "-s",
      "--summary",
      "-n",
      "--numbered",
      "-e",
      "--email",
      "--all",
      "--no-merges",
      "--merges",
    ]),
    valueFlags: new Set(["--since", "--after", "--until", "--before"]),
    optionalEqFlags: new Set(["--format"]),
  },
  blame: {
    boolFlags: new Set([
      "-n",
      "--show-number",
      "-e",
      "--show-email",
      "-w",
      "-s",
      "-l",
      "-t",
      "-c",
      "--porcelain",
      "--line-porcelain",
      "--incremental",
      "-M",
      "-C",
    ]),
    valueFlags: new Set(["-L", "--date"]),
  },
};

const GIT_READ_ONLY_SUBCOMMANDS = new Set(Object.keys(GIT_SAFE_FLAGS_BY_SUBCOMMAND));

const AGENT_SLACK_READ_ONLY_SUBCOMMANDS = new Set([
  "message:list",
  "message:get",
  "channel:list",
  "channel:get",
  "channel:info",
  "channel:history",
  "search:messages",
  "search:files",
  "search:all",
  "user:list",
  "user:get",
  "user:info",
  "canvas:get",
  "canvas:read",
  "workspace:list",
]);

const FILE_READING_COMMANDS = new Set([
  "cat",
  "head",
  "tail",
  "grep",
  "egrep",
  "fgrep",
  "rg",
  "cut",
  "diff",
  "du",
  "file",
  "find",
  "ls",
  "readlink",
  "realpath",
  "sort",
  "stat",
  "tree",
  "uniq",
  "wc",
  "jq",
  "yq",
  "date",
  "df",
  // Additional Unix/Windows file readers (enforced if user manually allow-lists them)
  "nl",
  "od",
  "xxd",
  "hexdump",
  "strings",
  "base64",
  "cksum",
  "md5",
  "md5sum",
  "sha1sum",
  "sha256sum",
  "shasum",
  "fold",
  "fmt",
  "column",
  "paste",
  "join",
  "comm",
  "cmp",
  "less",
  "more",
  "type",
  "dir",
  "findstr",
]);

type SafeFlagSpec = {
  readonly shortBoolFlags: ReadonlySet<string>;
  readonly shortValueFlags: ReadonlySet<string>;
  readonly shortFileValueFlags?: ReadonlySet<string>;
  readonly longBoolFlags: ReadonlySet<string>;
  readonly longValueFlags: ReadonlySet<string>;
  readonly longFileValueFlags?: ReadonlySet<string>;
  readonly longOptionalEqFlags?: ReadonlySet<string>;
  readonly recursiveShortFlags?: ReadonlySet<string>;
  readonly recursiveLongFlags?: ReadonlySet<string>;
  readonly allowNumericShortFlag?: boolean;
};

const EMPTY_SET: ReadonlySet<string> = new Set();

function makeSafeFlagSpec(spec: Partial<SafeFlagSpec>): SafeFlagSpec {
  return {
    shortBoolFlags: spec.shortBoolFlags ?? EMPTY_SET,
    shortValueFlags: spec.shortValueFlags ?? EMPTY_SET,
    shortFileValueFlags: spec.shortFileValueFlags,
    longBoolFlags: spec.longBoolFlags ?? EMPTY_SET,
    longValueFlags: spec.longValueFlags ?? EMPTY_SET,
    longFileValueFlags: spec.longFileValueFlags,
    longOptionalEqFlags: spec.longOptionalEqFlags,
    recursiveShortFlags: spec.recursiveShortFlags,
    recursiveLongFlags: spec.recursiveLongFlags,
    allowNumericShortFlag: spec.allowNumericShortFlag,
  };
}

const GREP_SAFE_SPEC = makeSafeFlagSpec({
  shortBoolFlags: new Set([
    "E",
    "F",
    "G",
    "P",
    "i",
    "v",
    "w",
    "x",
    "c",
    "L",
    "l",
    "o",
    "q",
    "s",
    "b",
    "H",
    "h",
    "n",
    "T",
    "u",
    "Z",
    "a",
    "I",
    "r",
    "z",
  ]),
  shortValueFlags: new Set(["e", "m", "A", "B", "C"]),
  shortFileValueFlags: new Set(["f"]),
  longBoolFlags: new Set([
    "--extended-regexp",
    "--fixed-strings",
    "--basic-regexp",
    "--perl-regexp",
    "--ignore-case",
    "--no-ignore-case",
    "--invert-match",
    "--word-regexp",
    "--line-regexp",
    "--count",
    "--files-without-match",
    "--files-with-matches",
    "--only-matching",
    "--quiet",
    "--silent",
    "--no-messages",
    "--byte-offset",
    "--with-filename",
    "--no-filename",
    "--line-number",
    "--initial-tab",
    "--null",
    "--text",
    "--recursive",
    "--null-data",
    "--help",
    "--version",
  ]),
  longValueFlags: new Set([
    "--regexp",
    "--max-count",
    "--after-context",
    "--before-context",
    "--context",
    "--include",
    "--exclude",
    "--exclude-dir",
    "--label",
    "--binary-files",
  ]),
  longFileValueFlags: new Set(["--file", "--exclude-from"]),
  longOptionalEqFlags: new Set(["--color", "--colour"]),
  recursiveShortFlags: new Set(["r"]),
  recursiveLongFlags: new Set(["--recursive"]),
});

// Strict per-command safe flag allowlists for read-only commands.
// Any flag not explicitly allowlisted (including GNU getopt_long abbreviations,
// file-writing options like sort -o / tree -o, symlink-dereferencing flags like
// grep -R / rg --follow / ls -L / du -L / tree -l, or cross-platform ambiguous
// flags like stat -f / ls -T / ls -w) fails closed and requires user approval.
const SAFE_FLAG_SPEC_BY_COMMAND: Readonly<Record<string, SafeFlagSpec>> = {
  cat: makeSafeFlagSpec({
    shortBoolFlags: new Set(["A", "b", "e", "E", "n", "s", "t", "T", "u", "v"]),
    longBoolFlags: new Set([
      "--show-all",
      "--number-nonblank",
      "--show-ends",
      "--number",
      "--squeeze-blank",
      "--show-tabs",
      "--show-nonprinting",
      "--help",
      "--version",
    ]),
  }),
  head: makeSafeFlagSpec({
    shortBoolFlags: new Set(["q", "v", "z"]),
    shortValueFlags: new Set(["n", "c"]),
    longBoolFlags: new Set(["--quiet", "--silent", "--verbose", "--zero-terminated", "--help", "--version"]),
    longValueFlags: new Set(["--lines", "--bytes"]),
    allowNumericShortFlag: true,
  }),
  tail: makeSafeFlagSpec({
    shortBoolFlags: new Set(["q", "v", "z"]),
    shortValueFlags: new Set(["n", "c"]),
    longBoolFlags: new Set(["--quiet", "--silent", "--verbose", "--zero-terminated", "--help", "--version"]),
    longValueFlags: new Set(["--lines", "--bytes"]),
    allowNumericShortFlag: true,
  }),
  cut: makeSafeFlagSpec({
    shortBoolFlags: new Set(["n", "s", "z"]),
    shortValueFlags: new Set(["b", "c", "d", "f"]),
    longBoolFlags: new Set(["--complement", "--only-delimited", "--zero-terminated", "--help", "--version"]),
    longValueFlags: new Set(["--bytes", "--characters", "--delimiter", "--fields", "--output-delimiter"]),
  }),
  sort: makeSafeFlagSpec({
    shortBoolFlags: new Set(["b", "d", "f", "g", "i", "M", "h", "n", "R", "r", "V", "c", "C", "m", "s", "u", "z"]),
    shortValueFlags: new Set(["k", "t", "S"]),
    longBoolFlags: new Set([
      "--ignore-leading-blanks",
      "--dictionary-order",
      "--ignore-case",
      "--general-numeric-sort",
      "--human-numeric-sort",
      "--ignore-nonprinting",
      "--month-sort",
      "--numeric-sort",
      "--random-sort",
      "--reverse",
      "--version-sort",
      "--check",
      "--merge",
      "--stable",
      "--unique",
      "--zero-terminated",
      "--help",
      "--version",
    ]),
    longValueFlags: new Set(["--key", "--field-separator", "--buffer-size", "--batch-size", "--parallel"]),
  }),
  uniq: makeSafeFlagSpec({
    shortBoolFlags: new Set(["c", "d", "D", "i", "u", "z"]),
    shortValueFlags: new Set(["f", "s", "w"]),
    longBoolFlags: new Set([
      "--count",
      "--repeated",
      "--all-repeated",
      "--ignore-case",
      "--unique",
      "--zero-terminated",
      "--help",
      "--version",
    ]),
    longValueFlags: new Set(["--skip-fields", "--skip-chars", "--check-chars"]),
  }),
  wc: makeSafeFlagSpec({
    shortBoolFlags: new Set(["c", "m", "l", "L", "w"]),
    longBoolFlags: new Set(["--bytes", "--chars", "--lines", "--max-line-length", "--words", "--help", "--version"]),
  }),
  grep: GREP_SAFE_SPEC,
  egrep: GREP_SAFE_SPEC,
  fgrep: GREP_SAFE_SPEC,
  rg: makeSafeFlagSpec({
    shortBoolFlags: new Set(["i", "s", "S", "v", "w", "F", "c", "l", "n", "N", "H", "I", "o", "q", "u", "a", "P", "U", "z"]),
    shortValueFlags: new Set(["e", "m", "A", "B", "C", "g", "t", "T", "d", "M"]),
    shortFileValueFlags: new Set(["f"]),
    longBoolFlags: new Set([
      "--ignore-case",
      "--case-sensitive",
      "--smart-case",
      "--invert-match",
      "--word-regexp",
      "--fixed-strings",
      "--count",
      "--count-matches",
      "--files-with-matches",
      "--files-without-match",
      "--files",
      "--line-number",
      "--no-line-number",
      "--with-filename",
      "--no-filename",
      "--only-matching",
      "--quiet",
      "--hidden",
      "--no-ignore",
      "--multiline",
      "--json",
      "--vimgrep",
      "--help",
      "--version",
    ]),
    longValueFlags: new Set([
      "--regexp",
      "--max-count",
      "--after-context",
      "--before-context",
      "--context",
      "--glob",
      "--iglob",
      "--type",
      "--type-not",
      "--max-depth",
      "--max-columns",
      "--sort",
      "--sortr",
      "--color",
    ]),
    longFileValueFlags: new Set(["--file", "--ignore-file"]),
  }),
  ls: makeSafeFlagSpec({
    shortBoolFlags: new Set([
      "a",
      "A",
      "b",
      "B",
      "c",
      "C",
      "d",
      "f",
      "F",
      "g",
      "G",
      "h",
      "H",
      "i",
      "k",
      "l",
      "m",
      "n",
      "o",
      "p",
      "q",
      "Q",
      "r",
      "R",
      "s",
      "S",
      "t",
      "u",
      "U",
      "v",
      "x",
      "X",
      "1",
      "@",
    ]),
    longBoolFlags: new Set([
      "--all",
      "--almost-all",
      "--directory",
      "--classify",
      "--human-readable",
      "--inode",
      "--numeric-uid-gid",
      "--reverse",
      "--recursive",
      "--size",
      "--full-time",
      "--group-directories-first",
      "--help",
      "--version",
    ]),
    longValueFlags: new Set(["--ignore", "--tabsize", "--width", "--sort", "--time", "--time-style", "--format", "--quoting-style"]),
    longOptionalEqFlags: new Set(["--color", "--hyperlink", "--classify"]),
    recursiveShortFlags: new Set(["R"]),
    recursiveLongFlags: new Set(["--recursive"]),
  }),
  diff: makeSafeFlagSpec({
    shortBoolFlags: new Set(["a", "b", "B", "c", "d", "E", "i", "l", "N", "p", "q", "r", "s", "t", "T", "u", "w", "y", "Z"]),
    shortValueFlags: new Set(["U", "C", "I", "L", "S", "W", "x"]),
    shortFileValueFlags: new Set(["X"]),
    longBoolFlags: new Set([
      "--text",
      "--ignore-space-change",
      "--ignore-blank-lines",
      "--ignore-case",
      "--minimal",
      "--new-file",
      "--brief",
      "--recursive",
      "--report-identical-files",
      "--expand-tabs",
      "--initial-tab",
      "--ignore-all-space",
      "--side-by-side",
      "--suppress-common-lines",
      "--help",
      "--version",
    ]),
    longValueFlags: new Set(["--label", "--exclude", "--width", "--starting-file"]),
    longFileValueFlags: new Set(["--exclude-from"]),
    longOptionalEqFlags: new Set(["--unified", "--context", "--color"]),
    recursiveShortFlags: new Set(["r"]),
    recursiveLongFlags: new Set(["--recursive"]),
  }),
  du: makeSafeFlagSpec({
    shortBoolFlags: new Set(["a", "b", "c", "g", "h", "H", "k", "m", "P", "s", "S", "x", "0"]),
    shortValueFlags: new Set(["d", "B", "t"]),
    shortFileValueFlags: new Set(["X"]),
    longBoolFlags: new Set([
      "--all",
      "--apparent-size",
      "--bytes",
      "--total",
      "--human-readable",
      "--si",
      "--no-dereference",
      "--summarize",
      "--separate-dirs",
      "--one-file-system",
      "--null",
      "--help",
      "--version",
    ]),
    longValueFlags: new Set(["--max-depth", "--block-size", "--threshold", "--exclude", "--time-style"]),
    longFileValueFlags: new Set(["--exclude-from"]),
  }),
  tree: makeSafeFlagSpec({
    shortBoolFlags: new Set(["a", "d", "f", "x", "i", "p", "u", "g", "s", "h", "D", "F", "q", "N", "Q", "v", "r", "t", "c", "U", "C", "n", "J"]),
    shortValueFlags: new Set(["L", "P", "I"]),
    longBoolFlags: new Set(["--dirsfirst", "--noreport", "--prune", "--matchdirs", "--gitignore", "--du", "--help", "--version"]),
    longValueFlags: new Set(["--charset", "--timefmt", "--sort", "--filelimit"]),
  }),
  stat: makeSafeFlagSpec({
    shortBoolFlags: new Set(["L", "t", "x"]),
    shortValueFlags: new Set(["c"]),
    longBoolFlags: new Set(["--dereference", "--terse", "--help", "--version"]),
    longValueFlags: new Set(["--format", "--printf"]),
  }),
  file: makeSafeFlagSpec({
    shortBoolFlags: new Set(["b", "E", "h", "i", "I", "k", "L", "n", "N", "p", "r", "s", "v", "z", "Z", "0"]),
    shortValueFlags: new Set(["e", "F", "P"]),
    longBoolFlags: new Set([
      "--brief",
      "--mime",
      "--mime-type",
      "--mime-encoding",
      "--dereference",
      "--no-dereference",
      "--keep-going",
      "--preserve-date",
      "--raw",
      "--uncompress",
      "--help",
      "--version",
    ]),
    longValueFlags: new Set(["--exclude", "--separator", "--parameter"]),
  }),
  date: makeSafeFlagSpec({
    shortBoolFlags: new Set(["u", "R"]),
    shortValueFlags: new Set(["d"]),
    shortFileValueFlags: new Set(["r"]),
    longBoolFlags: new Set(["--utc", "--universal", "--rfc-email", "--rfc-2822", "--help", "--version"]),
    longValueFlags: new Set(["--date"]),
    longFileValueFlags: new Set(["--reference"]),
    longOptionalEqFlags: new Set(["--iso-8601", "--rfc-3339"]),
  }),
  df: makeSafeFlagSpec({
    shortBoolFlags: new Set(["a", "g", "h", "H", "i", "k", "l", "m", "P", "T"]),
    shortValueFlags: new Set(["B", "t", "x"]),
    longBoolFlags: new Set([
      "--all",
      "--human-readable",
      "--si",
      "--inodes",
      "--local",
      "--portability",
      "--print-type",
      "--total",
      "--help",
      "--version",
    ]),
    longValueFlags: new Set(["--block-size", "--type", "--exclude-type"]),
    longOptionalEqFlags: new Set(["--output"]),
  }),
  readlink: makeSafeFlagSpec({
    shortBoolFlags: new Set(["f", "e", "m", "n", "q", "s", "v", "z"]),
    longBoolFlags: new Set([
      "--canonicalize",
      "--canonicalize-existing",
      "--canonicalize-missing",
      "--no-newline",
      "--quiet",
      "--silent",
      "--verbose",
      "--zero",
      "--help",
      "--version",
    ]),
  }),
  realpath: makeSafeFlagSpec({
    shortBoolFlags: new Set(["e", "m", "L", "P", "q", "s", "z"]),
    longBoolFlags: new Set([
      "--canonicalize-existing",
      "--canonicalize-missing",
      "--logical",
      "--physical",
      "--quiet",
      "--no-symlinks",
      "--zero",
      "--help",
      "--version",
    ]),
    longFileValueFlags: new Set(["--relative-to", "--relative-base"]),
  }),
  echo: makeSafeFlagSpec({
    shortBoolFlags: new Set(["n", "e", "E"]),
  }),
  printf: makeSafeFlagSpec({}),
  pwd: makeSafeFlagSpec({
    shortBoolFlags: new Set(["L", "P"]),
    longBoolFlags: new Set(["--logical", "--physical", "--help", "--version"]),
  }),
  uname: makeSafeFlagSpec({
    shortBoolFlags: new Set(["a", "s", "n", "r", "v", "m", "p", "i", "o"]),
    longBoolFlags: new Set([
      "--all",
      "--kernel-name",
      "--nodename",
      "--kernel-release",
      "--kernel-version",
      "--machine",
      "--processor",
      "--hardware-platform",
      "--operating-system",
      "--help",
      "--version",
    ]),
  }),
  hostname: makeSafeFlagSpec({
    shortBoolFlags: new Set(["s", "f", "i", "I", "d"]),
    longBoolFlags: new Set(["--short", "--fqdn", "--long", "--ip-address", "--all-ip-addresses", "--domain", "--help", "--version"]),
  }),
  whoami: makeSafeFlagSpec({
    longBoolFlags: new Set(["--help", "--version"]),
  }),
  which: makeSafeFlagSpec({
    shortBoolFlags: new Set(["a", "s"]),
    longBoolFlags: new Set(["--all", "--help", "--version"]),
  }),
  basename: makeSafeFlagSpec({
    shortBoolFlags: new Set(["a", "z"]),
    shortValueFlags: new Set(["s"]),
    longBoolFlags: new Set(["--multiple", "--zero", "--help", "--version"]),
    longValueFlags: new Set(["--suffix"]),
  }),
  dirname: makeSafeFlagSpec({
    shortBoolFlags: new Set(["z"]),
    longBoolFlags: new Set(["--zero", "--help", "--version"]),
  }),
};

type Quote = "'" | '"' | null;

type ShellToken = {
  readonly raw: string;
  readonly value: string;
  readonly hasUnquotedGlob: boolean;
};

type ShellSyntaxInspection = {
  readonly reasons: readonly string[];
  readonly inputRedirectTokens: readonly ShellToken[];
};

export type CommandSecurityEvaluation = {
  readonly blocked: boolean;
  readonly commandNames: string[];
  readonly blockedCommands: string[];
  readonly capabilityReasons: string[];
  readonly allowScopeGrant: boolean;
};

function normalizeCommandBaseName(commandName: string): string {
  const normalized = commandName.trim().toLowerCase();
  if (!normalized) return "";
  const base = path.posix.basename(normalized.replace(/\\/g, "/"));
  const withoutAdsAndDots = base.replace(/:.*$/, "").replace(/[.\s]+$/, "");
  return withoutAdsAndDots.replace(WINDOWS_EXECUTABLE_EXT_REGEX, "").replace(/[.\s]+$/, "");
}

export function isAlwaysRequireApprovalCommand(commandName: string): boolean {
  const normalized = commandName.trim().toLowerCase();
  if (!normalized) return false;
  const baseName = normalizeCommandBaseName(normalized);
  return (
    ALWAYS_REQUIRE_APPROVAL_COMMANDS.has(normalized) ||
    ALWAYS_REQUIRE_APPROVAL_COMMANDS.has(baseName) ||
    VERSIONED_INTERPRETER_REGEX.test(baseName)
  );
}

function isWordBoundaryBefore(input: string, index: number): boolean {
  if (index === 0) return true;
  const prev = input[index - 1];
  return (
    prev === " " ||
    prev === "\t" ||
    prev === "\n" ||
    prev === "\r" ||
    prev === ";" ||
    prev === "|" ||
    prev === "&" ||
    prev === "(" ||
    prev === ")" ||
    prev === "<" ||
    prev === ">"
  );
}

function isAmpersandSeparator(command: string, index: number): boolean {
  const previous = command[index - 1];
  const next = command[index + 1];
  return previous !== "<" && previous !== ">" && next !== ">" && next !== "&";
}

function isCommandGroupStart(command: string, index: number): boolean {
  const before = command.slice(0, index).trimEnd();
  if (!before) return true;

  const previous = before[before.length - 1];
  return (
    previous === ";" ||
    previous === "|" ||
    previous === "&" ||
    previous === "(" ||
    previous === "\n" ||
    previous === "\r"
  );
}

function splitCommandSegments(command: string): string[] {
  const segments: string[] = [];
  const quoteStack: Quote[] = [];
  let current = "";
  let quote: Quote = null;
  let escaped = false;
  let parenDepth = 0;
  let inBacktick = false;
  let backtickOuterQuote: Quote = null;

  const push = () => {
    if (current.trim()) {
      segments.push(current);
    }
    current = "";
  };

  for (let index = 0; index < command.length; index++) {
    const char = command[index];
    const next = command[index + 1];

    if (escaped) {
      current += char;
      escaped = false;
      continue;
    }

    if (char === "\\" && quote !== "'") {
      current += char;
      escaped = true;
      continue;
    }

    if (char === "'" && quote !== '"') {
      quote = quote === "'" ? null : "'";
      current += char;
      continue;
    }

    if (char === '"' && quote !== "'") {
      quote = quote === '"' ? null : '"';
      current += char;
      continue;
    }

    // POSIX shell comments start at unquoted `#` at a word boundary and run to EOL
    if (quote === null && char === "#" && isWordBoundaryBefore(command, index)) {
      push();
      while (index < command.length && command[index] !== "\n" && command[index] !== "\r") {
        index++;
      }
      continue;
    }

    if (
      quote !== "'" &&
      ((char === "$" && next === "(") || ((char === "<" || char === ">") && next === "("))
    ) {
      push();
      quoteStack.push(quote);
      quote = null;
      parenDepth++;
      index++;
      continue;
    }

    if (quote !== "'" && char === "`") {
      push();
      if (inBacktick) {
        quote = backtickOuterQuote;
        backtickOuterQuote = null;
        inBacktick = false;
      } else {
        backtickOuterQuote = quote;
        quote = null;
        inBacktick = true;
      }
      continue;
    }

    if (quote === null) {
      if (char === "&" && next === "&") {
        push();
        index++;
        continue;
      }
      if (char === "|" && next === "|") {
        push();
        index++;
        continue;
      }
      if (char === ";" || char === "|" || char === "\n" || char === "\r") {
        push();
        continue;
      }
      if (char === "&" && isAmpersandSeparator(command, index)) {
        push();
        continue;
      }
      if (char === "(" && isCommandGroupStart(command, index)) {
        push();
        quoteStack.push(null);
        parenDepth++;
        continue;
      }
      if (char === ")" && parenDepth > 0) {
        push();
        parenDepth--;
        quote = quoteStack.pop() ?? null;
        continue;
      }
    }

    current += char;
  }

  push();
  return segments;
}

function sanitizeToken(token: string): string {
  return token.trim();
}

function isShellFunctionDefinition(segment: string): boolean {
  return SHELL_FUNCTION_DEFINITION_REGEX.test(segment.trim());
}

function readWordFrom(
  input: string,
  startIndex: number,
): { token: ShellToken | null; nextIndex: number } {
  let index = startIndex;
  while (index < input.length && (input[index] === " " || input[index] === "\t")) {
    index++;
  }
  if (index >= input.length) {
    return { token: null, nextIndex: index };
  }

  let raw = "";
  let value = "";
  let quote: Quote = null;
  let escaped = false;
  let hasUnquotedGlob = false;

  while (index < input.length) {
    const char = input[index];
    if (escaped) {
      raw += char;
      if (
        quote === '"' &&
        char !== '"' &&
        char !== "\\" &&
        char !== "$" &&
        char !== "`" &&
        char !== "\n"
      ) {
        value += `\\${char}`;
      } else {
        value += char;
      }
      escaped = false;
      index++;
      continue;
    }
    if (char === "\\" && quote !== "'") {
      raw += char;
      escaped = true;
      index++;
      continue;
    }
    if (char === "'" && quote !== '"') {
      quote = quote === "'" ? null : "'";
      raw += char;
      index++;
      continue;
    }
    if (char === '"' && quote !== "'") {
      quote = quote === '"' ? null : '"';
      raw += char;
      index++;
      continue;
    }
    if (
      quote === null &&
      (char === " " ||
        char === "\t" ||
        char === "\n" ||
        char === "\r" ||
        char === ";" ||
        char === "|" ||
        char === "&" ||
        char === "<" ||
        char === ">" ||
        char === "(" ||
        char === ")")
    ) {
      break;
    }
    if (quote === null && (char === "*" || char === "?" || char === "[")) {
      hasUnquotedGlob = true;
    }
    raw += char;
    value += char;
    index++;
  }

  return {
    token: raw.length > 0 ? { raw, value, hasUnquotedGlob } : null,
    nextIndex: index,
  };
}

function inspectWindowsCmdSyntax(command: string): ShellSyntaxInspection {
  const reasons = new Set<string>();
  let inDoubleQuote = false;

  if (command.trimStart().startsWith("@")) {
    reasons.add("Command uses cmd.exe @ command prefix");
  }

  for (let index = 0; index < command.length; index++) {
    const char = command[index];
    const next = command[index + 1];
    const code = char.charCodeAt(0);

    if (char === "\0") {
      reasons.add("Command contains a null byte");
      continue;
    }

    if (char === "\n" || char === "\r") {
      reasons.add("Command contains multiple lines");
      continue;
    }

    if (code < 0x20 && char !== "\t") {
      reasons.add("Command contains control characters ambiguous under cmd.exe");
      continue;
    }

    // cmd.exe expands %VAR% and !VAR! even inside double quotes
    if (char === "%" || char === "!") {
      reasons.add("Command uses Windows environment variable expansion");
      continue;
    }

    if (char === '"') {
      inDoubleQuote = !inDoubleQuote;
      continue;
    }

    if (inDoubleQuote) {
      // cmd.exe does not treat backslash as an escape inside double quotes,
      // and .cmd/.bat shims re-interpret shell metacharacters inside quoted args.
      if (char === "\\" && next === '"') {
        reasons.add("Command contains escaped double quote ambiguous under cmd.exe");
      }
      if (
        char === "&" ||
        char === "|" ||
        char === "<" ||
        char === ">" ||
        char === "^" ||
        char === "(" ||
        char === ")" ||
        char === "`" ||
        char === "$"
      ) {
        reasons.add("Command contains shell metacharacters inside quotes under cmd.exe");
      }
      continue;
    }

    // Outside double quotes in cmd.exe, single quotes do NOT quote metacharacters
    if (char === "'") {
      reasons.add("Command uses single quotes which are not quoting delimiters in cmd.exe");
      continue;
    }
    if (char === "^") {
      reasons.add("Command uses cmd.exe caret escape syntax");
      continue;
    }
    if (char === "&" || char === "|") {
      reasons.add("Command chains or pipes commands under cmd.exe");
      continue;
    }
    if (char === "<" || char === ">") {
      reasons.add("Command redirects input or output under cmd.exe");
      continue;
    }
    if (char === "(" || char === ")") {
      reasons.add("Command uses parenthesized grouping under cmd.exe");
      continue;
    }
    if (char === "`" || char === "$") {
      reasons.add("Command uses shell substitution syntax");
      continue;
    }
    if (char === "," || char === ";" || char === "=") {
      reasons.add("Command uses cmd.exe token delimiter (comma, semicolon, or equals)");
      continue;
    }
  }

  if (inDoubleQuote) {
    reasons.add("Command contains unbalanced quotes");
  }

  const firstTokens = tokenizeWindowsCmdSegment(command);
  if (firstTokens.length > 0) {
    const firstCmd = firstTokens[0].value.replace(/^@+/, "");
    if (firstCmd.endsWith(".")) {
      reasons.add("Command name has trailing dot ambiguous under Windows");
    }
    const afterDrive = /^[A-Za-z]:[\\/]/.test(firstCmd) ? firstCmd.slice(2) : firstCmd;
    if (afterDrive.includes(":")) {
      reasons.add("Command name contains NTFS stream or drive-relative colon syntax");
    }
  }

  return {
    reasons: Array.from(reasons),
    inputRedirectTokens: [],
  };
}

function tokenizeWindowsCmdSegment(command: string): ShellToken[] {
  const tokens: ShellToken[] = [];
  let index = 0;

  while (index < command.length) {
    while (
      index < command.length &&
      (command[index] === " " ||
        command[index] === "\t" ||
        command[index] === "\v" ||
        command[index] === "\f")
    ) {
      index++;
    }
    if (index >= command.length) break;

    let raw = "";
    let value = "";
    let inDoubleQuote = false;
    let hasUnquotedGlob = false;

    while (index < command.length) {
      const char = command[index];
      if (char === '"') {
        inDoubleQuote = !inDoubleQuote;
        raw += char;
        index++;
        continue;
      }
      if (
        !inDoubleQuote &&
        (char === " " ||
          char === "\t" ||
          char === "\v" ||
          char === "\f" ||
          char === "\n" ||
          char === "\r")
      ) {
        break;
      }
      // On Windows, utilities (including Git/MSYS2/MinGW ports) expand wildcards
      // and character-class globs even inside double quotes.
      if (char === "*" || char === "?" || char === "[") {
        hasUnquotedGlob = true;
      }
      raw += char;
      value += char;
      index++;
    }

    if (raw.length > 0) {
      tokens.push({ raw, value, hasUnquotedGlob });
    }
  }

  return tokens;
}

function inspectShellSyntax(
  command: string,
  shellDialect: RuntimeShellDialect = "posix-sh",
): ShellSyntaxInspection {
  if (shellDialect === "windows-cmd") {
    return inspectWindowsCmdSyntax(command);
  }

  const reasons = new Set<string>();
  const inputRedirectTokens: ShellToken[] = [];
  let quote: Quote = null;
  let escaped = false;
  let inBacktick = false;
  let backtickOuterQuote: Quote = null;

  for (let index = 0; index < command.length; index++) {
    const char = command[index];
    const next = command[index + 1];

    if (char === "\0") {
      reasons.add("Command contains a null byte");
      continue;
    }

    if (escaped) {
      if (char === "\n" || char === "\r") {
        reasons.add("Command contains unbalanced quotes or line continuation");
      } else if (
        quote === '"' &&
        char !== '"' &&
        char !== "\\" &&
        char !== "$" &&
        char !== "`"
      ) {
        reasons.add("Command contains non-special backslash escape inside double quotes");
      }
      escaped = false;
      continue;
    }

    if (char === "\\" && quote !== "'") {
      escaped = true;
      continue;
    }

    if (char === "'" && quote !== '"') {
      quote = quote === "'" ? null : "'";
      continue;
    }

    if (char === '"' && quote !== "'") {
      quote = quote === '"' ? null : '"';
      continue;
    }

    if (quote !== "'") {
      if (char === "$" && next === "(") {
        reasons.add("Command uses command substitution");
        index++;
        continue;
      }
      if (char === "`") {
        reasons.add("Command uses command substitution");
        if (inBacktick) {
          quote = backtickOuterQuote;
          backtickOuterQuote = null;
          inBacktick = false;
        } else {
          backtickOuterQuote = quote;
          quote = null;
          inBacktick = true;
        }
        continue;
      }
      if ((char === "<" || char === ">") && next === "(") {
        reasons.add("Command uses process substitution");
        index++;
        continue;
      }
      if (char === "$") {
        // Covers $VAR, ${VAR}, $((...)), $'...', $"...", $*, $@, $0, etc.
        reasons.add("Command uses shell variable or parameter expansion");
        continue;
      }
    }

    if (quote === null) {
      if (char === "\r") {
        reasons.add("Command contains a carriage return");
        continue;
      }
      // Unquoted `#` at a word boundary starts a POSIX comment — fail closed AND
      // skip to EOL so quotes inside the comment never desync parser state.
      if (char === "#" && isWordBoundaryBefore(command, index)) {
        reasons.add("Command contains a shell comment");
        while (index < command.length && command[index] !== "\n") {
          index++;
        }
        continue;
      }
      // Reject ANY unquoted `(` or `)` to defeat zsh glob qualifiers `*(e:'id':)`,
      // zsh `=(cmd)`, fish `(cmd)`, subshells, and non-brace function definitions.
      if (char === "(" || char === ")") {
        reasons.add("Command uses subshell, glob qualifier, or parenthesized expression");
        continue;
      }
      if (char === "{" || char === "}") {
        reasons.add("Command uses brace expansion or command grouping");
        continue;
      }

      // Redirections:
      // `&>` / `&>>` is bash/zsh-specific and parsed as background `&` + `>` in POSIX `/bin/sh` (`dash`).
      if (char === "&" && next === ">") {
        reasons.add("Command uses non-POSIX output redirection");
        index += command[index + 2] === ">" ? 2 : 1;
        continue;
      }

      if (char === ">") {
        if (next === "&") {
          // Safe fd merge such as >&1, >&2, 2>&1, >&-
          let fdEnd = index + 2;
          while (fdEnd < command.length && /[0-9-]/.test(command[fdEnd])) {
            fdEnd++;
          }
          const fdTarget = command.slice(index + 2, fdEnd);
          const after = command[fdEnd];
          const isDelimiter =
            after === undefined ||
            after === " " ||
            after === "\t" ||
            after === ";" ||
            after === "|" ||
            after === "&" ||
            after === "\n" ||
            after === "\r";
          if (/^(?:[0-9]+|-)$/.test(fdTarget) && isDelimiter) {
            index = fdEnd - 1;
            continue;
          }
          // Otherwise bash/zsh treats >&word as redirecting stdout+stderr to file
          reasons.add("Command redirects output to a file");
          index++;
          continue;
        }
        const opEnd = next === ">" || next === "|" ? index + 2 : index + 1;
        // Peek target word WITHOUT advancing main loop past it so every character
        // inside the target (e.g. `$VAR`, backticks, `\<newline>`, unbalanced quotes)
        // is still scanned by the main loop.
        const { token } = readWordFrom(command, opEnd);
        if (!token || token.raw !== "/dev/null") {
          reasons.add("Command redirects output to a file");
        }
        index = opEnd - 1;
        continue;
      }

      if (char === "<") {
        if (next === "<") {
          reasons.add("Command uses a shell heredoc or here-string");
          index += command[index + 2] === "<" || command[index + 2] === "-" ? 2 : 1;
          continue;
        }
        if (next === ">") {
          reasons.add("Command redirects output to a file");
          index++;
          continue;
        }
        if (next === "&") {
          // Safe fd duplication like <&0, <&-
          let fdEnd = index + 2;
          while (fdEnd < command.length && /[0-9-]/.test(command[fdEnd])) {
            fdEnd++;
          }
          const fdTarget = command.slice(index + 2, fdEnd);
          const after = command[fdEnd];
          const isDelimiter =
            after === undefined ||
            after === " " ||
            after === "\t" ||
            after === ";" ||
            after === "|" ||
            after === "&" ||
            after === "\n" ||
            after === "\r";
          if (/^(?:[0-9]+|-)$/.test(fdTarget) && isDelimiter) {
            index = fdEnd - 1;
            continue;
          }
          reasons.add("Command contains malformed input redirection");
          index++;
          continue;
        }
        // Peek target word WITHOUT skipping it in the main loop so expansions or
        // continuations inside `< ${X}/etc/passwd` are still detected.
        const { token } = readWordFrom(command, index + 1);
        if (token) {
          inputRedirectTokens.push(token);
        } else {
          reasons.add("Command contains malformed input redirection");
        }
        continue;
      }
    }
  }

  if (quote !== null || escaped || inBacktick) {
    reasons.add("Command contains unbalanced quotes or line continuation");
  }

  return {
    reasons: Array.from(reasons),
    inputRedirectTokens,
  };
}

function tokenizeShellSegment(segment: string): ShellToken[] {
  const tokens: ShellToken[] = [];
  let index = 0;

  while (index < segment.length) {
    while (index < segment.length && (segment[index] === " " || segment[index] === "\t")) {
      index++;
    }
    if (index >= segment.length) break;

    // Skip redirection operators and their targets so they are not treated as command args
    const remaining = segment.slice(index);
    const fdRedirMatch = remaining.match(/^(?:[0-9]+)?(&>>|&>|>>|>\||<>|<<<|<<-|<<|>&|<&|>|<)/);
    if (fdRedirMatch) {
      const op = fdRedirMatch[1];
      index += fdRedirMatch[0].length;
      if (op === ">&" || op === "<&") {
        while (index < segment.length && /[0-9-]/.test(segment[index])) {
          index++;
        }
      } else {
        const { nextIndex } = readWordFrom(segment, index);
        index = nextIndex;
      }
      continue;
    }

    const { token, nextIndex } = readWordFrom(segment, index);
    if (token) {
      tokens.push(token);
    }
    if (nextIndex <= index) {
      index++;
    } else {
      index = nextIndex;
    }
  }

  return tokens;
}

function extractWrappedCommands(primaryBaseName: string, args: readonly ShellToken[]): string[] {
  const flagsWithValue: Record<string, Set<string>> = {
    sudo: new Set(["-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-T", "-U"]),
    su: new Set(["-c", "-s", "-g", "-G"]),
    doas: new Set(["-u", "-C"]),
    env: new Set(["-u", "--unset", "-C", "--chdir", "-S", "--split-string"]),
    nice: new Set(["-n", "--adjustment"]),
    timeout: new Set(["-k", "--kill-after", "-s", "--signal"]),
    stdbuf: new Set(["-i", "--input", "-o", "--output", "-e", "--error"]),
    xargs: new Set(["-I", "-L", "-n", "-P", "-d", "-E", "-s", "-a", "--arg-file"]),
    watch: new Set(["-n", "--interval"]),
  };

  const results: string[] = [];
  let currentWrapper = primaryBaseName;
  let currentArgs = args;
  let depth = 0;

  while (WRAPPER_COMMANDS.has(currentWrapper) && currentArgs.length > 0 && depth < 10) {
    depth++;
    const valueFlags = flagsWithValue[currentWrapper] ?? new Set<string>();
    let skipDurationForTimeout = currentWrapper === "timeout";
    let nextIdx = -1;
    let nextCmd: string | null = null;

    for (let i = 0; i < currentArgs.length; i++) {
      const val = currentArgs[i].value;
      if (!val) continue;
      if (val === "--") {
        if (i + 1 < currentArgs.length) {
          nextCmd = sanitizeToken(currentArgs[i + 1].value).toLowerCase() || null;
          nextIdx = i + 2;
        }
        break;
      }
      if (val.startsWith("-")) {
        if (currentWrapper === "env") {
          if ((val === "-S" || val === "--split-string") && i + 1 < currentArgs.length) {
            const innerTokens = currentArgs[i + 1].value.trim().split(/\s+/).filter(Boolean);
            const first = innerTokens.find((t) => !ENV_ASSIGNMENT_REGEX.test(t) && !t.startsWith("-"));
            if (first) {
              nextCmd = sanitizeToken(first).toLowerCase() || null;
            }
            break;
          }
          if (val.startsWith("--split-string=")) {
            const innerTokens = val.slice("--split-string=".length).trim().split(/\s+/).filter(Boolean);
            const first = innerTokens.find((t) => !ENV_ASSIGNMENT_REGEX.test(t) && !t.startsWith("-"));
            if (first) {
              nextCmd = sanitizeToken(first).toLowerCase() || null;
            }
            break;
          }
          if (val.startsWith("-S") && val.length > 2) {
            const innerTokens = val.slice(2).trim().split(/\s+/).filter(Boolean);
            const first = innerTokens.find((t) => !ENV_ASSIGNMENT_REGEX.test(t) && !t.startsWith("-"));
            if (first) {
              nextCmd = sanitizeToken(first).toLowerCase() || null;
            }
            break;
          }
        }
        const eqIdx = val.indexOf("=");
        const flagName = eqIdx === -1 ? val : val.slice(0, eqIdx);
        if (eqIdx === -1 && valueFlags.has(flagName)) {
          i++;
        }
        continue;
      }
      if (ENV_ASSIGNMENT_REGEX.test(val)) {
        continue;
      }
      if (skipDurationForTimeout) {
        skipDurationForTimeout = false;
        continue;
      }
      nextCmd = sanitizeToken(val).toLowerCase() || null;
      nextIdx = i + 1;
      break;
    }

    if (!nextCmd) break;
    results.push(nextCmd);
    currentWrapper = normalizeCommandBaseName(nextCmd);
    currentArgs = nextIdx >= 0 ? currentArgs.slice(nextIdx) : [];
  }

  return results;
}

export function extractCommandNames(
  command: string,
  shellDialect: RuntimeShellDialect = getRuntimeContext().shellDialect,
): string[] {
  const discovered = new Set<string>();

  if (shellDialect === "windows-cmd") {
    const tokens = tokenizeWindowsCmdSegment(command);
    if (tokens.length > 0) {
      const primary = sanitizeToken(tokens[0].value.replace(/^@+/, "")).toLowerCase();
      if (primary) {
        discovered.add(primary);
        const baseName = normalizeCommandBaseName(primary);
        if (WRAPPER_COMMANDS.has(baseName) && tokens.length > 1) {
          for (const wrapped of extractWrappedCommands(baseName, tokens.slice(1))) {
            discovered.add(wrapped);
          }
        }
      }
    }
    return Array.from(discovered);
  }

  const segments = splitCommandSegments(command);

  for (const segment of segments) {
    const trimmedSegment = segment.trim();
    if (!trimmedSegment) continue;
    if (isShellFunctionDefinition(trimmedSegment)) {
      discovered.add(SHELL_FUNCTION_DEFINITION_COMMAND);
      continue;
    }

    const tokens = tokenizeShellSegment(trimmedSegment);
    if (!tokens.length) continue;

    let index = 0;
    while (index < tokens.length && ENV_ASSIGNMENT_REGEX.test(tokens[index].value)) {
      index++;
    }

    if (index >= tokens.length) continue;

    const primary = sanitizeToken(tokens[index].value).toLowerCase();
    if (!primary) continue;

    discovered.add(primary);

    const baseName = normalizeCommandBaseName(primary);
    if (WRAPPER_COMMANDS.has(baseName) && index + 1 < tokens.length) {
      for (const wrapped of extractWrappedCommands(baseName, tokens.slice(index + 1))) {
        discovered.add(wrapped);
      }
    }
  }

  return Array.from(discovered);
}

function expandHomePath(rawPath: string): string | null {
  const trimmed = rawPath.trim();
  if (!trimmed) return "";
  if (trimmed === "~") return os.homedir();
  if (trimmed.startsWith("~/") || trimmed.startsWith("~\\")) {
    return path.join(os.homedir(), trimmed.slice(2));
  }
  // ~otheruser/... references another user's home directory — treat as outside workspace
  if (trimmed.startsWith("~")) {
    return null;
  }
  return trimmed;
}

/**
 * Shared working-directory resolver used by both `evaluateCommandSecurity` and
 * `BuiltinTools.executeCommand.execute` so permission checks and execution
 * always target the exact same directory.
 */
export function resolveCommandWorkingDir(cwd?: string): string {
  const rootDir = path.resolve(WorkDir);
  if (!cwd || !cwd.trim()) {
    return rootDir;
  }
  const expanded = expandHomePath(cwd);
  if (expanded === null) {
    return path.resolve(rootDir, cwd.trim());
  }
  return path.isAbsolute(expanded)
    ? path.resolve(expanded)
    : path.resolve(rootDir, expanded);
}

function isWindowsAbsolutePath(rawPath: string): boolean {
  return /^[A-Za-z]:/.test(rawPath) || rawPath.startsWith("\\\\");
}

const WINDOWS_RESERVED_DEVICE_REGEX = /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i;

function isWindowsUnsafePathToken(rawPath: string): string | null {
  if (/^[A-Za-z]:(?![\\/])/.test(rawPath)) {
    return "Command uses a Windows drive-relative path";
  }
  const afterDrive = /^[A-Za-z]:[\\/]/.test(rawPath) ? rawPath.slice(2) : rawPath;
  if (afterDrive.includes(":")) {
    return "Command uses Windows NTFS Alternate Data Stream syntax";
  }
  const segments = rawPath.replace(/\\/g, "/").split("/").filter(Boolean);
  for (const seg of segments) {
    const cleanSeg = seg.replace(/:.*$/, "").replace(/[. ]+$/, "");
    if (WINDOWS_RESERVED_DEVICE_REGEX.test(cleanSeg)) {
      return "Command accesses a reserved Windows device name";
    }
  }
  return null;
}

function dirHasUnsafeSymlinkOrProtectedEntry(
  dirPath: string,
  workspaceRoot: string,
  platform: NodeJS.Platform,
  recursive: boolean,
  options?: {
    ignoreDotEntries?: boolean;
    maxEntries?: number;
  },
): boolean {
  const ignoreDotEntries = options?.ignoreDotEntries ?? false;
  const maxEntries = options?.maxEntries ?? 5000;
  let visitedCount = 0;
  const visitedDirs = new Set<string>();
  const queue: string[] = [dirPath];

  while (queue.length > 0) {
    const current = queue.shift();
    if (current === undefined) break;
    const canonicalCurrent = canonicalizePathSync(current, platform);
    if (visitedDirs.has(canonicalCurrent)) continue;
    visitedDirs.add(canonicalCurrent);

    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch {
      // Unreadable or nonexistent directory during inspection: fail closed if recursive
      return recursive;
    }

    for (const entry of entries) {
      if (ignoreDotEntries && entry.name.startsWith(".")) {
        continue;
      }
      visitedCount++;
      if (visitedCount > maxEntries) {
        return true;
      }
      const fullPath = path.join(current, entry.name);
      if (entry.isSymbolicLink()) {
        let resolvedReal: string;
        try {
          resolvedReal = fs.realpathSync(fullPath);
        } catch {
          // Dangling or broken symlink: fail closed
          return true;
        }
        if (
          !isPathInsideDir(workspaceRoot, resolvedReal, platform) ||
          isSameNormalizedPath(resolvedReal, workspaceRoot, platform) ||
          isProtectedWorkspacePath(resolvedReal, "read", workspaceRoot, platform)
        ) {
          return true;
        }
        if (recursive) {
          try {
            if (fs.statSync(resolvedReal).isDirectory()) {
              queue.push(resolvedReal);
            }
          } catch {
            return true;
          }
        }
        continue;
      }
      if (isProtectedWorkspacePath(fullPath, "search", workspaceRoot, platform)) {
        return true;
      }
      if (recursive && entry.isDirectory()) {
        queue.push(fullPath);
      }
    }
  }

  return false;
}

function validateCommandPath(
  token: ShellToken,
  workingDir: string,
  workspaceRoot: string,
  isRecursive: boolean,
  platform: NodeJS.Platform,
  options?: {
    ignoreDotEntries?: boolean;
  },
): string | null {
  const raw = token.value.trim();
  if (!raw || raw === "-" || (platform !== "win32" && raw === "/dev/null")) {
    return null;
  }

  if (platform === "win32") {
    const winIssue = isWindowsUnsafePathToken(raw);
    if (winIssue) {
      return winIssue;
    }
  }

  // On non-Windows hosts or cross-platform tests, treat Windows drive/UNC paths
  // explicitly as outside workspace unless they resolve inside it.
  if (isWindowsAbsolutePath(raw) && platform !== "win32") {
    return "Command accesses a path outside the workspace";
  }

  // Normalize Windows backslashes when evaluating paths under win32
  const normalizedRaw = platform === "win32" ? raw.replace(/\\/g, "/") : raw;

  const globIndex = normalizedRaw.search(/[*?[]/);
  if (token.hasUnquotedGlob && globIndex !== -1) {
    const beforeGlob = normalizedRaw.slice(0, globIndex);
    const afterGlob = normalizedRaw.slice(globIndex);
    // Any traversal component after a wildcard cannot be statically bounded
    if (/(?:^|[/\\])\.\.(?:$|[/\\])/.test(afterGlob)) {
      return "Command uses a wildcard path that may traverse outside the workspace";
    }
    if (beforeGlob.startsWith("~")) {
      return "Command uses a wildcard path outside the workspace";
    }
    const lastSep = Math.max(beforeGlob.lastIndexOf("/"), beforeGlob.lastIndexOf("\\"));
    const staticDir = lastSep === -1 ? "" : beforeGlob.slice(0, lastSep + 1);
    const patternHead = beforeGlob.slice(lastSep + 1);
    const resolvedDir = canonicalizePathSync(
      path.isAbsolute(staticDir) ? staticDir : path.resolve(workingDir, staticDir || "."),
      platform,
    );
    if (!isPathInsideDir(workspaceRoot, resolvedDir, platform)) {
      return "Command accesses a path outside the workspace";
    }
    if (isProtectedWorkspacePath(resolvedDir, "search", workspaceRoot, platform)) {
      return "Command accesses protected workspace configuration";
    }
    // A wildcard rooted at workspace root (e.g. `*` or `*/oauth.json`) could match `config/`
    if (isSameNormalizedPath(resolvedDir, workspaceRoot, platform)) {
      return "Command uses a wildcard rooted at the workspace root";
    }
    const spansSubdirs = afterGlob.includes("/") || afterGlob.includes("\\") || afterGlob.includes("**");
    const isShallowNonDotGlob =
      !spansSubdirs && !isRecursive && !patternHead.startsWith(".") && platform !== "win32";
    if (
      dirHasUnsafeSymlinkOrProtectedEntry(
        resolvedDir,
        workspaceRoot,
        platform,
        spansSubdirs || isRecursive,
        { ignoreDotEntries: isShallowNonDotGlob || (options?.ignoreDotEntries ?? false) },
      )
    ) {
      return "Command uses a wildcard in a directory containing protected entries or external symlinks";
    }
    return null;
  }

  const expanded = expandHomePath(normalizedRaw);
  if (expanded === null) {
    return "Command accesses a path outside the workspace";
  }

  const resolved = path.isAbsolute(expanded) ? expanded : path.resolve(workingDir, expanded);
  const canonical = canonicalizePathSync(resolved, platform);

  if (!isPathInsideDir(workspaceRoot, canonical, platform)) {
    return "Command accesses a path outside the workspace";
  }

  if (isProtectedWorkspacePath(canonical, isRecursive ? "search" : "read", workspaceRoot, platform)) {
    return "Command accesses protected workspace configuration";
  }

  if (isRecursive) {
    if (isSameNormalizedPath(canonical, workspaceRoot, platform)) {
      return "Recursive command scans the workspace root including protected configuration";
    }
    let isDirectory = false;
    try {
      isDirectory = fs.statSync(canonical).isDirectory();
    } catch {
      isDirectory = false;
    }
    if (
      isDirectory &&
      dirHasUnsafeSymlinkOrProtectedEntry(canonical, workspaceRoot, platform, true, {
        ignoreDotEntries: options?.ignoreDotEntries ?? false,
      })
    ) {
      return "Recursive command scans a directory containing protected entries or external symlinks";
    }
  }

  return null;
}

const AGENT_SLACK_SAFE_VALUE_FLAGS = new Set([
  "-w",
  "--workspace",
  "-c",
  "--channel",
  "-l",
  "--limit",
  "--oldest",
  "--latest",
  "--thread",
  "--query",
  "-q",
  "--sort",
  "--cursor",
  "--format",
  "--types",
  "-u",
  "--user",
  "--ts",
]);

const AGENT_SLACK_SAFE_BOOL_FLAGS = new Set([
  "--help",
  "-h",
  "--version",
  "--json",
  "--include-archived",
]);

function inspectAgentSlackArgs(args: readonly ShellToken[]): string | null {
  if (
    args.length === 1 &&
    (args[0].value === "--help" || args[0].value === "-h" || args[0].value === "--version")
  ) {
    return null;
  }

  if (args.length < 2) {
    return "agent-slack invocation is missing an explicit read-only subcommand";
  }

  const first = args[0].value;
  const second = args[1].value;
  if (first.startsWith("-") || second.startsWith("-")) {
    return "agent-slack global flags before the subcommand require approval";
  }

  const subcommandKey = `${first.toLowerCase()}:${second.toLowerCase()}`;
  if (!AGENT_SLACK_READ_ONLY_SUBCOMMANDS.has(subcommandKey)) {
    return `agent-slack subcommand "${first.toLowerCase()} ${second.toLowerCase()}" requires approval`;
  }

  for (let i = 2; i < args.length; i++) {
    const val = args[i].value;
    if (val === "--") {
      break;
    }
    if (!val.startsWith("-") || val === "-") {
      continue;
    }
    const eqIdx = val.indexOf("=");
    const flag = eqIdx === -1 ? val : val.slice(0, eqIdx);
    if (AGENT_SLACK_SAFE_VALUE_FLAGS.has(flag)) {
      if (eqIdx === -1) {
        if (i + 1 >= args.length) {
          return `agent-slack flag "${flag}" is missing its argument`;
        }
        i++;
      }
      continue;
    }
    if (eqIdx === -1 && AGENT_SLACK_SAFE_BOOL_FLAGS.has(flag)) {
      continue;
    }
    return `agent-slack uses an unverified flag "${flag}"`;
  }

  return null;
}

type ParsedFileArgs = {
  readonly targetPaths: ShellToken[];
  readonly flagFilePaths: ShellToken[];
  readonly isRecursive: boolean;
  readonly ignoreDotEntries: boolean;
  readonly reasons: string[];
};

function parseCommandWithSafeSpec(
  baseName: string,
  spec: SafeFlagSpec,
  args: readonly ShellToken[],
  shellDialect: RuntimeShellDialect,
): ParsedFileArgs {
  const targetPaths: ShellToken[] = [];
  const flagFilePaths: ShellToken[] = [];
  const reasons: string[] = [];
  const positional: ShellToken[] = [];
  let isRecursive = baseName === "tree" || baseName === "du" || baseName === "rg";
  let ignoreDotEntries = (baseName === "tree" && shellDialect !== "windows-cmd") || baseName === "rg";
  let endOfOptions = false;
  let grepHasExplicitPattern = false;
  const isGrepFamily =
    baseName === "grep" || baseName === "egrep" || baseName === "fgrep" || baseName === "rg";

  for (let i = 0; i < args.length; i++) {
    const token = args[i];
    const val = token.value;

    if (!endOfOptions && val === "--") {
      endOfOptions = true;
      continue;
    }

    const isFlagLike =
      !endOfOptions &&
      ((val.startsWith("-") && val !== "-") ||
        (shellDialect === "windows-cmd" && val.startsWith("/")));

    // Reject option-like tokens appearing after positional operands to eliminate
    // BSD (macOS non-permuting getopt) vs. GNU (permuting getopt) parser differentials
    // such as `head knowledge/note.md -n config/oauth.json` or `uniq knowledge/note.md -c`.
    if (isFlagLike && positional.length > 0) {
      reasons.push(
        `Command "${baseName}" places option "${val}" after a positional argument (ambiguous across BSD/GNU getopt)`,
      );
      continue;
    }

    if (!endOfOptions && shellDialect === "windows-cmd" && val.startsWith("/")) {
      reasons.push(`Command "${baseName}" uses an unverified Windows flag "${val}"`);
      continue;
    }

    if (!endOfOptions && val.startsWith("-") && val !== "-") {
      // Allow numeric shorthand like `head -20` / `tail -50`
      if (spec.allowNumericShortFlag && /^-[0-9]+$/.test(val)) {
        continue;
      }

      if (val.startsWith("--")) {
        const eqIndex = val.indexOf("=");
        const flagName = eqIndex === -1 ? val : val.slice(0, eqIndex);
        const eqValue = eqIndex === -1 ? undefined : val.slice(eqIndex + 1);

        if (spec.recursiveLongFlags?.has(flagName)) {
          isRecursive = true;
        }
        if (
          baseName === "rg" &&
          (flagName === "--hidden" || flagName === "--no-ignore" || flagName === "--unrestricted")
        ) {
          ignoreDotEntries = false;
        }

        if (spec.longFileValueFlags?.has(flagName)) {
          if (isGrepFamily && flagName === "--file") {
            grepHasExplicitPattern = true;
          }
          if (eqValue !== undefined) {
            flagFilePaths.push({ raw: eqValue, value: eqValue, hasUnquotedGlob: token.hasUnquotedGlob });
          } else if (i + 1 < args.length) {
            flagFilePaths.push(args[i + 1]);
            i++;
          } else {
            reasons.push(`Command "${baseName}" flag "${flagName}" is missing its file argument`);
          }
          continue;
        }

        if (spec.longValueFlags.has(flagName)) {
          if (isGrepFamily && flagName === "--regexp") {
            grepHasExplicitPattern = true;
          }
          if (eqValue === undefined) {
            if (i + 1 < args.length) {
              i++;
            } else {
              reasons.push(`Command "${baseName}" flag "${flagName}" is missing its argument`);
            }
          }
          continue;
        }

        if (spec.longOptionalEqFlags?.has(flagName)) {
          // Optional-argument flags MUST NOT consume the next positional token!
          // Bare `--color` or `--color=always` are both safe; next token stays positional.
          continue;
        }

        if (eqValue === undefined && spec.longBoolFlags.has(flagName)) {
          if (baseName === "rg" && flagName === "--files") {
            grepHasExplicitPattern = true;
          }
          continue;
        }

        reasons.push(`Command "${baseName}" uses an unverified or potentially unsafe flag "${flagName}"`);
        continue;
      }

      // Short flag or short flag cluster (e.g. `-la`, `-n20`, `-rn`, `-efoo`, `-f/etc/passwd`)
      const cluster = val.slice(1);
      for (let cIdx = 0; cIdx < cluster.length; cIdx++) {
        const ch = cluster[cIdx];

        if (spec.recursiveShortFlags?.has(ch)) {
          isRecursive = true;
        }
        if (baseName === "tree" && ch === "a") {
          ignoreDotEntries = false;
        }
        if (baseName === "rg" && (ch === "." || ch === "u")) {
          ignoreDotEntries = false;
        }

        if (spec.shortFileValueFlags?.has(ch)) {
          if (isGrepFamily && ch === "f") {
            grepHasExplicitPattern = true;
          }
          const attached = cluster.slice(cIdx + 1);
          if (attached) {
            flagFilePaths.push({ raw: attached, value: attached, hasUnquotedGlob: token.hasUnquotedGlob });
          } else if (i + 1 < args.length) {
            flagFilePaths.push(args[i + 1]);
            i++;
          } else {
            reasons.push(`Command "${baseName}" flag "-${ch}" is missing its file argument`);
          }
          break;
        }

        if (spec.shortValueFlags.has(ch)) {
          if (isGrepFamily && ch === "e") {
            grepHasExplicitPattern = true;
          }
          const attached = cluster.slice(cIdx + 1);
          if (!attached) {
            if (i + 1 < args.length) {
              i++;
            } else {
              reasons.push(`Command "${baseName}" flag "-${ch}" is missing its argument`);
            }
          }
          break;
        }

        if (spec.shortBoolFlags.has(ch)) {
          continue;
        }

        reasons.push(`Command "${baseName}" uses an unverified or potentially unsafe flag "-${ch}"`);
        break;
      }
      continue;
    }

    positional.push(token);
  }

  if (isGrepFamily) {
    if (grepHasExplicitPattern) {
      targetPaths.push(...positional);
    } else if (positional.length > 0) {
      targetPaths.push(...positional.slice(1));
    }
  } else if (baseName === "uniq") {
    if (positional.length >= 2) {
      reasons.push("uniq writes output to a file");
    }
    if (positional.length >= 1) {
      targetPaths.push(positional[0]);
    }
  } else if (
    baseName === "date" ||
    baseName === "echo" ||
    baseName === "printf" ||
    baseName === "pwd" ||
    baseName === "uname" ||
    baseName === "hostname" ||
    baseName === "whoami" ||
    baseName === "which" ||
    baseName === "basename" ||
    baseName === "dirname"
  ) {
    // Positional args for these commands are format strings / text / names, not file reads
  } else {
    targetPaths.push(...positional);
  }

  return { targetPaths, flagFilePaths, isRecursive, ignoreDotEntries, reasons };
}

function parseGenericFileReadingArgs(
  args: readonly ShellToken[],
  shellDialect: RuntimeShellDialect,
): ParsedFileArgs {
  const targetPaths: ShellToken[] = [];
  const reasons: string[] = [];
  let endOfOptions = false;

  for (const token of args) {
    const val = token.value;
    if (!endOfOptions && val === "--") {
      endOfOptions = true;
      continue;
    }
    if (!endOfOptions && val.startsWith("-") && val !== "-") {
      reasons.push(`Command uses an unverified flag "${val}" with a file-reading utility`);
      continue;
    }
    if (!endOfOptions && shellDialect === "windows-cmd" && val.startsWith("/")) {
      reasons.push(`Command uses an unverified Windows flag "${val}" with a file-reading utility`);
      continue;
    }
    targetPaths.push(token);
  }

  return { targetPaths, flagFilePaths: [], isRecursive: false, ignoreDotEntries: false, reasons };
}

function isInsideWorkspaceGitRepo(
  workingDir: string,
  workspaceRoot: string,
  platform: NodeJS.Platform,
): boolean {
  let current = canonicalizePathSync(workingDir, platform);
  const canonicalRoot = canonicalizePathSync(workspaceRoot, platform);
  if (!isPathInsideDir(canonicalRoot, current, platform)) {
    return false;
  }
  while (isPathInsideDir(canonicalRoot, current, platform)) {
    const gitEntry = path.join(current, ".git");
    try {
      const stat = fs.lstatSync(gitEntry);
      if (
        stat.isDirectory() &&
        !stat.isSymbolicLink() &&
        isPathInsideDir(canonicalRoot, canonicalizePathSync(gitEntry, platform), platform)
      ) {
        return true;
      }
    } catch {
      // No .git at this directory level; walk up within workspaceRoot
    }
    if (isSameNormalizedPath(current, canonicalRoot, platform)) {
      break;
    }
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
  return false;
}

function inspectGitArgs(
  args: readonly ShellToken[],
  workingDir: string,
  workspaceRoot: string,
  platform: NodeJS.Platform,
): string | null {
  if (args.length === 0) {
    return "git invocation is missing a read-only subcommand";
  }

  if (args.length === 1 && (args[0].value === "--version" || args[0].value === "--help")) {
    return null;
  }

  const first = args[0].value;
  if (first.startsWith("-")) {
    return "git global flags before the subcommand require approval";
  }

  const subcommand = first.toLowerCase();
  if (!GIT_READ_ONLY_SUBCOMMANDS.has(subcommand)) {
    return `git subcommand "${subcommand}" requires approval`;
  }

  const spec = GIT_SAFE_FLAGS_BY_SUBCOMMAND[subcommand];
  if (!spec) {
    return `git subcommand "${subcommand}" requires approval`;
  }

  // Require an existing non-symlink .git directory inside the workspace for all
  // repo-reading subcommands so git cannot walk up to an external ancestor repo
  // (e.g. $HOME/.git) or fall back to implicit `git diff --no-index`.
  if (!isInsideWorkspaceGitRepo(workingDir, workspaceRoot, platform)) {
    return `git ${subcommand} requires an existing git repository inside the workspace`;
  }

  const positionalTokens: ShellToken[] = [];
  let endOfOptions = false;
  const subArgs = args.slice(1);

  for (let i = 0; i < subArgs.length; i++) {
    const token = subArgs[i];
    const val = token.value;
    if (!endOfOptions && val === "--") {
      endOfOptions = true;
      continue;
    }
    if (!endOfOptions && val.startsWith("-") && val !== "-") {
      if (spec.allowNumericShortFlag && /^-[0-9]+$/.test(val)) {
        continue;
      }
      if (val.startsWith("--")) {
        const eqIdx = val.indexOf("=");
        const flagName = eqIdx === -1 ? val : val.slice(0, eqIdx);
        if (eqIdx !== -1) {
          if (spec.optionalEqFlags?.has(flagName) || spec.valueFlags.has(flagName)) {
            continue;
          }
          return `git ${subcommand} uses an unverified or potentially unsafe flag "${flagName}"`;
        }
        // Check optionalEqFlags BEFORE valueFlags so optional-argument flags never
        // consume and skip validation of the following token.
        if (spec.optionalEqFlags?.has(flagName) || spec.boolFlags.has(flagName)) {
          continue;
        }
        if (spec.valueFlags.has(flagName)) {
          if (i + 1 >= subArgs.length) {
            return `git ${subcommand} flag "${flagName}" is missing its argument`;
          }
          i++;
          continue;
        }
        return `git ${subcommand} uses an unverified or potentially unsafe flag "${flagName}"`;
      }

      // Short flags: exact bool flag, attached optional-arg forms (`-U3`, `-uno`),
      // exact value flag, or attached value flag like `-n5`, `-L1,10`
      if (spec.boolFlags.has(val)) {
        continue;
      }
      if ((subcommand === "diff" || subcommand === "show") && /^-U[0-9]+$/.test(val)) {
        continue;
      }
      if (subcommand === "status" && /^-u(?:no|normal|all)$/.test(val)) {
        continue;
      }
      if (spec.valueFlags.has(val)) {
        if (i + 1 >= subArgs.length) {
          return `git ${subcommand} flag "${val}" is missing its argument`;
        }
        i++;
        continue;
      }
      if (val.length > 2 && spec.valueFlags.has(val.slice(0, 2))) {
        continue;
      }
      return `git ${subcommand} uses an unverified or potentially unsafe flag "${val}"`;
    }

    positionalTokens.push(token);
  }

  // Validate positional / pathspec arguments so `git diff`, `git blame`, `git ls-files`,
  // `git show`, `git log`, and `git status` cannot read outside the workspace or protected dirs.
  for (const token of positionalTokens) {
    const raw = token.value.trim();
    if (!raw) continue;
    // Block git pathspec magic (`:(top)...`, `:(literal)...`) and index-stage syntax (`:0:...`)
    if (raw.startsWith(":")) {
      return "git pathspec magic and index-stage references require approval";
    }
    // Check git revision:path notation (e.g. `HEAD:../config/oauth.json` or `HEAD:config/oauth.json`)
    if (raw.includes(":") && !isWindowsAbsolutePath(raw)) {
      const colonIdx = raw.indexOf(":");
      if (raw.lastIndexOf(":") !== colonIdx) {
        return "git multi-colon revision/pathspec references require approval";
      }
      const pathPart = raw.slice(colonIdx + 1);
      if (pathPart) {
        const revPathIssue = validateCommandPath(
          { raw: pathPart, value: pathPart, hasUnquotedGlob: token.hasUnquotedGlob },
          workingDir,
          workspaceRoot,
          false,
          platform,
        );
        if (revPathIssue) {
          return revPathIssue;
        }
      }
      continue;
    }
    const pathIssue = validateCommandPath(token, workingDir, workspaceRoot, false, platform);
    if (pathIssue) {
      return pathIssue;
    }
  }

  return null;
}

const WINDOWS_CWD_SHADOW_EXTENSIONS = new Set([
  ".exe",
  ".com",
  ".bat",
  ".cmd",
  ".vbs",
  ".vbe",
  ".js",
  ".jse",
  ".wsf",
  ".wsh",
  ".msc",
  ".ps1",
  ".pif",
  ".scr",
]);

function hasWindowsCwdCommandShadow(workingDir: string, primary: string): boolean {
  const normalizedBase = normalizeCommandBaseName(primary).toLowerCase();
  if (!normalizedBase) return false;
  const exts = new Set(WINDOWS_CWD_SHADOW_EXTENSIONS);
  const pathExt = process.env.PATHEXT;
  if (pathExt) {
    for (const part of pathExt.split(";")) {
      const trimmed = part.trim().toLowerCase();
      if (trimmed.startsWith(".")) {
        exts.add(trimmed);
      }
    }
  }
  try {
    const entries = fs.readdirSync(workingDir);
    for (const entry of entries) {
      const lower = entry.toLowerCase();
      if (lower === normalizedBase) {
        return true;
      }
      for (const ext of exts) {
        if (lower === `${normalizedBase}${ext}`) {
          return true;
        }
      }
    }
  } catch {
    // Working directory may not exist in synthetic/cross-platform evaluations
  }
  return false;
}

export function evaluateCommandSecurity(
  command: string,
  sessionAllowedCommands?: Set<string>,
  options?: {
    cwd?: string;
    shellDialect?: RuntimeShellDialect;
    platform?: NodeJS.Platform;
  },
): CommandSecurityEvaluation {
  const runtime = getRuntimeContext(options?.platform);
  const platform = options?.platform ?? runtime.platform;
  const shellDialect = options?.shellDialect ?? runtime.shellDialect;
  const commandNames = extractCommandNames(command, shellDialect);
  const allowList = getSecurityAllowList();
  const allowSet = new Set(allowList);

  if (allowSet.has("*")) {
    return {
      blocked: false,
      commandNames,
      blockedCommands: [],
      capabilityReasons: [],
      allowScopeGrant: false,
    };
  }

  const capabilityReasons = new Set<string>();
  const workspaceRoot = canonicalizePathSync(WorkDir, platform);

  let workingDir = workspaceRoot;
  if (options?.cwd && options.cwd.trim()) {
    const expandedCwd = expandHomePath(options.cwd);
    if (expandedCwd === null || (isWindowsAbsolutePath(options.cwd.trim()) && platform !== "win32")) {
      capabilityReasons.add("Working directory is outside the workspace");
    } else {
      const resolvedCwd = resolveCommandWorkingDir(options.cwd);
      workingDir = canonicalizePathSync(resolvedCwd, platform);
      if (!isPathInsideDir(workspaceRoot, workingDir, platform)) {
        capabilityReasons.add("Working directory is outside the workspace");
      } else if (isProtectedWorkspacePath(workingDir, "read", workspaceRoot, platform)) {
        capabilityReasons.add("Working directory targets protected workspace configuration");
      }
    }
  }

  // 1. Inspect raw shell syntax (redirections, command/process substitution, $VAR, braces, comments, etc.)
  const syntax = inspectShellSyntax(command, shellDialect);
  for (const reason of syntax.reasons) {
    capabilityReasons.add(reason);
  }
  for (const redirectTarget of syntax.inputRedirectTokens) {
    const pathIssue = validateCommandPath(
      redirectTarget,
      workingDir,
      workspaceRoot,
      false,
      platform,
    );
    if (pathIssue) {
      capabilityReasons.add(pathIssue);
    }
  }

  // Fail closed on non-empty commands that yield no executable command name
  // (e.g. `< /etc/passwd` triggering zsh READNULLCMD, bare env assignments, or comments).
  if (command.trim().length > 0 && commandNames.length === 0) {
    capabilityReasons.add("Command has no executable command name");
  }

  // 2. Inspect each command segment for inherent capabilities, safe flags, and path arguments
  const segments =
    shellDialect === "windows-cmd"
      ? command.trim()
        ? [command]
        : []
      : splitCommandSegments(command);

  for (const segment of segments) {
    const trimmedSegment = segment.trim();
    if (!trimmedSegment) continue;

    if (shellDialect === "posix-sh" && isShellFunctionDefinition(trimmedSegment)) {
      capabilityReasons.add("Command defines a shell function");
      continue;
    }

    const tokens =
      shellDialect === "windows-cmd"
        ? tokenizeWindowsCmdSegment(trimmedSegment)
        : tokenizeShellSegment(trimmedSegment);
    if (!tokens.length) continue;

    let index = 0;
    let hasEnvAssignment = false;
    if (shellDialect === "posix-sh") {
      while (index < tokens.length && ENV_ASSIGNMENT_REGEX.test(tokens[index].value)) {
        hasEnvAssignment = true;
        index++;
      }
    }

    if (hasEnvAssignment) {
      capabilityReasons.add("Command sets inline environment variables");
    }
    if (index >= tokens.length) continue;

    const primaryToken = tokens[index];
    const rawPrimaryToken =
      shellDialect === "windows-cmd"
        ? primaryToken.value.replace(/^@+/, "")
        : primaryToken.value;
    const primary = sanitizeToken(rawPrimaryToken).toLowerCase();
    if (!primary) continue;

    if (primaryToken.hasUnquotedGlob || /[*?[]/.test(primary)) {
      capabilityReasons.add("Command name contains wildcard characters");
    }

    const baseName = normalizeCommandBaseName(primary);
    const args = tokens.slice(index + 1);

    if (isAlwaysRequireApprovalCommand(primary)) {
      capabilityReasons.add(
        `Command "${primary}" can execute arbitrary code, change directory, or expose environment secrets`,
      );
    }

    if (
      (shellDialect === "windows-cmd" || platform === "win32") &&
      !primary.includes("/") &&
      !primary.includes("\\") &&
      hasWindowsCwdCommandShadow(workingDir, primary)
    ) {
      capabilityReasons.add(
        `Working directory contains a file shadowing command "${primary}" on Windows`,
      );
    }

    if (baseName === "agent-slack") {
      const slackReason = inspectAgentSlackArgs(args);
      if (slackReason) {
        capabilityReasons.add(slackReason);
      }
    }

    if (baseName === "git") {
      const gitReason = inspectGitArgs(args, workingDir, workspaceRoot, platform);
      if (gitReason) {
        capabilityReasons.add(gitReason);
      }
    }

    const safeSpec = SAFE_FLAG_SPEC_BY_COMMAND[baseName];
    if (safeSpec) {
      const parsed = parseCommandWithSafeSpec(baseName, safeSpec, args, shellDialect);
      for (const reason of parsed.reasons) {
        capabilityReasons.add(reason);
      }

      if (FILE_READING_COMMANDS.has(baseName)) {
        if (parsed.targetPaths.length === 0 && parsed.isRecursive) {
          if (isSameNormalizedPath(workingDir, workspaceRoot, platform)) {
            capabilityReasons.add(
              "Recursive command scans the workspace root including protected configuration",
            );
          } else if (
            dirHasUnsafeSymlinkOrProtectedEntry(workingDir, workspaceRoot, platform, true, {
              ignoreDotEntries: parsed.ignoreDotEntries,
            })
          ) {
            capabilityReasons.add(
              "Recursive command scans a directory containing protected entries or external symlinks",
            );
          }
        }

        for (const pathToken of parsed.targetPaths) {
          const pathIssue = validateCommandPath(
            pathToken,
            workingDir,
            workspaceRoot,
            parsed.isRecursive,
            platform,
            { ignoreDotEntries: parsed.ignoreDotEntries },
          );
          if (pathIssue) {
            capabilityReasons.add(pathIssue);
          }
        }

        for (const flagPathToken of parsed.flagFilePaths) {
          const pathIssue = validateCommandPath(
            flagPathToken,
            workingDir,
            workspaceRoot,
            false,
            platform,
          );
          if (pathIssue) {
            capabilityReasons.add(pathIssue);
          }
        }
      }
    } else if (FILE_READING_COMMANDS.has(baseName)) {
      const parsed = parseGenericFileReadingArgs(args, shellDialect);
      for (const reason of parsed.reasons) {
        capabilityReasons.add(reason);
      }
      for (const pathToken of parsed.targetPaths) {
        const pathIssue = validateCommandPath(
          pathToken,
          workingDir,
          workspaceRoot,
          parsed.isRecursive,
          platform,
        );
        if (pathIssue) {
          capabilityReasons.add(pathIssue);
        }
      }
    }
  }

  // 3. Check command-name allow-list
  const blockedCommands =
    !allowList.length && (!sessionAllowedCommands || sessionAllowedCommands.size === 0)
      ? commandNames
      : commandNames.filter((cmd) => !allowSet.has(cmd) && !sessionAllowedCommands?.has(cmd));

  const reasonsList = Array.from(capabilityReasons);
  const blocked = reasonsList.length > 0 || blockedCommands.length > 0;
  const allowScopeGrant =
    reasonsList.length === 0 &&
    blockedCommands.length > 0 &&
    blockedCommands.every(
      (cmd) =>
        !isAlwaysRequireApprovalCommand(cmd) &&
        !cmd.includes("/") &&
        !cmd.includes("\\"),
    );

  return {
    blocked,
    commandNames,
    blockedCommands,
    capabilityReasons: reasonsList,
    allowScopeGrant,
  };
}

export function isBlocked(
  command: string,
  sessionAllowedCommands?: Set<string>,
  options?: {
    cwd?: string;
    shellDialect?: RuntimeShellDialect;
    platform?: NodeJS.Platform;
  },
): boolean {
  return evaluateCommandSecurity(command, sessionAllowedCommands, options).blocked;
}

export interface CommandResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

function buildSafeExecEnv(env?: NodeJS.ProcessEnv): NodeJS.ProcessEnv | undefined {
  if (process.platform === "win32") {
    return {
      ...(env ?? process.env),
      NoDefaultCurrentDirectoryInExePath: "1",
    };
  }
  return env;
}

/**
 * Executes an arbitrary shell command
 * @param command - The command to execute (e.g., "cat abc.txt | grep 'abc@gmail.com'")
 * @param options - Optional execution options
 * @returns Promise with stdout, stderr, and exit code
 */
export async function executeCommand(
  command: string,
  options?: {
    cwd?: string;
    timeout?: number; // timeout in milliseconds
    maxBuffer?: number; // max buffer size in bytes
    env?: NodeJS.ProcessEnv; // override environment
  },
): Promise<CommandResult> {
  try {
    const shell = getExecutionShell();
    const { stdout, stderr } = await execPromise(command, {
      cwd: options?.cwd,
      timeout: options?.timeout,
      maxBuffer: options?.maxBuffer || 1024 * 1024, // default 1MB
      shell,
      env: buildSafeExecEnv(options?.env),
    });

    return {
      stdout: stdout.trim(),
      stderr: stderr.trim(),
      exitCode: 0,
    };
  } catch (error: unknown) {
    // exec throws an error if the command fails or times out
    const e = error as { stdout?: string; stderr?: string; code?: number; message?: string };
    return {
      stdout: e.stdout?.trim() || "",
      stderr: e.stderr?.trim() || e.message || "",
      exitCode: e.code || 1,
    };
  }
}

export interface AbortableCommandResult extends CommandResult {
  wasAborted: boolean;
}

const SIGKILL_GRACE_MS = 200;

/**
 * Kill a process tree using negative PID (process group kill on Unix).
 * Falls back to direct kill if group kill fails.
 */
function killProcessTree(proc: ChildProcess, signal: NodeJS.Signals): void {
  if (!proc.pid || proc.killed) return;
  try {
    // Negative PID kills the entire process group (Unix)
    process.kill(-proc.pid, signal);
  } catch {
    try {
      proc.kill(signal);
    } catch {
      // Process may already be dead
    }
  }
}

/**
 * Executes a shell command with abort support.
 * Uses spawn with detached=true to create a process group for proper tree killing.
 * Returns both the promise and the child process handle.
 */
export function executeCommandAbortable(
  command: string,
  options?: {
    cwd?: string;
    timeout?: number;
    maxBuffer?: number;
    signal?: AbortSignal;
    onData?: (chunk: string) => void;
    env?: NodeJS.ProcessEnv;
  },
): { promise: Promise<AbortableCommandResult>; process: ChildProcess } {
  // Check if already aborted before spawning
  if (options?.signal?.aborted) {
    // Return a dummy process and a resolved result
    const dummyProc = spawn(process.execPath, ["-e", "process.exit(0)"]);
    dummyProc.kill();
    return {
      process: dummyProc,
      promise: Promise.resolve({
        stdout: "",
        stderr: "",
        exitCode: 130,
        wasAborted: true,
      }),
    };
  }

  const shell = getExecutionShell();
  const proc = spawn(command, [], {
    shell,
    cwd: options?.cwd,
    env: buildSafeExecEnv(options?.env),
    detached: process.platform !== "win32", // Create process group on Unix
    stdio: ["ignore", "pipe", "pipe"],
  });

  const promise = new Promise<AbortableCommandResult>((resolve) => {
    let stdout = "";
    let stderr = "";
    let wasAborted = false;
    let exited = false;

    // Collect output
    proc.stdout?.on("data", (chunk: Buffer) => {
      const text = chunk.toString();
      const maxBuffer = options?.maxBuffer || 1024 * 1024;
      if (stdout.length < maxBuffer) {
        stdout += text;
      }
      options?.onData?.(text);
    });
    proc.stderr?.on("data", (chunk: Buffer) => {
      const text = chunk.toString();
      const maxBuffer = options?.maxBuffer || 1024 * 1024;
      if (stderr.length < maxBuffer) {
        stderr += text;
      }
      options?.onData?.(text);
    });

    // Abort handler
    const abortHandler = () => {
      wasAborted = true;
      killProcessTree(proc, "SIGTERM");
      // Force kill after grace period
      setTimeout(() => {
        if (!exited) {
          killProcessTree(proc, "SIGKILL");
        }
      }, SIGKILL_GRACE_MS);
    };

    if (options?.signal) {
      options.signal.addEventListener("abort", abortHandler, { once: true });
    }

    // Timeout handler
    let timeoutId: ReturnType<typeof setTimeout> | undefined;
    if (options?.timeout) {
      timeoutId = setTimeout(() => {
        wasAborted = true;
        killProcessTree(proc, "SIGTERM");
        setTimeout(() => {
          if (!exited) {
            killProcessTree(proc, "SIGKILL");
          }
        }, SIGKILL_GRACE_MS);
      }, options.timeout);
    }

    proc.once("exit", (code) => {
      exited = true;
      // Cleanup listeners
      if (options?.signal) {
        options.signal.removeEventListener("abort", abortHandler);
      }
      if (timeoutId) {
        clearTimeout(timeoutId);
      }

      if (wasAborted) {
        stdout += "\n\n(Command was aborted)";
      }

      resolve({
        stdout: stdout.trim(),
        stderr: stderr.trim(),
        exitCode: code ?? 1,
        wasAborted,
      });
    });

    proc.once("error", (err) => {
      exited = true;
      if (options?.signal) {
        options.signal.removeEventListener("abort", abortHandler);
      }
      if (timeoutId) {
        clearTimeout(timeoutId);
      }
      resolve({
        stdout: "",
        stderr: err.message,
        exitCode: 1,
        wasAborted,
      });
    });
  });

  return { promise, process: proc };
}

/**
 * Executes a command synchronously (blocking)
 * Use with caution - prefer executeCommand for async execution
 */
export function executeCommandSync(
  command: string,
  options?: {
    cwd?: string;
    timeout?: number;
  },
): CommandResult {
  try {
    const shell = getExecutionShell();
    const stdout = execSync(command, {
      cwd: options?.cwd,
      timeout: options?.timeout,
      encoding: "utf-8",
      shell,
      env: buildSafeExecEnv(),
    });

    return {
      stdout: stdout.trim(),
      stderr: "",
      exitCode: 0,
    };
  } catch (error: unknown) {
    const e = error as { stdout?: string; stderr?: string; status?: number; message?: string };
    return {
      stdout: e.stdout?.toString().trim() || "",
      stderr: e.stderr?.toString().trim() || e.message || "",
      exitCode: e.status || 1,
    };
  }
}
