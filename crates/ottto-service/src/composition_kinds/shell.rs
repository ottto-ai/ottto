//! Lexical shell-command parsing shared by the session-start facts and
//! composition kinds: file-like tokens, directory changes and path
//! normalization against the session folder. No `stat`, no IO.

use std::path::Path;

pub(crate) const MAX_SHELL_PATH_TOKENS: usize = 16;
const MAX_PATH_BYTES: usize = 512;

/// `ext` of a path's last segment: 1-8 ASCII alphanumerics after the last dot.
pub(crate) fn extension(path: &str) -> Option<&str> {
    let name = path.rsplit('/').next()?;
    let (_, ext) = name.rsplit_once('.')?;
    ((1..=8).contains(&ext.len()) && ext.bytes().all(|byte| byte.is_ascii_alphanumeric()))
        .then_some(ext)
}

/// File-like tokens of a shell command, taken lexically (no `stat`): not a
/// flag, no URL or shell syntax, and either a path (`/`) or a file extension.
pub(crate) fn shell_path_tokens(command: &str) -> impl Iterator<Item = &str> {
    command
        .split(|ch: char| {
            ch.is_whitespace() || matches!(ch, ';' | '|' | '&' | '(' | ')' | '<' | '>' | '`')
        })
        .map(|token| token.trim_matches(|ch| matches!(ch, '"' | '\'' | ',')))
        .filter(|token| {
            !token.is_empty()
                && !token.starts_with('-')
                && !token.contains("://")
                && !token.contains(['*', '?', '$', '{', '}', '=', '[', ']'])
                && (token.contains('/') || extension(token).is_some())
        })
        .take(MAX_SHELL_PATH_TOKENS)
}

/// True when a shell command may change its working directory, so its
/// relative paths cannot be shown to be inside the session's checkout.
pub(crate) fn shell_changes_directory(command: &str) -> bool {
    // Quotes and braces split too, so `bash -lc 'cd x && ...'` is caught.
    command
        .split(|ch: char| {
            ch.is_whitespace()
                || matches!(
                    ch,
                    ';' | '|' | '&' | '(' | ')' | '`' | '\'' | '"' | '{' | '}'
                )
        })
        .any(|word| {
            matches!(word, "cd" | "pushd" | "popd" | "chdir")
                // `-C dir` and attached `-Cdir` (git, make, tar, `env -C`).
                || word.starts_with("-C")
                || [
                    "--chdir",
                    "--directory",
                    "--git-dir",
                    "--work-tree",
                    "-chdir",
                    "--cwd",
                    "--prefix",
                ]
                .iter()
                .any(|flag| word.starts_with(flag))
        })
}

fn is_repo_relative(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.starts_with('~')
        && !path.split('/').any(|segment| segment == "..")
}

/// Admission's forbidden fragments for any plain path (from the server's
/// footprint schema), matched case-insensitively.
const PLAIN_PATH_FORBIDDEN_FRAGMENTS: [&str; 15] = [
    "/users/",
    "\\users\\",
    "/home/",
    "\\home\\",
    "file://",
    "transcript_path",
    "workspace_path",
    "full_transcript_path",
    "authorization:",
    "bearer ",
    "otdev_",
    "otsi_",
    "otsr_",
    "otel_",
    "otrelay_",
];

/// True when admission takes `path` as a plain `repo_path` unchanged (its
/// `_safe_relative_path`): any other path travels hashed or is withheld, so
/// one unsafe path never clears the whole session-start block.
pub(crate) fn is_plain_path(path: &str) -> bool {
    let lowered = path.to_lowercase();
    is_repo_relative(path)
        && path.chars().count() <= MAX_PATH_BYTES
        // No backslash form (`\x`, `a\..\b`, `C:\x`) and no drive or URL form.
        && !path.contains('\\')
        && !path.contains(":/")
        // Admission collapses whitespace runs; only single inner spaces survive it.
        && !path.starts_with(' ')
        && !path.ends_with(' ')
        && !path.contains("  ")
        && !path
            .chars()
            .any(|ch| ch != ' ' && (ch.is_whitespace() || ch.is_control()))
        && !PLAIN_PATH_FORBIDDEN_FRAGMENTS
            .iter()
            .any(|fragment| lowered.contains(fragment))
}

/// `(key, plain path)`: the key is the repo-relative path when the file is
/// inside the session's working directory (a lexical prefix test), else the
/// path as written. The plain path is set only when admission accepts it and
/// its base is proven: an absolute path under `cwd`, or a relative one when
/// `trust_relative` and the session directory is known. Every other file can
/// only travel hashed.
pub(crate) fn normalize_path(
    raw: &str,
    cwd: Option<&Path>,
    trust_relative: bool,
) -> Option<(String, Option<String>)> {
    let raw = raw.trim();
    let raw = raw.strip_prefix("./").unwrap_or(raw);
    if raw.is_empty() || raw.len() > MAX_PATH_BYTES {
        return None;
    }
    if raw.starts_with('/') {
        let inside = cwd
            .and_then(Path::to_str)
            .and_then(|cwd| raw.strip_prefix(cwd.trim_end_matches('/')))
            .and_then(|rest| rest.strip_prefix('/'))
            .filter(|rest| is_repo_relative(rest));
        return Some(match inside {
            Some(rest) => (
                rest.to_string(),
                is_plain_path(rest).then(|| rest.to_string()),
            ),
            None => (raw.to_string(), None),
        });
    }
    let plain = trust_relative && cwd.is_some() && is_plain_path(raw);
    Some((raw.to_string(), plain.then(|| raw.to_string())))
}

// -------------------------------------------------------------------------
// Command classification (kinds_version 2).
//
// A small lexical reading of a shell command: quotes, escapes, heredocs,
// redirections, pipelines and `&&`/`||`/`;` lists. It never runs anything and
// never touches the file system. Each pipeline whose standard output reaches
// the model is one output-producing segment; writes (a redirect to a file,
// `sed -i`, a heredoc fed to `cat > f`) produce none and are never reads.
// -------------------------------------------------------------------------

/// What an output-producing pipeline shows the model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ShellClass {
    /// File contents (`cat`, `sed -n`, `nl`, `head`, `git show rev:path`, ...).
    Read,
    Git,
    /// Searches and listings (`rg`, `grep`, `find`, `ls`, `git grep`, ...).
    Search,
    TestsBuilds,
    Other,
}

/// One output-producing pipeline of a shell command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ShellSegment {
    pub(crate) class: ShellClass,
    /// The files a read shows: joined to the folder the pipeline runs in when
    /// relative and that folder is known, else as written. Empty when the read
    /// names no file the text can show (standard input, unknown variables,
    /// globs). Only reads carry paths.
    pub(crate) paths: Vec<String>,
}

/// Most output-producing pipelines kept for one command.
const MAX_SEGMENTS: usize = 64;
/// Most tokens read from one command (heredoc bodies are skipped, not counted).
const MAX_TOKENS: usize = 8192;
/// Nesting of `bash -c '...'` scripts followed.
const MAX_NESTING: u8 = 3;
/// Most variables remembered from `NAME=value` within one command.
const MAX_VARS: usize = 32;

/// The output-producing pipelines of a shell command run in `cwd`, in order.
/// A `cd` changes the folder later relative paths join to.
pub(crate) fn classify_shell(script: &str, cwd: Option<&Path>) -> Vec<ShellSegment> {
    let mut state = EvalState {
        base: cwd.map(|cwd| normalize_lexically(&cwd.to_string_lossy())),
        vars: Vec::new(),
    };
    let mut out = Vec::new();
    eval_script(script, &mut state, &mut out, 0);
    out
}

struct EvalState {
    /// The folder relative paths join to; `None` when unknown.
    base: Option<String>,
    vars: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Word {
    text: String,
    /// Holds an expansion (`$x`, `$(..)`, backticks) the lexer did not resolve.
    dynamic: bool,
    /// Holds an unquoted glob character.
    glob: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Redir {
    /// `>`, `>>`, `>|` on standard output (fd 1 or none) or `&>`.
    StdoutToFile,
    /// Any redirect of another descriptor, or `>&N` duplication.
    Other,
    /// `< file`.
    Input,
    /// `<<WORD` (body skipped) or `<<< word`.
    HereDoc,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Word(Word),
    /// Redirect plus its target word, when it takes one.
    Redirect(Redir, Option<Word>),
    Pipe,
    /// `&&`, `||`, `;`, `&`, newline, `(`, `)`.
    Separator,
}

struct Lexer<'a> {
    src: &'a str,
    pos: usize,
    pending_heredocs: Vec<(String, bool)>,
}

impl<'a> Lexer<'a> {
    fn peek(&self) -> Option<char> {
        self.src[self.pos..].chars().next()
    }

    fn peek_at(&self, offset: usize) -> Option<char> {
        self.src[self.pos..].chars().nth(offset)
    }

    fn bump(&mut self) -> Option<char> {
        let ch = self.peek()?;
        self.pos += ch.len_utf8();
        Some(ch)
    }

    fn starts_with(&self, text: &str) -> bool {
        self.src[self.pos..].starts_with(text)
    }

    /// Skip heredoc bodies that start after the newline just read.
    fn skip_heredoc_bodies(&mut self) {
        for (delimiter, strip_tabs) in std::mem::take(&mut self.pending_heredocs) {
            loop {
                if self.pos >= self.src.len() {
                    return;
                }
                let rest = &self.src[self.pos..];
                let end = rest.find('\n').map_or(rest.len(), |index| index + 1);
                let line = rest[..end].trim_end_matches(['\n', '\r']);
                self.pos += end;
                let line = if strip_tabs {
                    line.trim_start_matches('\t')
                } else {
                    line
                };
                if line.trim_end() == delimiter {
                    break;
                }
            }
        }
    }

    /// One word starting at the current position (quotes and expansions
    /// joined). Returns `None` at an operator or the end.
    fn word(&mut self) -> Option<Word> {
        let mut word = Word {
            text: String::new(),
            dynamic: false,
            glob: false,
        };
        let mut any = false;
        while let Some(ch) = self.peek() {
            match ch {
                ' ' | '\t' | '\n' | '\r' | ';' | '&' | '|' | '(' | ')' | '<' | '>' => break,
                '\'' => {
                    self.bump();
                    while let Some(ch) = self.bump() {
                        if ch == '\'' {
                            break;
                        }
                        word.text.push(ch);
                    }
                }
                '"' => {
                    self.bump();
                    while let Some(ch) = self.bump() {
                        match ch {
                            '"' => break,
                            '\\' => {
                                if let Some(next) = self.bump() {
                                    if !matches!(next, '"' | '\\' | '$' | '`' | '\n') {
                                        word.text.push('\\');
                                    }
                                    if next != '\n' {
                                        word.text.push(next);
                                    }
                                }
                            }
                            '$' | '`' => {
                                self.pos -= 1;
                                self.expansion(&mut word);
                            }
                            _ => word.text.push(ch),
                        }
                    }
                }
                '\\' => {
                    self.bump();
                    match self.bump() {
                        Some('\n') | None => {}
                        Some(next) => word.text.push(next),
                    }
                }
                '$' | '`' => self.expansion(&mut word),
                '*' | '?' | '[' => {
                    self.bump();
                    word.glob = true;
                    word.text.push(ch);
                }
                _ => {
                    self.bump();
                    word.text.push(ch);
                }
            }
            any = true;
        }
        any.then_some(word)
    }

    /// `$name`, `${..}`, `$(..)`, `$'..'`, or a backtick span, kept as text.
    fn expansion(&mut self, word: &mut Word) {
        let start = self.pos;
        let first = self.bump();
        if first == Some('`') {
            while let Some(ch) = self.bump() {
                if ch == '`' {
                    break;
                }
            }
            word.dynamic = true;
            word.text.push_str(&self.src[start..self.pos]);
            return;
        }
        match self.peek() {
            Some('\'') => {
                // ANSI-C quoting: literal text with escapes.
                self.bump();
                while let Some(ch) = self.bump() {
                    match ch {
                        '\'' => break,
                        '\\' => {
                            self.bump();
                        }
                        _ => word.text.push(ch),
                    }
                }
                return;
            }
            Some('(') | Some('{') => {
                let (open, close) = if self.peek() == Some('(') {
                    ('(', ')')
                } else {
                    ('{', '}')
                };
                let mut depth = 0usize;
                while let Some(ch) = self.bump() {
                    if ch == open {
                        depth += 1;
                    } else if ch == close {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                }
            }
            Some(ch) if ch.is_ascii_alphanumeric() || ch == '_' => {
                while self
                    .peek()
                    .is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_')
                {
                    self.bump();
                }
            }
            Some(ch) if "@*#?$!-".contains(ch) => {
                self.bump();
            }
            _ => {
                // A lone `$` is literal.
                word.text.push('$');
                return;
            }
        }
        word.dynamic = true;
        word.text.push_str(&self.src[start..self.pos]);
    }

    fn redirect_target(&mut self) -> Option<Word> {
        while matches!(self.peek(), Some(' ' | '\t')) {
            self.bump();
        }
        self.word()
    }

    fn tokens(mut self) -> Vec<Tok> {
        let mut tokens = Vec::new();
        while tokens.len() < MAX_TOKENS {
            let Some(ch) = self.peek() else { break };
            match ch {
                ' ' | '\t' | '\r' => {
                    self.bump();
                }
                '\n' => {
                    self.bump();
                    self.skip_heredoc_bodies();
                    tokens.push(Tok::Separator);
                }
                '#' => {
                    while self.peek().is_some_and(|ch| ch != '\n') {
                        self.bump();
                    }
                }
                ';' | '(' | ')' => {
                    self.bump();
                    tokens.push(Tok::Separator);
                }
                '&' => {
                    if self.starts_with("&>") {
                        self.pos += 2;
                        if self.peek() == Some('>') {
                            self.bump();
                        }
                        let target = self.redirect_target();
                        tokens.push(Tok::Redirect(Redir::StdoutToFile, target));
                    } else {
                        self.bump();
                        if self.peek() == Some('&') {
                            self.bump();
                        }
                        tokens.push(Tok::Separator);
                    }
                }
                '|' => {
                    self.bump();
                    match self.peek() {
                        Some('|') => {
                            self.bump();
                            tokens.push(Tok::Separator);
                        }
                        Some('&') => {
                            self.bump();
                            tokens.push(Tok::Pipe);
                        }
                        _ => tokens.push(Tok::Pipe),
                    }
                }
                '<' | '>' => tokens.push(self.redirect(None)),
                '0'..='9' if self.fd_redirect_ahead() => {
                    let fd = self.bump().and_then(|ch| ch.to_digit(10));
                    tokens.push(self.redirect(fd));
                }
                _ => match self.word() {
                    Some(word) => tokens.push(Tok::Word(word)),
                    None => {
                        self.bump();
                    }
                },
            }
        }
        tokens
    }

    /// A single digit followed by `<` or `>` (`2>`, `1>>`, `0<`).
    fn fd_redirect_ahead(&self) -> bool {
        matches!(self.peek_at(1), Some('<' | '>'))
    }

    fn redirect(&mut self, fd: Option<u32>) -> Tok {
        if self.starts_with("<<<") {
            self.pos += 3;
            let _ = self.redirect_target();
            return Tok::Redirect(Redir::HereDoc, None);
        }
        if self.starts_with("<<") {
            self.pos += 2;
            let strip_tabs = self.peek() == Some('-');
            if strip_tabs {
                self.bump();
            }
            if let Some(delimiter) = self.redirect_target() {
                self.pending_heredocs.push((delimiter.text, strip_tabs));
            }
            return Tok::Redirect(Redir::HereDoc, None);
        }
        if self.starts_with("<>") || self.starts_with("<&") || self.starts_with(">&") {
            let input = self.starts_with("<");
            self.pos += 2;
            let target = self.redirect_target();
            // `>&2`, `2>&1`, `<&0`: duplication; `>&file` is a file redirect.
            let duplicate = target
                .as_ref()
                .is_some_and(|word| word.text == "-" || word.text.parse::<u32>().is_ok());
            let kind = if input || duplicate || fd.is_some_and(|fd| fd != 1) {
                Redir::Other
            } else {
                Redir::StdoutToFile
            };
            return Tok::Redirect(kind, target);
        }
        if self.starts_with("<") {
            self.bump();
            let target = self.redirect_target();
            return Tok::Redirect(
                if fd.map_or(true, |fd| fd == 0) {
                    Redir::Input
                } else {
                    Redir::Other
                },
                target,
            );
        }
        // `>`, `>>`, `>|`.
        self.bump();
        if matches!(self.peek(), Some('>' | '|')) {
            self.bump();
        }
        let target = self.redirect_target();
        let kind = if fd.map_or(true, |fd| fd == 1) {
            Redir::StdoutToFile
        } else {
            Redir::Other
        };
        Tok::Redirect(kind, target)
    }
}

/// One simple command: its words and redirects.
#[derive(Debug, Default)]
struct SimpleCommand {
    words: Vec<Word>,
    stdout_to_file: bool,
    heredoc: bool,
    inputs: Vec<Word>,
}

fn eval_script(script: &str, state: &mut EvalState, out: &mut Vec<ShellSegment>, depth: u8) {
    let tokens = Lexer {
        src: script,
        pos: 0,
        pending_heredocs: Vec::new(),
    }
    .tokens();
    let mut pipeline: Vec<SimpleCommand> = vec![SimpleCommand::default()];
    for token in tokens.into_iter().chain([Tok::Separator]) {
        match token {
            Tok::Word(word) => pipeline.last_mut().expect("never empty").words.push(word),
            Tok::Redirect(kind, target) => {
                let command = pipeline.last_mut().expect("never empty");
                match kind {
                    Redir::StdoutToFile => command.stdout_to_file = true,
                    Redir::HereDoc => command.heredoc = true,
                    Redir::Input => command.inputs.extend(target),
                    Redir::Other => {}
                }
            }
            Tok::Pipe => pipeline.push(SimpleCommand::default()),
            Tok::Separator => {
                let stages = std::mem::replace(&mut pipeline, vec![SimpleCommand::default()]);
                eval_pipeline(stages, state, out, depth);
            }
        }
        if out.len() >= MAX_SEGMENTS {
            return;
        }
    }
}

/// How one stage of a pipeline counts.
enum Stage {
    /// Produces nothing the model reads (`cd`, assignments, `mkdir`, writes).
    Silent,
    /// Reshapes its input (`head`, `grep x`, `sort` with no file).
    Filter,
    Class(ShellClass, Vec<String>),
    /// A nested `sh -c` script's own segments.
    Nested(Vec<ShellSegment>),
}

fn eval_pipeline(
    stages: Vec<SimpleCommand>,
    state: &mut EvalState,
    out: &mut Vec<ShellSegment>,
    depth: u8,
) {
    let stages: Vec<SimpleCommand> = stages
        .into_iter()
        .filter(|stage| !stage.words.is_empty() || stage.heredoc || !stage.inputs.is_empty())
        .collect();
    let Some(last) = stages.last() else {
        return;
    };
    let reaches_model = !last.stdout_to_file;
    let single = stages.len() == 1;
    let mut result: Option<(ShellClass, Vec<String>)> = None;
    let mut extra_reads: Vec<String> = Vec::new();
    let mut prints = false;
    for (index, stage) in stages.into_iter().enumerate() {
        let stage = eval_command(stage, index, state, depth);
        prints |= !matches!(stage, Stage::Silent);
        match stage {
            Stage::Silent | Stage::Filter => {}
            Stage::Nested(segments) => {
                if single {
                    if reaches_model {
                        out.extend(segments);
                    }
                    return;
                }
                if result.is_none() {
                    result = segments
                        .into_iter()
                        .next()
                        .map(|segment| (segment.class, segment.paths));
                }
            }
            Stage::Class(class, paths) => match &mut result {
                None => result = Some((class, paths)),
                Some((ShellClass::Read, _)) if class == ShellClass::Read => {
                    extra_reads.extend(paths)
                }
                Some(_) => {}
            },
        }
    }
    if !reaches_model || !prints {
        return;
    }
    let (class, mut paths) = result.unwrap_or((ShellClass::Other, Vec::new()));
    if class == ShellClass::Read {
        paths.extend(extra_reads);
        let mut seen = std::collections::BTreeSet::new();
        paths.retain(|path| seen.insert(path.clone()));
        paths.truncate(MAX_SHELL_PATH_TOKENS);
    } else {
        paths.clear();
    }
    out.push(ShellSegment { class, paths });
}

/// Replace `$NAME` and `${NAME}` from the command's own assignments; `None`
/// when any other expansion is left.
fn resolve(word: &Word, state: &EvalState) -> Option<String> {
    if !word.dynamic {
        return Some(word.text.clone());
    }
    let text = word.text.as_str();
    let mut resolved = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('$') {
        resolved.push_str(&rest[..at]);
        let after = &rest[at + 1..];
        let (name, used) = match after.strip_prefix('{') {
            Some(inner) => {
                let end = inner.find('}')?;
                (&inner[..end], end + 2)
            }
            None => {
                let end = after
                    .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
                    .unwrap_or(after.len());
                (&after[..end], end)
            }
        };
        let (_, value) = state.vars.iter().rev().find(|(known, _)| known == name)?;
        resolved.push_str(value);
        rest = &after[used..];
    }
    resolved.push_str(rest);
    (!resolved.contains('`')).then_some(resolved)
}

fn is_assignment(text: &str) -> Option<(&str, &str)> {
    let (name, value) = text.split_once('=')?;
    (!name.is_empty()
        && !name.starts_with(|ch: char| ch.is_ascii_digit())
        && name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_'))
    .then_some((name, value))
}

fn set_var(state: &mut EvalState, name: &str, value: Option<String>) {
    state.vars.retain(|(known, _)| known != name);
    if let Some(value) = value {
        if state.vars.len() < MAX_VARS {
            state.vars.push((name.to_string(), value));
        }
    }
}

/// The basename of a program word (`/usr/bin/git` -> `git`).
fn program_name(text: &str) -> &str {
    text.rsplit('/').next().unwrap_or(text)
}

const SHELLS: [&str; 6] = ["sh", "bash", "zsh", "dash", "ksh", "fish"];
const SILENT: [&str; 31] = [
    "cd", "pushd", "popd", "export", "set", "unset", "source", ".", "alias", "unalias", "true",
    "false", ":", "shopt", "trap", "wait", "sleep", "exit", "return", "umask", "ulimit", "mkdir",
    "touch", "rm", "rmdir", "mv", "cp", "ln", "chmod", "chown", "kill",
];
const SEARCH: [&str; 16] = [
    "grep", "egrep", "fgrep", "rg", "ag", "ack", "find", "fd", "fdfind", "locate", "mdfind", "ls",
    "tree", "exa", "eza", "lsd",
];
const READERS: [&str; 22] = [
    "cat", "head", "tail", "nl", "bat", "batcat", "less", "more", "tac", "sed", "awk", "gawk",
    "jq", "yq", "cut", "sort", "uniq", "column", "xxd", "od", "hexdump", "strings",
];
/// Programs that only reshape standard input when given no file.
const FILTERS: [&str; 6] = ["wc", "tr", "fold", "fmt", "rev", "paste"];
const BUILD_TOOLS: [&str; 44] = [
    "cargo",
    "rustc",
    "make",
    "gmake",
    "cmake",
    "ctest",
    "ninja",
    "meson",
    "bazel",
    "bazelisk",
    "buck",
    "buck2",
    "gradle",
    "gradlew",
    "mvn",
    "mvnw",
    "ant",
    "sbt",
    "xcodebuild",
    "pytest",
    "py.test",
    "tox",
    "nox",
    "jest",
    "vitest",
    "mocha",
    "ava",
    "tsc",
    "eslint",
    "prettier",
    "ruff",
    "mypy",
    "pyright",
    "black",
    "flake8",
    "pylint",
    "isort",
    "swiftlint",
    "swiftformat",
    "ktlint",
    "rubocop",
    "rspec",
    "phpunit",
    "clippy-driver",
];
/// Package runners whose subcommands build, test or install.
const PACKAGE_RUNNERS: [&str; 5] = ["npm", "pnpm", "yarn", "bun", "deno"];
const PACKAGE_BUILD_SUBCOMMANDS: [&str; 15] = [
    "test",
    "t",
    "run",
    "run-script",
    "build",
    "lint",
    "typecheck",
    "check",
    "ci",
    "install",
    "i",
    "add",
    "compile",
    "fmt",
    "format",
];
const PYTHON_BUILD_MODULES: [&str; 12] = [
    "pytest",
    "unittest",
    "mypy",
    "ruff",
    "black",
    "build",
    "pip",
    "tox",
    "nox",
    "compileall",
    "pyright",
    "flake8",
];

fn eval_command(command: SimpleCommand, index: usize, state: &mut EvalState, depth: u8) -> Stage {
    let SimpleCommand {
        words,
        stdout_to_file: _,
        heredoc,
        inputs,
    } = command;
    // Leading assignments, keywords and grouping words.
    let mut start = 0;
    let mut assignments = Vec::new();
    while let Some(word) = words.get(start) {
        if let Some((name, value)) = is_assignment(&word.text) {
            let value = resolve(
                &Word {
                    text: value.to_string(),
                    ..word.clone()
                },
                state,
            );
            assignments.push((name.to_string(), value));
            start += 1;
        } else if matches!(
            word.text.as_str(),
            "{" | "}" | "!" | "if" | "then" | "else" | "elif" | "do" | "while" | "until" | "time"
        ) && !word.dynamic
        {
            start += 1;
        } else {
            break;
        }
    }
    let words = &words[start..];
    let Some(first) = words.first() else {
        // An assignment-only command sets shell variables.
        for (name, value) in assignments {
            set_var(state, &name, value);
        }
        return if heredoc {
            Stage::Class(ShellClass::Other, Vec::new())
        } else {
            Stage::Silent
        };
    };
    if matches!(
        first.text.as_str(),
        "fi" | "done" | "esac" | "for" | "case" | "in"
    ) {
        return Stage::Silent;
    }
    eval_words(words, heredoc, &inputs, index, state, depth)
}

fn eval_words(
    words: &[Word],
    heredoc: bool,
    inputs: &[Word],
    index: usize,
    state: &mut EvalState,
    depth: u8,
) -> Stage {
    let Some(first) = words.first() else {
        return Stage::Silent;
    };
    let program = program_name(&first.text);
    let args = &words[1..];
    let rest_after = |skip: usize| &words[skip.min(words.len())..];
    match program {
        "cd" | "pushd" => {
            let target = args
                .iter()
                .find(|word| !word.text.starts_with('-') || word.text == "-");
            state.base = match target.and_then(|word| resolve(word, state)) {
                Some(dir) if dir != "-" && !dir.starts_with('~') => {
                    join(state.base.as_deref(), &dir)
                }
                _ => None,
            };
            return Stage::Silent;
        }
        "popd" => {
            state.base = None;
            return Stage::Silent;
        }
        "export" | "declare" | "typeset" | "local" | "readonly" => {
            for word in args {
                if let Some((name, value)) = is_assignment(&word.text) {
                    let value = resolve(
                        &Word {
                            text: value.to_string(),
                            ..word.clone()
                        },
                        state,
                    );
                    set_var(state, name, value);
                }
            }
            return Stage::Silent;
        }
        // Wrappers: classify the command they run.
        "sudo" | "doas" | "nohup" | "command" | "builtin" | "exec" | "unbuffer" | "caffeinate"
        | "stdbuf" | "nice" | "ionice" | "timeout" | "gtimeout" | "xargs" | "env" | "time" => {
            let mut skip = 1;
            while let Some(word) = words.get(skip) {
                let text = word.text.as_str();
                if program == "env" && is_assignment(text).is_some() {
                    skip += 1;
                } else if program == "env" && (text == "-C" || text == "--chdir") {
                    let dir = words.get(skip + 1).and_then(|word| resolve(word, state));
                    state.base = dir.and_then(|dir| join(state.base.as_deref(), &dir));
                    skip += 2;
                } else if text.starts_with('-') {
                    let takes_value = matches!(
                        (program, text),
                        ("sudo", "-u" | "-g" | "-C" | "-D" | "-h" | "-p")
                            | ("nice", "-n")
                            | ("ionice", "-c" | "-n")
                            | (
                                "timeout" | "gtimeout",
                                "-s" | "-k" | "--signal" | "--kill-after"
                            )
                            | (
                                "xargs",
                                "-n" | "-I" | "-P" | "-L" | "-d" | "-s" | "-E" | "-a"
                            )
                            | ("stdbuf", "-i" | "-o" | "-e")
                            | ("env", "-u" | "-S")
                            | ("caffeinate", "-t" | "-w")
                    );
                    skip += if takes_value { 2 } else { 1 };
                } else if matches!(program, "timeout" | "gtimeout")
                    && text.starts_with(|ch: char| ch.is_ascii_digit())
                {
                    skip += 1;
                    break;
                } else {
                    break;
                }
            }
            return eval_words(rest_after(skip), heredoc, inputs, index, state, depth);
        }
        "uv" | "poetry" | "pipenv" | "pdm" | "rye" | "hatch" | "bundle" | "pixi"
            if args
                .first()
                .is_some_and(|word| matches!(word.text.as_str(), "run" | "exec")) =>
        {
            let mut skip = 2;
            while let Some(word) = words.get(skip) {
                let text = word.text.as_str();
                if !text.starts_with('-') {
                    break;
                }
                let takes_value = matches!(
                    text,
                    "--with"
                        | "--project"
                        | "--directory"
                        | "--python"
                        | "-p"
                        | "--package"
                        | "--group"
                        | "--extra"
                        | "--env-file"
                        | "-e"
                        | "--index"
                        | "--from"
                );
                skip += if takes_value { 2 } else { 1 };
            }
            if words.get(skip).is_none() {
                return Stage::Class(ShellClass::TestsBuilds, Vec::new());
            }
            return eval_words(rest_after(skip), heredoc, inputs, index, state, depth);
        }
        "npx" | "bunx" | "pnpx" => {
            let skip = 1 + args
                .iter()
                .take_while(|word| word.text.starts_with('-'))
                .count();
            return eval_words(rest_after(skip), heredoc, inputs, index, state, depth);
        }
        "pnpm" | "yarn"
            if args
                .first()
                .is_some_and(|word| matches!(word.text.as_str(), "exec" | "dlx")) =>
        {
            return eval_words(rest_after(2), heredoc, inputs, index, state, depth);
        }
        _ => {}
    }
    if SHELLS.contains(&program) {
        // `bash -lc 'script'`: classify the script itself.
        let flag = args.iter().position(|word| {
            word.text.starts_with('-')
                && word.text.len() > 1
                && word.text[1..].chars().all(|ch| ch.is_ascii_alphabetic())
                && word.text.contains('c')
        });
        if let Some(flag) = flag {
            if depth >= MAX_NESTING {
                return Stage::Class(ShellClass::Other, Vec::new());
            }
            // A quoted script is one word; a command array joined by spaces
            // (`zsh -lc cat a.md`) leaves the script as the remaining words.
            let script = match &args[flag + 1..] {
                [] => return Stage::Class(ShellClass::Other, Vec::new()),
                [script] => script.text.clone(),
                [script, ..] if script.text.contains(' ') => script.text.clone(),
                words => words
                    .iter()
                    .map(|word| word.text.as_str())
                    .collect::<Vec<_>>()
                    .join(" "),
            };
            let mut nested = EvalState {
                base: state.base.clone(),
                vars: state.vars.clone(),
            };
            let mut segments = Vec::new();
            eval_script(&script, &mut nested, &mut segments, depth + 1);
            return Stage::Nested(segments);
        }
        return Stage::Class(class_by_name(program), Vec::new());
    }
    if SILENT.contains(&program) {
        return Stage::Silent;
    }
    if program == "git" {
        return eval_git(args, state);
    }
    if program == "gh" {
        return Stage::Class(ShellClass::Git, Vec::new());
    }
    if SEARCH.contains(&program) {
        // `... | grep x` filters the stage before it.
        if index > 0 && matches!(program, "grep" | "egrep" | "fgrep" | "rg" | "ag" | "ack") {
            return Stage::Filter;
        }
        return Stage::Class(ShellClass::Search, Vec::new());
    }
    if program == "tee" {
        return Stage::Class(ShellClass::Other, Vec::new());
    }
    if READERS.contains(&program) {
        return eval_reader(program, args, heredoc, inputs, index, state);
    }
    if FILTERS.contains(&program) {
        return if index > 0 {
            Stage::Filter
        } else {
            Stage::Class(ShellClass::Other, Vec::new())
        };
    }
    if program == "perl"
        && args
            .iter()
            .any(|word| word.text.starts_with("-i") || word.text.starts_with("-pi"))
    {
        return Stage::Silent;
    }
    Stage::Class(class_of_program(program, args), Vec::new())
}

fn class_by_name(program: &str) -> ShellClass {
    if program.contains("test") {
        ShellClass::TestsBuilds
    } else {
        ShellClass::Other
    }
}

fn class_of_program(program: &str, args: &[Word]) -> ShellClass {
    let sub = args
        .iter()
        .find(|word| !word.text.starts_with('-'))
        .map(|word| word.text.as_str());
    let builds = BUILD_TOOLS.contains(&program)
        || program.starts_with("cargo-")
        || (PACKAGE_RUNNERS.contains(&program)
            && sub.is_some_and(|sub| PACKAGE_BUILD_SUBCOMMANDS.contains(&sub)))
        || (matches!(program, "go" | "swift" | "dotnet")
            && sub.is_some_and(|sub| {
                matches!(
                    sub,
                    "build" | "test" | "vet" | "install" | "generate" | "package"
                )
            }))
        || (matches!(program, "pip" | "pip3") && sub == Some("install"))
        || (program == "uv"
            && sub.is_some_and(|sub| matches!(sub, "sync" | "pip" | "lock" | "build")))
        || (program == "poetry"
            && sub.is_some_and(|sub| matches!(sub, "install" | "build" | "lock")))
        || (program.starts_with("python")
            && args
                .windows(2)
                .find(|pair| pair[0].text == "-m")
                .is_some_and(|pair| PYTHON_BUILD_MODULES.contains(&pair[1].text.as_str())))
        || (program == "playwright" && sub == Some("test"));
    if builds {
        ShellClass::TestsBuilds
    } else {
        class_by_name(program)
    }
}

/// `git [-C dir] [global flags] <subcommand> ...`.
fn eval_git(args: &[Word], state: &mut EvalState) -> Stage {
    let mut dir = state.base.clone();
    let mut index = 0;
    while let Some(word) = args.get(index) {
        let text = word.text.as_str();
        if text == "-C" {
            dir = args
                .get(index + 1)
                .and_then(|word| resolve(word, state))
                .and_then(|path| join(dir.as_deref(), &path));
            index += 2;
        } else if matches!(text, "-c" | "--git-dir" | "--work-tree" | "--namespace") {
            index += 2;
        } else if text.starts_with('-') {
            index += 1;
        } else {
            break;
        }
    }
    let Some(subcommand) = args.get(index).map(|word| word.text.as_str()) else {
        return Stage::Class(ShellClass::Git, Vec::new());
    };
    let rest = &args[index + 1..];
    match subcommand {
        "grep" | "ls-files" | "ls-tree" => Stage::Class(ShellClass::Search, Vec::new()),
        "show" | "cat-file" => {
            // `git show rev:path` prints the file at `rev`.
            let paths: Vec<String> = rest
                .iter()
                .filter(|word| !word.text.starts_with('-'))
                .filter_map(|word| resolve(word, state))
                .filter(|text| !text.contains("://"))
                .filter_map(|text| {
                    let (_, path) = text.split_once(':')?;
                    (!path.is_empty() && !path.starts_with('/'))
                        .then(|| join(dir.as_deref(), path.trim_start_matches("./")))
                        .flatten()
                })
                .take(MAX_SHELL_PATH_TOKENS)
                .collect();
            if paths.is_empty() {
                Stage::Class(ShellClass::Git, Vec::new())
            } else {
                Stage::Class(ShellClass::Read, paths)
            }
        }
        _ => Stage::Class(ShellClass::Git, Vec::new()),
    }
}

/// Flags of reader programs that take a separate value.
fn reader_flag_takes_value(program: &str, flag: &str) -> bool {
    match program {
        "head" | "tail" => matches!(flag, "-n" | "-c" | "--lines" | "--bytes" | "-s"),
        "sed" => matches!(flag, "-e" | "-f" | "-l" | "--expression" | "--file"),
        "awk" | "gawk" => matches!(flag, "-f" | "-F" | "-v" | "-i" | "--file" | "--assign"),
        "jq" | "yq" => matches!(flag, "--indent" | "-L" | "--tab" | "-f" | "--from-file"),
        "cut" => matches!(flag, "-d" | "-f" | "-c" | "-b"),
        "sort" => matches!(flag, "-k" | "-t" | "-o" | "-S" | "-T" | "--key"),
        "uniq" => matches!(flag, "-f" | "-s" | "-w"),
        "column" => matches!(flag, "-s" | "-c" | "-o"),
        "xxd" | "od" | "hexdump" => {
            matches!(flag, "-l" | "-s" | "-c" | "-n" | "-g" | "-t" | "-j" | "-N")
        }
        "strings" => matches!(flag, "-n" | "-t"),
        "nl" => matches!(flag, "-w" | "-s" | "-v" | "-i" | "-b" | "-n"),
        "bat" | "batcat" => matches!(
            flag,
            "-l" | "--language"
                | "-r"
                | "--line-range"
                | "--style"
                | "--theme"
                | "-H"
                | "--highlight-line"
        ),
        _ => false,
    }
}

fn eval_reader(
    program: &str,
    args: &[Word],
    heredoc: bool,
    inputs: &[Word],
    index: usize,
    state: &EvalState,
) -> Stage {
    if program == "sed"
        && args
            .iter()
            .any(|word| word.text.starts_with("-i") || word.text == "--in-place")
    {
        // In-place edit: a write.
        return Stage::Silent;
    }
    if heredoc {
        // `cat <<EOF` prints the heredoc, not a file.
        return Stage::Class(ShellClass::Other, Vec::new());
    }
    // The first operand of these is a script or filter, not a file.
    let mut script_pending = match program {
        "sed" => !args.iter().any(|word| {
            matches!(word.text.as_str(), "-e" | "-f" | "--expression" | "--file")
                || word.text.starts_with("--expression=")
        }),
        "awk" | "gawk" => !args
            .iter()
            .any(|word| word.text == "-f" || word.text == "--file"),
        "jq" | "yq" => !args
            .iter()
            .any(|word| word.text == "-f" || word.text == "--from-file"),
        _ => false,
    };
    let mut operands: Vec<&Word> = Vec::new();
    let mut skip_next = 0usize;
    for word in args {
        if skip_next > 0 {
            skip_next -= 1;
            continue;
        }
        let text = word.text.as_str();
        if program.starts_with("jq") || program == "yq" {
            if matches!(text, "--arg" | "--argjson" | "--slurpfile" | "--rawfile") {
                skip_next = 2;
                continue;
            }
            if matches!(text, "--args" | "--jsonargs") {
                break;
            }
        }
        if text == "--" {
            continue;
        }
        if text.starts_with('-') && text.len() > 1 {
            if reader_flag_takes_value(program, text) {
                skip_next = 1;
            }
            continue;
        }
        if matches!(program, "head" | "tail") && text.starts_with('+') {
            continue;
        }
        if script_pending {
            script_pending = false;
            continue;
        }
        if matches!(program, "awk" | "gawk") && is_assignment(text).is_some() {
            continue;
        }
        operands.push(word);
    }
    operands.extend(inputs.iter());
    if operands.is_empty() {
        return if index > 0 {
            Stage::Filter
        } else {
            Stage::Class(ShellClass::Other, Vec::new())
        };
    }
    let paths = operands
        .into_iter()
        .filter(|word| !word.glob)
        .filter_map(|word| resolve(word, state))
        .filter(|text| text != "-" && !text.contains("://"))
        .filter_map(|text| join(state.base.as_deref(), &text))
        .take(MAX_SHELL_PATH_TOKENS)
        .collect();
    Stage::Class(ShellClass::Read, paths)
}

/// `raw` joined to `base` when relative and `base` is known, normalized
/// lexically; `~` paths and relative paths without a base stay as written.
fn join(base: Option<&str>, raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() || raw.len() > MAX_PATH_BYTES {
        return None;
    }
    if raw.starts_with('/') {
        return Some(normalize_lexically(raw));
    }
    if raw.starts_with('~') {
        return Some(raw.to_string());
    }
    match base {
        Some(base) => Some(normalize_lexically(&format!(
            "{}/{raw}",
            base.trim_end_matches('/')
        ))),
        None => Some(raw.strip_prefix("./").unwrap_or(raw).to_string()),
    }
}

/// Resolve `.` and `..` in an absolute path without touching the disk.
pub(crate) fn normalize_lexically(path: &str) -> String {
    if !path.starts_with('/') {
        return path.to_string();
    }
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            part => parts.push(part),
        }
    }
    format!("/{}", parts.join("/"))
}

/// `raw` joined to `base` (see `join`), for callers holding a `Path`.
pub(crate) fn join_to(base: Option<&Path>, raw: &str) -> Option<String> {
    let base = base.map(|base| normalize_lexically(&base.to_string_lossy()));
    join(base.as_deref(), raw)
}
