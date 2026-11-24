use super::{invalid_server, sleep_until, timed_out, Failure};
use ottto_protocol::{cloud_account_id, CLOUD_CONNECT_REGION};
use serde::{Deserialize, Deserializer};
use serde_json::Value;
use std::ffi::OsString;
use std::io::{self, Read};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use zeroize::Zeroizing;

const STS_ENDPOINT: &str = "https://sts.us-east-1.amazonaws.com";
const CF_ENDPOINT: &str = "https://cloudformation.us-east-1.amazonaws.com";
const CALL_CAP: Duration = Duration::from_secs(60);
const MAX_OUTPUT: u64 = 1024 * 1024;

pub(super) struct Aws {
    path: PathBuf,
    profile: Option<String>,
    verbose: bool,
}

pub(super) struct Session {
    credentials: Credentials,
    ca_bundle: Option<OsString>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Credentials {
    #[serde(deserialize_with = "secret")]
    access_key_id: Zeroizing<String>,
    #[serde(deserialize_with = "secret")]
    secret_access_key: Zeroizing<String>,
    #[serde(default, deserialize_with = "optional_secret")]
    session_token: Option<Zeroizing<String>>,
    expiration: Option<String>,
}

fn secret<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(deserializer).map(Zeroizing::new)
}

fn optional_secret<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Zeroizing<String>>, D::Error> {
    Option::<String>::deserialize(deserializer).map(|value| value.map(Zeroizing::new))
}

impl Session {
    pub(super) fn expires_soon(&self) -> bool {
        self.credentials
            .expiration
            .as_deref()
            .and_then(|date| OffsetDateTime::parse(date, &Rfc3339).ok())
            .is_some_and(|expires| expires - OffsetDateTime::now_utc() < time::Duration::minutes(5))
    }

    fn apply(&self, command: &mut Command) {
        command.env_clear().envs(
            std::env::vars_os().filter(|(key, _)| !key.to_string_lossy().starts_with("AWS_")),
        );
        let credentials = &self.credentials;
        let credential_env = [
            ("access_key_id", Some(credentials.access_key_id.as_str())),
            (
                "secret_access_key",
                Some(credentials.secret_access_key.as_str()),
            ),
            (
                "session_token",
                credentials.session_token.as_deref().map(String::as_str),
            ),
        ];
        command.envs(credential_env.into_iter().filter_map(|(name, value)| {
            value.map(|value| (format!("AWS_{}", name.to_ascii_uppercase()), value))
        }));
        command
            .env("AWS_CONFIG_FILE", "/dev/null")
            .env("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
            .env("AWS_IGNORE_CONFIGURED_ENDPOINT_URLS", "true")
            .env("AWS_EC2_METADATA_DISABLED", "true");
        if let Some(bundle) = &self.ca_bundle {
            command.env("AWS_CA_BUNDLE", bundle);
        }
    }
}

impl Aws {
    pub(super) fn resolve(
        profile: Option<String>,
        verbose: bool,
        deadline: Instant,
    ) -> Result<Self, Failure> {
        let path = aws_path().ok_or_else(|| {
            aws_failure(
                "aws_cli_missing",
                "Install AWS CLI v2 and run this command again.",
                "fix_aws_sign_in",
            )
        })?;
        let aws = Self {
            path,
            profile,
            verbose,
        };
        let mut command = aws.command();
        command.arg("--version");
        let output = run(command, deadline)?;
        if !output.status.success()
            || !(output.stdout.starts_with(b"aws-cli/2.")
                || output.stderr.starts_with(b"aws-cli/2."))
        {
            return Err(unsupported());
        }
        Ok(aws)
    }

    fn command(&self) -> Command {
        let mut command = Command::new(&self.path);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        command
    }

    fn configure(&self, args: &[&str], deadline: Instant) -> Result<Output, Failure> {
        let mut command = self.command();
        command
            .arg("configure")
            .args(args)
            .args(["--no-cli-pager", "--no-cli-auto-prompt"]);
        if let Some(profile) = &self.profile {
            command.arg(format!("--profile={profile}"));
        }
        run(command, deadline)
    }

    pub(super) fn export(&self, deadline: Instant) -> Result<Session, Failure> {
        let output = self.configure(&["export-credentials", "--format", "process"], deadline)?;
        if !output.status.success() {
            let error = output.error();
            if error.contains("Invalid choice") || error.contains("invalid choice") {
                return Err(unsupported());
            }
            if error.contains("config profile") && error.contains("could not be found") {
                return Err(aws_failure(
                    "aws_profile_invalid",
                    "The AWS CLI profile does not exist.",
                    "fix_flags",
                ));
            }
            return Err(not_signed_in());
        }
        let credentials: Credentials =
            serde_json::from_slice(&output.stdout).map_err(|_| not_signed_in())?;
        if credentials.access_key_id.is_empty()
            || credentials.secret_access_key.is_empty()
            || credentials
                .session_token
                .as_ref()
                .is_some_and(|token| token.is_empty())
            || credentials.expiration.as_deref().is_some_and(|expiration| {
                OffsetDateTime::parse(expiration, &Rfc3339)
                    .map_or(true, |date| date <= OffsetDateTime::now_utc())
            })
        {
            return Err(not_signed_in());
        }
        let bundle_output = self.configure(&["get", "ca_bundle"], deadline)?;
        let bundle = std::env::var_os("AWS_CA_BUNDLE")
            .filter(|path| !path.is_empty())
            .or_else(|| {
                if !bundle_output.status.success() {
                    return None;
                }
                let value = std::str::from_utf8(&bundle_output.stdout).ok()?.trim();
                (!value.is_empty()).then(|| OsString::from(value))
            });
        Ok(Session {
            credentials,
            ca_bundle: bundle,
        })
    }

    pub(super) fn identity(&self, session: &Session, deadline: Instant) -> Result<String, Failure> {
        let output = self.api(
            session,
            "sts",
            STS_ENDPOINT,
            &["get-caller-identity"],
            deadline,
        )?;
        let value = self.json(output)?;
        value["Account"]
            .as_str()
            .filter(|account| cloud_account_id(account))
            .map(str::to_owned)
            .ok_or_else(invalid_server)
    }

    pub(super) fn cloudformation(
        &self,
        session: &Session,
        args: &[&str],
        deadline: Instant,
    ) -> Result<Output, Failure> {
        self.api(session, "cloudformation", CF_ENDPOINT, args, deadline)
    }

    fn api(
        &self,
        session: &Session,
        service: &str,
        endpoint: &str,
        args: &[&str],
        deadline: Instant,
    ) -> Result<Output, Failure> {
        let mut command = self.command();
        session.apply(&mut command);
        command
            .env("AWS_PAGER", "")
            .env("AWS_CLI_AUTO_PROMPT", "off")
            .arg(service)
            .args(args)
            .args([
                "--output",
                "json",
                "--no-cli-pager",
                "--region",
                CLOUD_CONNECT_REGION,
                "--endpoint-url",
                endpoint,
            ]);
        run(command, deadline)
    }

    pub(super) fn json(&self, output: Output) -> Result<Value, Failure> {
        if !output.status.success() {
            let error = output.error();
            if self.verbose {
                eprintln!("{}", crate::sanitize_for_terminal(&error));
            }
            if [
                "ExpiredToken",
                "InvalidClientTokenId",
                "UnrecognizedClientException",
                "Unable to locate credentials",
                "InvalidAccessKeyId",
            ]
            .iter()
            .any(|code| error.contains(code))
            {
                return Err(not_signed_in());
            }
            if error.contains("AccessDenied") || error.contains("UnauthorizedOperation") {
                return Err(access_denied());
            }
            return Err(aws_failure("aws_request_failed", "AWS CLI did not complete the request. Run again or use --verbose for AWS error text.", "run_again"));
        }
        serde_json::from_slice(&output.stdout).map_err(|_| invalid_server())
    }
}

pub(super) fn profile_valid(profile: &str) -> bool {
    (1..=64).contains(&profile.len())
        && profile
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._@+=-".contains(&byte))
}

fn aws_path() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    let cwd = std::env::current_dir().ok()?.canonicalize().ok()?;
    std::env::split_paths(&path)
        .filter(|dir| dir.is_absolute())
        .filter_map(|dir| {
            let dir = dir.canonicalize().ok()?;
            if dir == cwd {
                return None;
            }
            dir.join("aws").canonicalize().ok()
        })
        .find(|path| path.parent() != Some(cwd.as_path()) && is_executable(path))
}

fn is_executable(path: &PathBuf) -> bool {
    let Ok(metadata) = path.metadata() else {
        return false;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    metadata.is_file()
}

pub(super) struct Output {
    pub(super) status: ExitStatus,
    stdout: Zeroizing<Vec<u8>>,
    stderr: Zeroizing<Vec<u8>>,
}

impl Output {
    pub(super) fn error(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.stderr)
    }
}

type PipeData = io::Result<Zeroizing<Vec<u8>>>;

fn read_pipe(pipe: impl Read + Send + 'static) -> mpsc::Receiver<PipeData> {
    let (tx, rx) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut bytes = Zeroizing::new(Vec::new());
        let result = pipe
            .take(MAX_OUTPUT + 1)
            .read_to_end(&mut bytes)
            .and_then(|length| {
                if length as u64 > MAX_OUTPUT {
                    return Err(io::Error::other("AWS output too large"));
                }
                Ok(bytes)
            });
        let _ = tx.send(result);
    });
    rx
}

fn take_pipe(
    pipe: &mpsc::Receiver<PipeData>,
    deadline: Instant,
) -> Result<Zeroizing<Vec<u8>>, Failure> {
    match pipe.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        Ok(Ok(bytes)) => Ok(bytes),
        Ok(Err(_)) | Err(mpsc::RecvTimeoutError::Disconnected) => Err(invalid_server()),
        Err(mpsc::RecvTimeoutError::Timeout) => Err(timed_out()),
    }
}

fn run(mut command: Command, deadline: Instant) -> Result<Output, Failure> {
    let deadline = deadline.min(Instant::now() + CALL_CAP);
    if Instant::now() >= deadline {
        return Err(timed_out());
    }
    let mut child = command.spawn().map_err(|_| {
        aws_failure(
            "aws_cli_missing",
            "Unable to start AWS CLI v2.",
            "fix_aws_sign_in",
        )
    })?;
    // Command owns a copy of the session environment until it is dropped.
    drop(command);
    let stdout = read_pipe(child.stdout.take().expect("piped stdout"));
    let stderr = read_pipe(child.stderr.take().expect("piped stderr"));
    let result = (|| {
        let stdout = take_pipe(&stdout, deadline)?;
        let stderr = take_pipe(&stderr, deadline)?;
        loop {
            if let Some(status) = child.try_wait().map_err(|_| invalid_server())? {
                return Ok(Output {
                    status,
                    stdout,
                    stderr,
                });
            }
            sleep_until(deadline, Duration::from_millis(25))?;
        }
    })();
    if result.is_err() {
        stop_child(&mut child);
    }
    result
}

fn stop_child(child: &mut Child) {
    #[cfg(unix)]
    if let Ok(pid) = i32::try_from(child.id()) {
        // The non-reaped child is the leader of its own process group.
        unsafe { libc::kill(-pid, libc::SIGKILL) };
    }
    let _ = child.kill();
    // A blocked kernel I/O operation must not extend the frontend deadline.
    let _ = child.try_wait();
}

fn aws_failure(code: &str, message: &str, action: &str) -> Failure {
    Failure::new(code, message, action)
}

fn unsupported() -> Failure {
    aws_failure(
        "aws_cli_unsupported",
        "Update to an AWS CLI v2 release that supports export-credentials.",
        "fix_aws_sign_in",
    )
}

fn not_signed_in() -> Failure {
    aws_failure(
        "aws_not_signed_in",
        "Run aws sso login or sign in to AWS, then run this again.",
        "fix_aws_sign_in",
    )
}

pub(super) fn access_denied() -> Failure {
    aws_failure(
        "aws_access_denied",
        "AWS denied permission to create or read the stack.",
        "fix_aws_permissions",
    )
}
