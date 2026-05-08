use crate::config::CONFIG;
use std::ffi::{OsStr, OsString};
use std::io::{self, Read};
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{ExitStatus, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// Small wrapper around external command execution.
///
/// All external process calls should go through this type so checks share the
/// same timeout and can be globally disabled for pure Rust/procfs runs.
pub struct Command {
    program: OsString,
    args: Vec<OsString>,
    stdin: Option<Stdio>,
    stdout: Option<Stdio>,
    stderr: Option<Stdio>,
}

impl Command {
    pub fn new<S: AsRef<OsStr>>(program: S) -> Self {
        Self {
            program: program.as_ref().to_os_string(),
            args: Vec::new(),
            stdin: None,
            stdout: None,
            stderr: None,
        }
    }

    pub fn arg<S: AsRef<OsStr>>(&mut self, arg: S) -> &mut Self {
        self.args.push(arg.as_ref().to_os_string());
        self
    }

    pub fn args<I, S>(&mut self, args: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.args
            .extend(args.into_iter().map(|arg| arg.as_ref().to_os_string()));
        self
    }

    pub fn stdin<T: Into<Stdio>>(&mut self, cfg: T) -> &mut Self {
        self.stdin = Some(cfg.into());
        self
    }

    pub fn stdout<T: Into<Stdio>>(&mut self, cfg: T) -> &mut Self {
        self.stdout = Some(cfg.into());
        self
    }

    pub fn stderr<T: Into<Stdio>>(&mut self, cfg: T) -> &mut Self {
        self.stderr = Some(cfg.into());
        self
    }

    pub fn output(&mut self) -> io::Result<Output> {
        if !external_commands_enabled() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "external commands disabled: {}",
                    self.program.to_string_lossy()
                ),
            ));
        }

        if let Some(output) = emulate_command_builtin(&self.program, &self.args) {
            return output;
        }

        let mut command = std::process::Command::new(&self.program);
        command.args(&self.args);
        command.stdin(self.stdin.take().unwrap_or_else(Stdio::null));
        command.stdout(self.stdout.take().unwrap_or_else(Stdio::piped));
        command.stderr(self.stderr.take().unwrap_or_else(Stdio::piped));

        run_with_timeout(command, command_timeout())
    }
}

fn external_commands_enabled() -> bool {
    CONFIG
        .get()
        .map(|config| config.external_commands)
        .unwrap_or(true)
}

fn command_timeout() -> Duration {
    CONFIG
        .get()
        .map(|config| Duration::from_secs(config.command_timeout_secs))
        .unwrap_or_else(|| Duration::from_secs(3))
}

fn run_with_timeout(mut command: std::process::Command, timeout: Duration) -> io::Result<Output> {
    let mut child = command.spawn()?;
    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();

    let stdout_reader = thread::spawn(move || read_pipe(stdout.take()));
    let stderr_reader = thread::spawn(move || read_pipe(stderr.take()));

    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }

        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("external command timed out after {}s", timeout.as_secs()),
            ));
        }

        thread::sleep(Duration::from_millis(20));
    };

    let stdout = stdout_reader
        .join()
        .unwrap_or_else(|_| Err(io::Error::other("stdout reader panicked")))?;
    let stderr = stderr_reader
        .join()
        .unwrap_or_else(|_| Err(io::Error::other("stderr reader panicked")))?;

    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

fn read_pipe<R: Read>(pipe: Option<R>) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    if let Some(mut pipe) = pipe {
        pipe.read_to_end(&mut output)?;
    }
    Ok(output)
}

fn emulate_command_builtin(program: &OsStr, args: &[OsString]) -> Option<io::Result<Output>> {
    if program != "command" || args.first().map(|arg| arg.as_os_str()) != Some(OsStr::new("-v")) {
        return None;
    }

    let Some(name) = args.get(1).and_then(|arg| arg.to_str()) else {
        return Some(Ok(output_with_status(2, Vec::new(), Vec::new())));
    };

    if let Some(path) = find_in_path(name) {
        let mut stdout = path.to_string_lossy().as_bytes().to_vec();
        stdout.push(b'\n');
        return Some(Ok(output_with_status(0, stdout, Vec::new())));
    }

    Some(Ok(output_with_status(1, Vec::new(), Vec::new())))
}

fn find_in_path(name: &str) -> Option<PathBuf> {
    if name.contains('/') {
        let path = PathBuf::from(name);
        return path.is_file().then_some(path);
    }

    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|path| path.is_file())
}

fn output_with_status(code: i32, stdout: Vec<u8>, stderr: Vec<u8>) -> Output {
    Output {
        status: exit_status(code),
        stdout,
        stderr,
    }
}

fn exit_status(code: i32) -> ExitStatus {
    ExitStatus::from_raw(code << 8)
}
