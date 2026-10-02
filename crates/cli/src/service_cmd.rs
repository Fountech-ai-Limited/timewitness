//! `timewitness agent install` and `timewitness agent uninstall`: the agent as a service that starts
//! at boot.
//!
//! An agent that runs only while somebody keeps a terminal open has no bound the morning after a
//! reboot, and a stranger will not keep a terminal open for us. So this hands the agent to whatever
//! starts things at boot on this machine: a systemd unit on Linux, a launchd daemon on macOS and a
//! scheduled task with a boot trigger on Windows. What it starts is the same `timewitness agent` a
//! person runs by hand, with the same options, writing its endpoint to a folder of its own so that
//! `timewitness status --agent` has something to be pointed at.
//!
//! The folder is fixed rather than chosen. A service that could be pointed anywhere would need the
//! installer to make and hand over folders it did not own, and the uninstaller to delete a file it
//! was only told the name of, both as an administrator. Somebody who wants the endpoint elsewhere
//! runs `timewitness agent --endpoint` under whatever they already use to start things.
//!
//! ## It still never sets the clock
//!
//! Installing is the one act in this tool that has to run as an administrator, which is the moment a
//! reader is most entitled to ask what else the privilege is used for. The answer is nothing: it
//! writes one definition and asks the platform to load it. The service itself runs as the account
//! that installed it and not as root, because nothing the agent does needs more.
//!
//! On Linux the unit takes the permission away as well. `ProtectClock` and an empty capability set
//! mean the kernel refuses the agent a clock change, so the promise does not rest on the code alone.
//! On macOS only root may set the clock and the daemon does not run as root. Windows has no switch a
//! task definition can set, so there the promise rests on the code, and `crates/architecture` holds
//! every line of it to that.
//!
//! ## Failing at boot
//!
//! A service that fails at boot stops and stays stopped rather than starting again forever. systemd
//! gives it five starts in ten minutes, a Windows task three restarts a minute apart, and launchd
//! starts it once. `timewitness status` then says no agent is answering, and the reason is where each
//! platform keeps a service's output.

use std::path::{Path, PathBuf};
use std::process::Command;

use timewitness_agent::wire::Endpoint;

use crate::args::Args;
use crate::render;
use crate::verify_cmd::Outcome;

/// The systemd unit's name, which is also what a person types to `systemctl` and `journalctl`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub const UNIT: &str = "timewitness-agent.service";

/// The launchd label, and so the name `launchctl` knows the daemon by.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub const LABEL: &str = "dev.timewitness.agent";

/// The scheduled task's name, in its own folder so it is easy to find in Task Scheduler.
#[cfg_attr(not(windows), allow(dead_code))]
pub const TASK: &str = "\\TimeWitness\\Agent";

/// Everything a service definition needs, worked out before anything is written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Service {
    /// The binary the service runs, which is the one doing the installing.
    pub program: PathBuf,
    /// Everything after the program: `agent`, the endpoint and any options passed on.
    pub arguments: Vec<String>,
    /// The account the agent runs as.
    pub account: String,
    /// Where the agent writes its endpoint, and so what `status --agent` is pointed at.
    pub endpoint: PathBuf,
}

/// `timewitness agent install`.
pub fn install(args: &Args) -> Outcome {
    if args.value("--endpoint").is_some() {
        return fail(
            "a service writes its endpoint to a folder of its own, and install says where. \
             --endpoint is for running the agent by hand",
        );
    }
    let service = match plan(args) {
        Ok(service) => service,
        Err(e) => return fail(&e),
    };
    match put_in_place(&service) {
        Ok(text) => Outcome { text, code: 0 },
        Err(e) => fail(&e),
    }
}

/// `timewitness agent uninstall`.
pub fn uninstall(args: &Args) -> Outcome {
    if let Some(given) = args.values.keys().chain(args.flags.iter()).next() {
        return fail(&format!(
            "uninstall takes nothing after it, and was given {given}. It takes away what install \
             put in place, wherever that was"
        ));
    }
    let endpoint = match service_endpoint() {
        Ok(endpoint) => endpoint,
        Err(e) => return fail(&e),
    };
    match take_away(&endpoint) {
        Ok(text) => Outcome { text, code: 0 },
        Err(e) => fail(&e),
    }
}

/// Works out what to install from the command line and this machine.
fn plan(args: &Args) -> Result<Service, String> {
    let program = std::env::current_exe()
        .and_then(|p| p.canonicalize())
        .map_err(|e| format!("this program cannot find its own file: {e}"))?;
    let program = plain_path(program);
    let endpoint = service_endpoint()?;
    for path in [&program, &endpoint] {
        path_is_plain(path)?;
    }
    let account =
        match args.value("--user") {
            Some(_) if cfg!(windows) => return Err(
                "on Windows the task runs as the account installing it, so there is no --user. \
                 Install it from the account the agent should run as"
                    .to_string(),
            ),
            Some(name) => name.to_string(),
            None => default_account()?,
        };
    if !account_is_plain(&account) {
        return Err(format!(
            "{account:?} is not an account name this will write into a service definition"
        ));
    }
    // The service runs this file as the account named, at every boot, so whoever can change the
    // file, or rename a folder above it, can run what they like as that account.
    #[cfg(unix)]
    only_trusted_can_change(&program, &[0, id_number("-u", &account)?], &account)?;

    let mut arguments = vec![
        "agent".to_string(),
        "--endpoint".to_string(),
        endpoint.display().to_string(),
    ];
    // Checked here rather than left to the agent, because the agent reads them at boot, when a
    // mistake is a service that will not start and nobody watching it fail.
    if let Some(n) = args.number("--interval").map_err(|e| e.0)? {
        if n < 1 {
            return Err("--interval is a whole number of seconds, at least one".to_string());
        }
        arguments.extend(["--interval".to_string(), n.to_string()]);
    }
    if let Some(n) = args.number("--max-width").map_err(|e| e.0)? {
        if n <= 0 {
            return Err("--max-width is a positive number of nanoseconds".to_string());
        }
        arguments.extend(["--max-width".to_string(), n.to_string()]);
    }

    Ok(Service {
        program,
        arguments,
        account,
        endpoint,
    })
}

/// A Windows path without the `\\?\` prefix `canonicalize` puts on it, which Task Scheduler does not
/// read. Everywhere else the path is left as it is.
fn plain_path(path: PathBuf) -> PathBuf {
    let text = path.display().to_string();
    text.strip_prefix(r"\\?\")
        .map_or(path, |rest| PathBuf::from(rest.to_string()))
}

/// Refuses a path a service definition would read as something else: a control character anywhere,
/// and on Windows a `%`, which Task Scheduler reads as the start of a variable.
fn path_is_plain(path: &Path) -> Result<(), String> {
    let text = path.display().to_string();
    if text.chars().any(char::is_control) || (cfg!(windows) && text.contains('%')) {
        return Err(format!(
            "{text:?} is not a path this will write into a service definition. Move the binary \
             somewhere plainer and install from there"
        ));
    }
    Ok(())
}

/// An account name safe to write into a definition: letters, digits and `._-`, plus, on Windows, the
/// backslash between a domain and a name and the spaces a Windows name may carry.
fn account_is_plain(name: &str) -> bool {
    let windows = cfg!(windows);
    !name.is_empty()
        && name.len() <= 256
        && !name.starts_with('-')
        && name.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(c, '.' | '_' | '-')
                || (windows && matches!(c, '\\' | ' '))
        })
}

/// A number `id` gives for an account: `-u` for its user and `-g` for its group.
#[cfg(unix)]
fn id_number(flag: &str, account: &str) -> Result<u32, String> {
    let out = Command::new("id")
        .args([flag, account])
        .output()
        .map_err(|e| format!("`id` could not be run: {e}"))?;
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .map_err(|_| format!("{account} is not an account on this machine"))
}

/// Refuses a binary that anybody but root or the service's own account could change, or that sits
/// under a folder somebody else could rename or fill.
///
/// Every folder from the binary up to `/` counts, because whoever can rename one of them can put a
/// different file where the service looks. A folder may be writable by its group where that group
/// is root's, or on macOS the administrators', and by anybody where it carries the sticky bit, as
/// `/tmp` does, since then only an entry's owner may rename it.
#[cfg(unix)]
fn only_trusted_can_change(program: &Path, owners: &[u32], account: &str) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;

    let trusted_group = |gid: u32| gid == 0 || (cfg!(target_os = "macos") && gid == 80);
    for path in program.ancestors() {
        let meta = std::fs::metadata(path)
            .map_err(|e| format!("{} could not be read: {e}", path.display()))?;
        let mode = meta.mode();
        let sticky = meta.is_dir() && mode & 0o1000 != 0;
        let who = if !owners.contains(&meta.uid()) {
            Some("the account that owns it")
        } else if mode & 0o002 != 0 && !sticky {
            Some("anybody on this machine")
        } else if mode & 0o020 != 0 && !sticky && !trusted_group(meta.gid()) {
            Some("everybody in its group")
        } else {
            None
        };
        if let Some(who) = who {
            return Err(format!(
                "{} can be changed by {who}, and the service would run {} as {account} at every \
                 boot, so whoever that is could run anything as {account}. Put the binary where \
                 only root can write, for example with `sudo install -m 0755 {} \
                 /usr/local/bin/timewitness`, and install from there",
                path.display(),
                program.display(),
                program.display(),
            ));
        }
    }
    Ok(())
}

/// A systemd unit that runs the agent at boot and cannot change the clock.
///
/// `ProtectClock` and the empty capability set are the two lines that matter: with them the kernel
/// refuses this service a clock change whatever the code does. The rest keeps it to its own state
/// folder. It waits for the network to be up, since the first thing the agent does is ask its
/// sources, and a unit that raced the network would spend its first round refusing.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn systemd_unit(service: &Service) -> String {
    let command = std::iter::once(service.program.display().to_string())
        .chain(service.arguments.iter().cloned())
        .map(|word| systemd_word(&word))
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "[Unit]\n\
         Description=TimeWitness agent, which measures this machine's clock and never sets it\n\
         Documentation=https://github.com/Fountech-ai-Limited/timewitness\n\
         Wants=network-online.target\n\
         After=network-online.target\n\
         StartLimitIntervalSec=600\n\
         StartLimitBurst=5\n\
         \n\
         [Service]\n\
         Type=simple\n\
         User={account}\n\
         ExecStart={command}\n\
         StateDirectory=timewitness\n\
         StateDirectoryMode=0700\n\
         Restart=on-failure\n\
         RestartSec=32\n\
         ProtectClock=yes\n\
         CapabilityBoundingSet=\n\
         AmbientCapabilities=\n\
         NoNewPrivileges=yes\n\
         ProtectSystem=strict\n\
         ProtectHome=read-only\n\
         PrivateTmp=yes\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        account = service.account,
    )
}

/// One word of a systemd command line: quoted, with the characters systemd would otherwise read as
/// a specifier or a variable doubled.
fn systemd_word(word: &str) -> String {
    let mut out = String::from("\"");
    for c in word.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '%' => out.push_str("%%"),
            '$' => out.push_str("$$"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A launchd daemon that starts the agent once at boot, as the account that installed it.
///
/// No `KeepAlive`: launchd has no limit on restarts, so a daemon told to stay alive that fails at
/// start fails every ten seconds for ever. What went wrong is written to `log`.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn launchd_plist(service: &Service, log: &Path) -> String {
    let words: String = std::iter::once(service.program.display().to_string())
        .chain(service.arguments.iter().cloned())
        .map(|word| format!("\t\t<string>{}</string>\n", xml(&word)))
        .collect();
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
         \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n\
         <dict>\n\
         \t<key>Label</key>\n\
         \t<string>{LABEL}</string>\n\
         \t<key>ProgramArguments</key>\n\
         \t<array>\n\
         {words}\
         \t</array>\n\
         \t<key>UserName</key>\n\
         \t<string>{account}</string>\n\
         \t<key>RunAtLoad</key>\n\
         \t<true/>\n\
         \t<key>StandardOutPath</key>\n\
         \t<string>/dev/null</string>\n\
         \t<key>StandardErrorPath</key>\n\
         \t<string>{log}</string>\n\
         </dict>\n\
         </plist>\n",
        account = xml(&service.account),
        log = xml(&log.display().to_string()),
    )
}

/// A Windows scheduled task that starts the agent at boot, as the account that installed it.
///
/// S4U runs it whether or not anybody is signed in and stores no password. `LeastPrivilege` runs it
/// without elevation. No time limit, because the default stops a task after three days, and three
/// restarts a minute apart if it fails.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn task_xml(service: &Service) -> String {
    let arguments = service
        .arguments
        .iter()
        .map(String::as_str)
        .map(windows_word)
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n\
         <Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\n\
         \x20 <RegistrationInfo>\n\
         \x20   <Description>TimeWitness agent, which measures this machine's clock and never sets \
         it</Description>\n\
         \x20 </RegistrationInfo>\n\
         \x20 <Triggers>\n\
         \x20   <BootTrigger>\n\
         \x20     <Enabled>true</Enabled>\n\
         \x20   </BootTrigger>\n\
         \x20 </Triggers>\n\
         \x20 <Principals>\n\
         \x20   <Principal id=\"Agent\">\n\
         \x20     <UserId>{account}</UserId>\n\
         \x20     <LogonType>S4U</LogonType>\n\
         \x20     <RunLevel>LeastPrivilege</RunLevel>\n\
         \x20   </Principal>\n\
         \x20 </Principals>\n\
         \x20 <Settings>\n\
         \x20   <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\n\
         \x20   <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\n\
         \x20   <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\n\
         \x20   <AllowHardTerminate>true</AllowHardTerminate>\n\
         \x20   <StartWhenAvailable>false</StartWhenAvailable>\n\
         \x20   <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\n\
         \x20   <AllowStartOnDemand>true</AllowStartOnDemand>\n\
         \x20   <Enabled>true</Enabled>\n\
         \x20   <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\n\
         \x20   <RestartOnFailure>\n\
         \x20     <Interval>PT1M</Interval>\n\
         \x20     <Count>3</Count>\n\
         \x20   </RestartOnFailure>\n\
         \x20 </Settings>\n\
         \x20 <Actions Context=\"Agent\">\n\
         \x20   <Exec>\n\
         \x20     <Command>{program}</Command>\n\
         \x20     <Arguments>{arguments}</Arguments>\n\
         \x20   </Exec>\n\
         \x20 </Actions>\n\
         </Task>\n",
        account = xml(&service.account),
        program = xml(&service.program.display().to_string()),
        arguments = xml(&arguments),
    )
}

/// Text made safe to sit inside an XML element.
fn xml(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// One word of a Windows command line, quoted the way a Windows program splits its arguments back.
fn windows_word(word: &str) -> String {
    if !word.is_empty() && !word.contains([' ', '\t', '"']) {
        return word.to_string();
    }
    let mut out = String::from("\"");
    let mut slashes = 0;
    for c in word.chars() {
        match c {
            '\\' => slashes += 1,
            '"' => {
                out.push_str(&"\\".repeat(slashes * 2 + 1));
                out.push('"');
                slashes = 0;
            }
            c => {
                out.push_str(&"\\".repeat(slashes));
                out.push(c);
                slashes = 0;
            }
        }
    }
    out.push_str(&"\\".repeat(slashes * 2));
    out.push('"');
    out
}

/// Where the service's agent keeps its endpoint on Linux: its own state folder, which systemd makes
/// and gives to the account the agent runs as.
const LINUX_STATE: &str = "/var/lib/timewitness";

/// The same folder on macOS, which the installer makes and gives to that account.
const MACOS_STATE: &str = "/Library/Application Support/TimeWitness";

/// Where a service's agent writes its endpoint.
///
/// On Windows it is the installing account's own local application data, which only that account
/// and the administrators can read, and never a shared folder: the file holds the token a caller
/// presents. With no such folder named there is nowhere private to put it, so the install stops.
fn service_endpoint() -> Result<PathBuf, String> {
    if cfg!(windows) {
        let base = std::env::var_os("LOCALAPPDATA").ok_or(
            "this account has no local application data folder, so there is nowhere private for \
             the agent's token",
        )?;
        Ok(PathBuf::from(base)
            .join("TimeWitness")
            .join("agent.endpoint"))
    } else if cfg!(target_os = "macos") {
        Ok(Path::new(MACOS_STATE).join("agent.endpoint"))
    } else {
        Ok(Path::new(LINUX_STATE).join("agent.endpoint"))
    }
}

/// The account a service runs as when nobody names one: whoever ran `sudo`, or on Windows whoever is
/// running this. Never root unless root is named, because nothing the agent does needs it and root
/// may set the clock.
fn default_account() -> Result<String, String> {
    if cfg!(windows) {
        let name = std::env::var("USERNAME")
            .map_err(|_| "this cannot tell which account is running it; name one with --user")?;
        return Ok(match std::env::var("USERDOMAIN") {
            Ok(domain) if !domain.is_empty() => format!("{domain}\\{name}"),
            _ => name,
        });
    }
    if let Ok(name) = std::env::var("SUDO_USER") {
        if !name.is_empty() {
            return Ok(name);
        }
    }
    let out = Command::new("id").arg("-un").output().map_err(|e| {
        format!("this cannot tell which account is running it ({e}); name one with --user")
    })?;
    let name = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if name == "root" {
        return Err(
            "this is running as root with no sudo, so there is no account to run the agent as. \
             Run it with sudo from the account the agent should run as, or name one with --user"
                .to_string(),
        );
    }
    Ok(name)
}

/// Runs a platform tool, and on failure says what it said.
fn tool(program: &str, arguments: &[&str]) -> Result<(), String> {
    let out = Command::new(program)
        .args(arguments)
        .output()
        .map_err(|e| format!("`{program}` could not be run: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let said = String::from_utf8_lossy(&out.stderr).trim().to_string();
    let said = if said.is_empty() {
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    } else {
        said
    };
    Err(format!(
        "`{program} {}` failed: {said}",
        arguments.join(" ")
    ))
}

/// A write that says plainly when the refusal was a permission.
#[cfg_attr(windows, allow(dead_code))]
fn write_as_administrator(path: &Path, bytes: &[u8]) -> Result<(), String> {
    std::fs::write(path, bytes).map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            format!(
                "{} could not be written: installing a service needs an administrator. {}",
                path.display(),
                if cfg!(windows) {
                    "Run it again as an administrator"
                } else {
                    "Run it again with sudo"
                }
            )
        } else {
            format!("{} could not be written: {e}", path.display())
        }
    })
}

/// Takes away the service's endpoint file, only if it is one, and its folder once nothing else is in
/// it. The folder is the service's own, so nothing a person made is touched.
fn clear_endpoint(endpoint: &Path) {
    if Endpoint::read(endpoint).is_ok() {
        let _ = std::fs::remove_file(endpoint);
    }
    if let Some(parent) = endpoint.parent() {
        let _ = std::fs::remove_dir(parent);
    }
}

/// What to type to ask the agent how it stands, said once the service is in place.
fn after_install(service: &Service, how: &str, output: &str, remove: &str) -> String {
    format!(
        "Installed. {how}, as {account}, and it starts at every boot.\n\n\
         It is starting now and writes its endpoint to {endpoint}.\n\
         \x20 timewitness status --agent {endpoint}\n\
         says whether it is up and how wrong this machine's clock could be. A fresh agent has a \
         first bound within a minute.\n\n\
         It measures this machine's clock and never sets it. {output}\n\
         `{remove}` takes it away again.",
        account = service.account,
        endpoint = service.endpoint.display(),
    )
}

#[cfg(target_os = "linux")]
fn put_in_place(service: &Service) -> Result<String, String> {
    let unit_path = Path::new("/etc/systemd/system").join(UNIT);
    write_as_administrator(&unit_path, systemd_unit(service).as_bytes())?;
    tool("systemctl", &["daemon-reload"])?;
    tool("systemctl", &["enable", UNIT])?;
    tool("systemctl", &["restart", UNIT])?;
    Ok(after_install(
        service,
        "The agent runs as the systemd service timewitness-agent",
        "The unit takes that permission away as well, so the kernel would refuse it a clock \
         change. What it prints is in `journalctl -u timewitness-agent`.",
        "sudo timewitness agent uninstall",
    ))
}

#[cfg(target_os = "linux")]
fn take_away(endpoint: &Path) -> Result<String, String> {
    let unit_path = Path::new("/etc/systemd/system").join(UNIT);
    if !unit_path.exists() {
        clear_endpoint(endpoint);
        return Ok("There was no TimeWitness service here to take away.".to_string());
    }
    tool("systemctl", &["disable", "--now", UNIT])?;
    std::fs::remove_file(&unit_path).map_err(|e| {
        format!(
            "{} could not be removed: {e}. Taking a service away needs an administrator",
            unit_path.display()
        )
    })?;
    tool("systemctl", &["daemon-reload"])?;
    clear_endpoint(endpoint);
    Ok(
        "Uninstalled. The agent is stopped, the systemd unit is gone and nothing of it starts at \
         boot."
            .to_string(),
    )
}

#[cfg(target_os = "macos")]
fn put_in_place(service: &Service) -> Result<String, String> {
    let plist_path = Path::new("/Library/LaunchDaemons").join(format!("{LABEL}.plist"));
    let folder = PathBuf::from(MACOS_STATE);
    let log = folder.join("agent.log");
    std::fs::create_dir_all(&folder).map_err(|e| {
        format!(
            "{} could not be made: {e}. Installing a service needs an administrator. Run it again \
             with sudo",
            folder.display()
        )
    })?;
    give_to(&folder, &service.account)?;
    write_as_administrator(&plist_path, launchd_plist(service, &log).as_bytes())?;
    let target = format!("system/{LABEL}");
    // Loaded already from an earlier install, it has to go before the new one can load. Not being
    // loaded is the usual case, so a failure here is not one.
    let _ = tool("launchctl", &["bootout", &target]);
    tool(
        "launchctl",
        &["bootstrap", "system", &plist_path.display().to_string()],
    )?;
    Ok(after_install(
        service,
        "The agent runs as the launchd daemon dev.timewitness.agent",
        &format!(
            "{} If it fails to start, why is in {}.",
            if service.account == "root" {
                "It runs as root because root was named, and root may set the clock on macOS; \
                 the agent's code never does."
            } else {
                "It does not run as root, and only root may set the clock on macOS."
            },
            log.display()
        ),
        "sudo timewitness agent uninstall",
    ))
}

/// Gives a folder to an account, private to it.
#[cfg(target_os = "macos")]
fn give_to(folder: &Path, account: &str) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    let (uid, gid) = (id_number("-u", account)?, id_number("-g", account)?);
    std::os::unix::fs::chown(folder, Some(uid), Some(gid))
        .map_err(|e| format!("{} could not be given to {account}: {e}", folder.display()))?;
    std::fs::set_permissions(folder, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("{} could not be made private: {e}", folder.display()))
}

#[cfg(target_os = "macos")]
fn take_away(endpoint: &Path) -> Result<String, String> {
    let plist_path = Path::new("/Library/LaunchDaemons").join(format!("{LABEL}.plist"));
    if !plist_path.exists() {
        clear_endpoint(endpoint);
        return Ok("There was no TimeWitness service here to take away.".to_string());
    }
    let _ = tool("launchctl", &["bootout", &format!("system/{LABEL}")]);
    std::fs::remove_file(&plist_path).map_err(|e| {
        format!(
            "{} could not be removed: {e}. Taking a service away needs an administrator",
            plist_path.display()
        )
    })?;
    let _ = std::fs::remove_file(Path::new(MACOS_STATE).join("agent.log"));
    clear_endpoint(endpoint);
    Ok(
        "Uninstalled. The agent is stopped, the launchd daemon is gone and nothing of it starts \
         at boot."
            .to_string(),
    )
}

#[cfg(windows)]
fn put_in_place(service: &Service) -> Result<String, String> {
    if let Some(folder) = service.endpoint.parent() {
        std::fs::create_dir_all(folder)
            .map_err(|e| format!("{} could not be made: {e}", folder.display()))?;
    }
    // Task Scheduler reads a definition in UTF-16, which is what the declaration in it says.
    let mut bytes = vec![0xFF, 0xFE];
    for unit in task_xml(service).encode_utf16() {
        bytes.extend(unit.to_le_bytes());
    }
    if !elevated() {
        return Err(
            "installing a service needs an administrator, and this is not running as one. Run it \
             again from a terminal opened as administrator"
                .to_string(),
        );
    }
    // An agent from an earlier install is still running with its old definition, and a new one
    // would find it answering on the endpoint and not start.
    let _ = tool("schtasks", &["/End", "/TN", TASK]);
    let folder = folder_only_administrators_can_write()?;
    let created =
        write_new(&folder.join(format!("{}.xml", random_name()?)), &bytes).and_then(|file| {
            tool(
                "schtasks",
                &[
                    "/Create",
                    "/TN",
                    TASK,
                    "/XML",
                    &file.display().to_string(),
                    "/F",
                ],
            )
        });
    let _ = std::fs::remove_dir_all(&folder);
    created?;
    tool("schtasks", &["/Run", "/TN", TASK])?;
    Ok(after_install(
        service,
        "The agent runs as the scheduled task \\TimeWitness\\Agent",
        "It runs without elevation. If it fails to start, Task Scheduler's history for the task \
         says why.",
        "timewitness agent uninstall",
    ))
}

/// Whether this is running elevated, read from its own token's integrity level. High (12288) or
/// System (16384) is an administrator's; `whoami` prints the level's number whatever the language.
#[cfg(windows)]
fn elevated() -> bool {
    Command::new("whoami")
        .arg("/groups")
        .output()
        .map(|out| {
            let groups = String::from_utf8_lossy(&out.stdout);
            groups.contains("S-1-16-12288") || groups.contains("S-1-16-16384")
        })
        .unwrap_or(false)
}

/// Sixteen random bytes as a name, so nothing can take a name before it is used.
#[cfg(windows)]
fn random_name() -> Result<String, String> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|e| format!("no random name could be made: {e}"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// A new folder for the task definition, in Windows' own temporary folder rather than the
/// account's, which anything running unelevated as that account could write. It is made under a
/// name nobody can know beforehand, and only administrators and SYSTEM may write in it, with
/// nothing inherited from the folder it sits in.
///
/// Until this, the definition went to a fixed name in the account's own temporary folder, and
/// unelevated code could have swapped in one with a SYSTEM principal before the elevated
/// `schtasks` read it back.
#[cfg(windows)]
fn folder_only_administrators_can_write() -> Result<PathBuf, String> {
    let root = std::env::var_os("SystemRoot")
        .ok_or("this machine does not say where Windows is, so there is nowhere safe to write")?;
    let folder = PathBuf::from(root)
        .join("Temp")
        .join(format!("timewitness-install-{}", random_name()?));
    std::fs::create_dir(&folder)
        .map_err(|e| format!("{} could not be made: {e}", folder.display()))?;
    let folder_text = folder.display().to_string();
    let only = tool(
        "icacls",
        &[
            folder_text.as_str(),
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-32-544:(OI)(CI)F",
            "*S-1-5-18:(OI)(CI)F",
        ],
    );
    if let Err(e) = only {
        let _ = std::fs::remove_dir_all(&folder);
        return Err(e);
    }
    Ok(folder)
}

/// Writes a file that must not exist yet, and refuses one that does.
#[cfg(windows)]
fn write_new(path: &Path, bytes: &[u8]) -> Result<PathBuf, String> {
    use std::io::Write;

    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .and_then(|mut file| file.write_all(bytes))
        .map_err(|e| format!("{} could not be written: {e}", path.display()))?;
    Ok(path.to_path_buf())
}

#[cfg(windows)]
fn take_away(endpoint: &Path) -> Result<String, String> {
    if let Err(said) = tool("schtasks", &["/Query", "/TN", TASK]) {
        clear_endpoint(endpoint);
        return Ok(format!(
            "There was no TimeWitness service here to take away, or none this account can see: \
             {said}"
        ));
    }
    // Stopping first, because deleting a task leaves its running process alone.
    let _ = tool("schtasks", &["/End", "/TN", TASK]);
    tool("schtasks", &["/Delete", "/TN", TASK, "/F"]).map_err(|e| {
        format!("{e}. Taking a service away needs an administrator: run it again as one")
    })?;
    clear_endpoint(endpoint);
    Ok(
        "Uninstalled. The agent is stopped, the scheduled task is gone and nothing of it starts at \
         boot."
            .to_string(),
    )
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn put_in_place(_service: &Service) -> Result<String, String> {
    Err(
        "this machine is not one the service is built for. Run `timewitness agent` under whatever \
         starts things at boot here"
            .to_string(),
    )
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn take_away(_endpoint: &Path) -> Result<String, String> {
    Ok("There was no TimeWitness service here to take away.".to_string())
}

fn fail(what: &str) -> Outcome {
    Outcome {
        text: render::failure(what),
        code: 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service(program: &str, endpoint: &str) -> Service {
        Service {
            program: PathBuf::from(program),
            arguments: vec![
                "agent".to_string(),
                "--endpoint".to_string(),
                endpoint.to_string(),
            ],
            account: "nik".to_string(),
            endpoint: PathBuf::from(endpoint),
        }
    }

    #[test]
    fn the_unit_takes_the_clock_away_from_the_agent() {
        let unit = systemd_unit(&service(
            "/usr/local/bin/timewitness",
            "/var/lib/timewitness/agent.endpoint",
        ));
        for line in [
            "ProtectClock=yes\n",
            "\nCapabilityBoundingSet=\n",
            "\nAmbientCapabilities=\n",
            "\nUser=nik\n",
            "\nWantedBy=multi-user.target\n",
            "\nStartLimitBurst=5\n",
            "\nExecStart=\"/usr/local/bin/timewitness\" \"agent\" \"--endpoint\" \
             \"/var/lib/timewitness/agent.endpoint\"\n",
        ] {
            assert!(unit.contains(line), "no {line:?} in\n{unit}");
        }
        assert!(
            !unit.contains("ReadWritePaths"),
            "the state folder needs no second grant:\n{unit}"
        );
    }

    #[test]
    fn nothing_in_a_path_is_read_as_systemd_syntax() {
        let unit = systemd_unit(&service(
            "/opt/time witness/100%/$HOME/timewitness",
            "/var/lib/timewitness/agent.endpoint",
        ));
        assert!(
            unit.contains("ExecStart=\"/opt/time witness/100%%/$$HOME/timewitness\" "),
            "{unit}"
        );
    }

    #[test]
    fn the_daemon_starts_once_at_boot_as_the_installing_account() {
        let plist = launchd_plist(
            &service(
                "/usr/local/bin/timewitness",
                "/Library/Application Support/TimeWitness/agent.endpoint",
            ),
            Path::new("/Library/Application Support/TimeWitness/agent.log"),
        );
        assert!(plist.contains("<key>RunAtLoad</key>\n\t<true/>"), "{plist}");
        assert!(
            plist.contains("<key>UserName</key>\n\t<string>nik</string>"),
            "{plist}"
        );
        assert!(
            plist.contains(
                "\t\t<string>/Library/Application Support/TimeWitness/agent.endpoint</string>\n"
            ),
            "{plist}"
        );
        assert!(!plist.contains("KeepAlive"), "{plist}");
    }

    #[test]
    fn the_task_starts_at_boot_without_elevation_and_without_a_stored_password() {
        let task = task_xml(&service(
            r"C:\Program Files\TimeWitness\timewitness.exe",
            r"C:\Users\Nik Kairinos\AppData\Local\TimeWitness\agent.endpoint",
        ));
        for part in [
            "<BootTrigger>",
            "<LogonType>S4U</LogonType>",
            "<RunLevel>LeastPrivilege</RunLevel>",
            "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>",
            r"<Command>C:\Program Files\TimeWitness\timewitness.exe</Command>",
            r"<Arguments>agent --endpoint &quot;C:\Users\Nik Kairinos\AppData\Local\TimeWitness\agent.endpoint&quot;</Arguments>",
        ] {
            assert!(task.contains(part), "no {part:?} in\n{task}");
        }
    }

    #[test]
    fn a_windows_word_splits_back_to_itself() {
        assert_eq!(windows_word("agent"), "agent");
        assert_eq!(windows_word(r"C:\a b\c"), r#""C:\a b\c""#);
        assert_eq!(windows_word(r"C:\a b\"), r#""C:\a b\\""#);
        assert_eq!(windows_word(r#"say "hi""#), r#""say \"hi\"""#);
        assert_eq!(windows_word(""), r#""""#);
    }

    #[cfg(unix)]
    #[test]
    fn a_binary_somebody_else_could_change_is_refused() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let root = std::env::temp_dir().join(format!("timewitness-service-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let folder = root.join("bin");
        std::fs::create_dir_all(&folder).unwrap();
        let binary = folder.join("timewitness");
        std::fs::write(&binary, b"not really a binary").unwrap();
        let mode = |path: &Path, mode: u32| {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
        };
        mode(&root, 0o755);
        mode(&folder, 0o755);
        mode(&binary, 0o755);
        let me = std::fs::metadata(&binary).unwrap().uid();
        // The temporary folder above is root's and sticky, so everything from here up is fine.
        let fine = only_trusted_can_change(&binary, &[0, me], "nik");

        mode(&folder, 0o777);
        let open_folder = only_trusted_can_change(&binary, &[0, me], "nik");
        mode(&folder, 0o1777);
        let sticky_folder = only_trusted_can_change(&binary, &[0, me], "nik");
        mode(&folder, 0o755);
        mode(&binary, 0o775);
        let group_file = only_trusted_can_change(&binary, &[0, me], "nik");
        mode(&binary, 0o755);
        let someone_elses = only_trusted_can_change(&binary, &[0, me + 1], "root");
        let _ = std::fs::remove_dir_all(&root);

        assert_eq!(fine, Ok(()));
        let refused = open_folder.unwrap_err();
        assert!(
            refused.starts_with(&format!("{} can be changed by anybody", folder.display())),
            "{refused}"
        );
        assert_eq!(sticky_folder, Ok(()));
        assert!(group_file
            .unwrap_err()
            .contains("by everybody in its group"));
        let refused = someone_elses.unwrap_err();
        assert!(
            refused.contains("by the account that owns it") && refused.contains("as root"),
            "{refused}"
        );
    }

    #[test]
    fn an_account_name_that_could_carry_anything_else_is_refused() {
        for plain in ["nik", "runner", "svc.time_witness-1"] {
            assert!(account_is_plain(plain), "{plain}");
        }
        for odd in ["", "-nik", "nik\nExecStart=/bin/sh", "nik</string>", "a;b"] {
            assert!(!account_is_plain(odd), "{odd:?}");
        }
    }
}
