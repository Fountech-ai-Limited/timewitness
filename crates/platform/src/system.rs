//! Where the operating system keeps its own programs.
//!
//! The service install runs `schtasks`, `icacls` and `whoami` as an administrator. Asked for by name,
//! Windows looks for a program in the folder the running executable was loaded from before it looks
//! in its own, so a `schtasks.exe` saved beside a downloaded `timewitness.exe` would run elevated in
//! its place. The install names each one by its full path in the folder this returns instead.
//!
//! The folder is asked of Windows rather than built from `SystemRoot`, because an environment
//! variable is whatever the process was started with and this answer is not.

use std::path::PathBuf;

/// The folder Windows keeps its own programs in, such as `C:\Windows\System32`, or nothing where
/// this is not Windows or Windows would not say.
#[must_use]
pub fn system_folder() -> Option<PathBuf> {
    platform::system_folder()
}

#[cfg(windows)]
mod platform {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use std::path::PathBuf;

    // In kernel32 on every Windows there has been. It writes the folder into the buffer and returns
    // how many UTF-16 units it wrote, not counting the terminator; where the buffer is too small it
    // writes nothing and returns the size it needs, terminator included; and 0 where it failed.
    #[link(name = "kernel32")]
    extern "system" {
        fn GetSystemDirectoryW(buffer: *mut u16, size: u32) -> u32;
    }

    /// The longest path Windows will hand back, in UTF-16 units.
    const LONGEST: usize = 32_768;

    pub fn system_folder() -> Option<PathBuf> {
        let mut buffer = vec![0u16; 260];
        loop {
            let size = u32::try_from(buffer.len()).ok()?;
            // Safety: the pointer and the size describe one buffer this function owns, and the call
            // writes at most `size` units into it. The buffer outlives the call, and nothing else
            // holds it while the call runs.
            let written = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), size) };
            let written = usize::try_from(written).ok()?;
            if written == 0 {
                return None;
            }
            if written < buffer.len() {
                buffer.truncate(written);
                return Some(PathBuf::from(OsString::from_wide(&buffer)));
            }
            if written > LONGEST {
                return None;
            }
            buffer.resize(written, 0);
        }
    }
}

#[cfg(not(windows))]
mod platform {
    use std::path::PathBuf;

    pub fn system_folder() -> Option<PathBuf> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::system_folder;

    #[cfg(windows)]
    #[test]
    fn the_system_folder_is_the_one_windows_runs_from() {
        let folder = system_folder().expect("Windows said where its programs are");
        assert!(folder.is_absolute(), "{}", folder.display());
        assert!(
            folder.join("kernel32.dll").is_file(),
            "{}",
            folder.display()
        );
        let root = std::env::var_os("SystemRoot").expect("SystemRoot");
        let expected = std::path::Path::new(&root).join("System32");
        assert_eq!(
            folder.display().to_string().to_lowercase(),
            expected.display().to_string().to_lowercase()
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn there_is_no_system_folder_anywhere_else() {
        assert_eq!(system_folder(), None);
    }
}
