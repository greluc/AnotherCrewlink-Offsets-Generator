//! One error type for the whole tool.
//!
//! The audit finding this replaces (F8) was a swallowed `catch` that logged and
//! returned void, so a failed dump surfaced two stages later as a confusing
//! "no dump found" and took the whole run down with it. Everything here carries
//! its own context and is returned, never printed and discarded.

use std::fmt;
use std::path::Path;

#[derive(Debug)]
pub enum Error {
    /// A file or directory we were told to read is not usable.
    Io {
        path: String,
        source: std::io::Error,
    },
    /// Input existed but did not look like what it claimed to be.
    Malformed(String),
    /// The external dumper could not be used, or refused to run.
    Tool(String),
    /// Something the user asked for cannot be done as asked.
    Usage(String),
    /// Generation finished but the result is not fit to publish.
    Validation(Vec<String>),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn io(path: impl AsRef<Path>, source: std::io::Error) -> Self {
        Error::Io {
            path: path.as_ref().display().to_string(),
            source,
        }
    }

    pub fn malformed(message: impl Into<String>) -> Self {
        Error::Malformed(message.into())
    }

    pub fn tool(message: impl Into<String>) -> Self {
        Error::Tool(message.into())
    }

    pub fn usage(message: impl Into<String>) -> Self {
        Error::Usage(message.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io { path, source } => write!(f, "{path}: {source}"),
            Error::Malformed(message) => write!(f, "{message}"),
            Error::Tool(message) => write!(f, "{message}"),
            Error::Usage(message) => write!(f, "{message}"),
            Error::Validation(problems) => {
                writeln!(
                    f,
                    "the generated offsets did not pass validation ({} problem{}):",
                    problems.len(),
                    if problems.len() == 1 { "" } else { "s" }
                )?;
                for problem in problems {
                    writeln!(f, "  - {problem}")?;
                }
                write!(
                    f,
                    "nothing was written. Publishing offsets that fail these checks \
                     hands the client a wrong pointer, which is worse than shipping nothing."
                )
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Reads a file, attaching the path to any failure.
pub fn read_file(path: impl AsRef<Path>) -> Result<Vec<u8>> {
    let path = path.as_ref();
    std::fs::read(path).map_err(|source| Error::io(path, source))
}

/// Reads a UTF-8 file, tolerating stray bytes. Dumped C# occasionally carries
/// odd identifiers, and losing a whole run to one bad byte would be silly.
pub fn read_to_string_lossy(path: impl AsRef<Path>) -> Result<String> {
    let bytes = read_file(path)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

pub fn write_file(path: impl AsRef<Path>, contents: &str) -> Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| Error::io(parent, source))?;
    }
    std::fs::write(path, contents).map_err(|source| Error::io(path, source))
}
