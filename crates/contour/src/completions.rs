//! `contour completions` — shell-completion install guide and installer.
//!
//! Default: print a per-shell install guide. `--install` writes the
//! completion file to its conventional location. `--script` emits only
//! the raw completion script (for piping / packaging). With no shell
//! argument, the current shell is detected from `$SHELL` and confirmed
//! interactively.

use anyhow::{Context, Result};
use clap::CommandFactory;
use colored::Colorize;
use std::path::PathBuf;

/// Shells contour generates completions for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ShellKind {
    Zsh,
    Bash,
    Fish,
}

impl std::fmt::Display for ShellKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl ShellKind {
    fn as_str(self) -> &'static str {
        match self {
            ShellKind::Zsh => "zsh",
            ShellKind::Bash => "bash",
            ShellKind::Fish => "fish",
        }
    }

    fn clap_shell(self) -> clap_complete::Shell {
        match self {
            ShellKind::Zsh => clap_complete::Shell::Zsh,
            ShellKind::Bash => clap_complete::Shell::Bash,
            ShellKind::Fish => clap_complete::Shell::Fish,
        }
    }

    /// Detect the shell from the `$SHELL` environment variable.
    fn detect() -> Option<Self> {
        let shell = std::env::var("SHELL").ok()?;
        match shell.rsplit('/').next()? {
            "zsh" => Some(Self::Zsh),
            "bash" => Some(Self::Bash),
            "fish" => Some(Self::Fish),
            _ => None,
        }
    }
}

/// Where a shell's completion file installs, and any one-time rc setup.
struct ShellTarget {
    /// Absolute install path.
    file: PathBuf,
    /// `~`-form path for display.
    tilde: &'static str,
    /// One-time `.zshrc`/`.bashrc` setup; `None` when the shell
    /// auto-loads the directory (fish).
    rc_setup: Option<&'static str>,
}

fn target(shell: ShellKind, home: &str) -> ShellTarget {
    match shell {
        ShellKind::Zsh => ShellTarget {
            file: PathBuf::from(format!("{home}/.zfunc/_contour")),
            tilde: "~/.zfunc/_contour",
            rc_setup: Some(
                "Add to ~/.zshrc (before `compinit`):\n  \
                 fpath=(~/.zfunc $fpath)\n  \
                 autoload -Uz compinit && compinit",
            ),
        },
        ShellKind::Bash => ShellTarget {
            file: PathBuf::from(format!("{home}/.bash_completion.d/contour")),
            tilde: "~/.bash_completion.d/contour",
            rc_setup: Some("Add to ~/.bashrc:\n  source ~/.bash_completion.d/contour"),
        },
        ShellKind::Fish => ShellTarget {
            file: PathBuf::from(format!("{home}/.config/fish/completions/contour.fish")),
            tilde: "~/.config/fish/completions/contour.fish",
            rc_setup: None,
        },
    }
}

/// Render the raw clap completion script into a buffer.
fn render_script(shell: ShellKind) -> Vec<u8> {
    let mut cmd = crate::Cli::command();
    let mut buf: Vec<u8> = Vec::new();
    clap_complete::generate(shell.clap_shell(), &mut cmd, "contour", &mut buf);
    buf
}

/// Resolve the shell: detect `$SHELL`, then confirm/pick interactively.
fn resolve_interactively() -> Result<ShellKind> {
    let detected = ShellKind::detect();
    let prompt = match detected {
        Some(d) => format!("Shell for completions (detected {d}):"),
        None => "Shell for completions:".to_string(),
    };
    let options = vec![ShellKind::Zsh, ShellKind::Bash, ShellKind::Fish];
    let cursor = detected
        .and_then(|d| options.iter().position(|s| *s == d))
        .unwrap_or(0);
    inquire::Select::new(&prompt, options)
        .with_starting_cursor(cursor)
        .prompt()
        .context("Cancelled")
}

/// Print the install guide for a shell.
fn print_guide(shell: ShellKind, tgt: &ShellTarget) {
    println!("{}", format!("Shell completions — {shell}").bold().cyan());
    println!();
    println!("{}", "Install automatically:".bold());
    println!("  contour completions {shell} --install");
    println!();
    println!("{}", "Or install by hand:".bold());
    println!("  contour completions {shell} --script > {}", tgt.tilde);
    if let Some(rc) = tgt.rc_setup {
        println!();
        println!("{rc}");
    } else {
        println!();
        println!("fish auto-loads that directory — no rc changes needed.");
    }
    println!();
    println!("Open a new shell to activate.");
}

/// `contour completions` entry point.
pub fn run(shell: Option<ShellKind>, install: bool, script: bool) -> Result<()> {
    let shell = match shell {
        Some(s) => s,
        None => resolve_interactively()?,
    };

    // Raw script — for piping into a file or a package build.
    if script {
        use std::io::Write as _;
        std::io::stdout()
            .write_all(&render_script(shell))
            .context("writing completion script to stdout")?;
        return Ok(());
    }

    let home = std::env::var("HOME").context("HOME is not set")?;
    let tgt = target(shell, &home);

    if install {
        if let Some(parent) = tgt.file.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        std::fs::write(&tgt.file, render_script(shell))
            .with_context(|| format!("writing {}", tgt.file.display()))?;
        println!(
            "{} Installed {shell} completions → {}",
            "✓".green(),
            tgt.tilde
        );
        if let Some(rc) = tgt.rc_setup {
            println!();
            println!("{}", "One-time setup:".bold());
            println!("{rc}");
        }
        println!();
        println!("Open a new shell to activate.");
        return Ok(());
    }

    print_guide(shell, &tgt);
    Ok(())
}
