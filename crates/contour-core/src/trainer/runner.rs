//! Interactive step execution with inquire.

use super::TrainerContext;
use super::step::{GitOp, StepAction, TrainerStep};
use anyhow::Result;
use colored::Colorize;
use inquire::Select;
use std::io::Write;
use std::process::{Command, Stdio};

/// Run a workflow interactively.
pub fn run_workflow(steps: Vec<TrainerStep>, ctx: &TrainerContext) -> Result<()> {
    let total_steps = steps.len();

    println!();
    println!("{}", "=".repeat(70));
    println!(
        "{}",
        "  Contour Trainer Mode - Learn GitOps Workflows"
            .bold()
            .cyan()
    );
    println!("{}", "=".repeat(70));
    println!();
    println!("This trainer will guide you through {total_steps} steps.");
    println!("Copy the commands shown and run them in your terminal when ready.");
    println!();

    for step in steps {
        run_step(&step, total_steps, ctx)?;
    }

    println!();
    println!("{}", "=".repeat(70));
    println!("{}", "  Workflow Complete!".bold().green());
    println!("{}", "=".repeat(70));
    println!();

    Ok(())
}

/// Run a single step.
fn run_step(step: &TrainerStep, total: usize, ctx: &TrainerContext) -> Result<()> {
    // Print step header
    println!();
    println!("{}", "=".repeat(70));
    let title = step.title.bold().cyan();
    println!(">> Step {}/{total}: {title}", step.number);
    println!("{}", "=".repeat(70));
    println!();

    // Print explanation
    if !step.explanation.is_empty() {
        for line in step.explanation.lines() {
            println!("{line}");
        }
        println!();
    }

    // Show commands
    if !step.commands.is_empty() {
        println!("{}", "Commands to run:".bold());
        for cmd in &step.commands {
            println!("  {} {}", "$".dimmed(), cmd.command.green());
            println!("    {}", cmd.description.dimmed());
        }
        println!();
    }

    // Show osquery helper
    if let Some(ref osquery) = step.osquery {
        print_osquery_helper(osquery);
    }

    // Handle step action
    if let Some(ref action) = step.action {
        execute_action(action, ctx)?;
    } else {
        // Just confirm to continue
        prompt_action(None)?;
    }

    Ok(())
}

/// Print an osquery helper in a nice box.
fn print_osquery_helper(osquery: &super::step::OsqueryQuery) {
    println!("{}", "Helpful osquery (run in Fleet):".bold());
    println!("  {}", osquery.description.dimmed());
    println!();
    println!("  {}", "─".repeat(66));
    for line in osquery.sql.trim().lines() {
        println!("  {}", line.cyan());
    }
    println!("  {}", "─".repeat(66));
    println!();
}

/// Execute a step action (educational - shows commands for user to run).
fn execute_action(action: &StepAction, _ctx: &TrainerContext) -> Result<()> {
    match action {
        StepAction::ContourCommand { args } => {
            let cmd_str = format!("contour {}", args.join(" "));
            println!("{} {}", "Run this command:".bold(), cmd_str.green());
            println!();
            prompt_action(Some(&cmd_str))?;
        }

        StepAction::ShowFile { path } => {
            println!(
                "{} {}",
                "File to review:".bold(),
                path.display().to_string().green()
            );
            println!();

            if path.exists() {
                let preview = std::fs::read_to_string(path)?;
                let lines: Vec<&str> = preview.lines().take(20).collect();
                println!("{}", "Preview (first 20 lines):".dimmed());
                println!("{}", "─".repeat(66));
                for line in lines {
                    println!("  {line}");
                }
                if preview.lines().count() > 20 {
                    println!("  {} ...and more", "...".dimmed());
                }
                println!("{}", "─".repeat(66));
            } else {
                println!(
                    "{} File does not exist yet: {}",
                    "Note:".yellow(),
                    path.display()
                );
            }
            println!();
            prompt_action(None)?;
        }

        StepAction::EditFile { path } => {
            let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vim".to_string());
            let cmd_str = format!("{} {}", editor, path.display());
            println!("{} {}", "File to edit:".bold(), cmd_str.green());
            println!();
            prompt_action(Some(&cmd_str))?;
        }

        StepAction::GitOperation { op } => {
            show_git_operation(op)?;
        }

        StepAction::ConfirmContinue => {
            prompt_action(None)?;
        }
    }

    Ok(())
}

/// Show git operation commands (educational - user runs them manually).
fn show_git_operation(op: &GitOp) -> Result<()> {
    match op {
        GitOp::Commit { message } => {
            let cmd_str = format!("git add . && git commit -m {message:?}");
            println!("{}", "Git Commit".bold());
            println!();
            println!("{} {}", "Run:".bold(), cmd_str.green());
            println!();
            prompt_action(Some(&cmd_str))?;
        }

        GitOp::CreatePr { title, body } => {
            println!("{}", "Create Pull Request".bold());
            println!();
            println!("{}", "Suggested PR:".dimmed());
            println!("  Title: {title}");
            let body_first_line = body.lines().next().unwrap_or("");
            println!("  Body:  {body_first_line}");
            println!();
            let cmd_str = format!("gh pr create --title {title:?}");
            println!("{} {}", "Run:".bold(), cmd_str.green());
            println!();
            prompt_action(Some(&cmd_str))?;
        }
    }

    Ok(())
}

/// Action choices for interactive steps.
#[derive(Debug, Clone, Copy)]
enum ActionChoice {
    Continue,
    Copy,
}

impl std::fmt::Display for ActionChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ActionChoice::Continue => write!(f, "Continue to next step"),
            ActionChoice::Copy => write!(f, "Copy command to clipboard"),
        }
    }
}

/// Prompt for action with optional command to copy.
fn prompt_action(command: Option<&str>) -> Result<()> {
    loop {
        let choices = if command.is_some() {
            vec![ActionChoice::Continue, ActionChoice::Copy]
        } else {
            vec![ActionChoice::Continue]
        };

        let choice = Select::new("What would you like to do?", choices)
            .with_help_message("↑↓ to move, Enter to select")
            .prompt()?;

        match choice {
            ActionChoice::Continue => return Ok(()),
            ActionChoice::Copy => {
                if let Some(cmd) = command {
                    copy_to_clipboard(cmd)?;
                    println!("{}", "✓ Copied to clipboard!".green());
                }
                // Loop back to prompt again after copying
            }
        }
    }
}

/// Copy text to clipboard using pbcopy (macOS).
fn copy_to_clipboard(text: &str) -> Result<()> {
    if cfg!(not(target_os = "macos")) {
        anyhow::bail!("Clipboard access requires macOS (uses `pbcopy` command)");
    }
    let mut child = Command::new("pbcopy").stdin(Stdio::piped()).spawn()?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(text.as_bytes())?;
    }

    child.wait()?;
    Ok(())
}
