//! Step definitions for trainer workflows.

use std::path::PathBuf;

/// A single step in a trainer workflow.
#[derive(Debug, Clone)]
pub struct TrainerStep {
    /// Step number (1-indexed for display).
    pub number: usize,
    /// Short title for the step.
    pub title: String,
    /// Detailed explanation of what this step does.
    pub explanation: String,
    /// Commands that will be executed or previewed.
    pub commands: Vec<CommandPreview>,
    /// Optional osquery SQL helpers for fleet-wide data.
    pub osquery: Option<OsqueryQuery>,
    /// The action to perform for this step.
    pub action: Option<StepAction>,
}

impl TrainerStep {
    /// Create a new step with the given number and title.
    #[must_use]
    pub fn new(number: usize, title: impl Into<String>) -> Self {
        Self {
            number,
            title: title.into(),
            explanation: String::new(),
            commands: Vec::new(),
            osquery: None,
            action: None,
        }
    }

    /// Add an explanation to the step.
    #[must_use]
    pub fn with_explanation(mut self, explanation: impl Into<String>) -> Self {
        self.explanation = explanation.into();
        self
    }

    /// Add a command preview.
    #[must_use]
    pub fn with_command(mut self, command: CommandPreview) -> Self {
        self.commands.push(command);
        self
    }

    /// Add multiple command previews.
    #[must_use]
    pub fn with_commands(mut self, commands: Vec<CommandPreview>) -> Self {
        self.commands.extend(commands);
        self
    }

    /// Add an osquery helper.
    #[must_use]
    pub fn with_osquery(mut self, osquery: OsqueryQuery) -> Self {
        self.osquery = Some(osquery);
        self
    }

    /// Set the action for this step.
    #[must_use]
    pub fn with_action(mut self, action: StepAction) -> Self {
        self.action = Some(action);
        self
    }
}

/// A command preview shown to the user.
#[derive(Debug, Clone)]
pub struct CommandPreview {
    /// The full command that would be run.
    pub command: String,
    /// A brief description of what the command does.
    pub description: String,
}

impl CommandPreview {
    /// Create a new command preview.
    #[must_use]
    pub fn new(command: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            command: command.into(),
            description: description.into(),
        }
    }
}

/// An osquery SQL helper for gathering fleet-wide data.
#[derive(Debug, Clone)]
pub struct OsqueryQuery {
    /// Description of what this query does.
    pub description: String,
    /// The SQL query to run in Fleet/osquery.
    pub sql: String,
}

impl OsqueryQuery {
    /// Create a new osquery helper.
    #[must_use]
    pub fn new(description: impl Into<String>, sql: impl Into<String>) -> Self {
        Self {
            description: description.into(),
            sql: sql.into(),
        }
    }
}

/// Actions that can be performed in a step.
#[derive(Debug, Clone)]
pub enum StepAction {
    /// Run a contour subcommand.
    ContourCommand {
        /// The subcommand and arguments (e.g., `["santa", "scan", "-o", "local-apps.csv"]`).
        args: Vec<String>,
    },
    /// Show a file's contents.
    ShowFile {
        /// Path to the file to display.
        path: PathBuf,
    },
    /// Open a file in the user's editor.
    EditFile {
        /// Path to the file to edit.
        path: PathBuf,
    },
    /// Perform a git operation.
    GitOperation {
        /// The git operation to perform.
        op: GitOp,
    },
    /// Just confirm and continue.
    ConfirmContinue,
}

/// Git operations that can be performed.
#[derive(Debug, Clone)]
pub enum GitOp {
    /// Stage and commit changes.
    Commit {
        /// Suggested commit message.
        message: String,
    },
    /// Create a pull request.
    CreatePr {
        /// Suggested PR title.
        title: String,
        /// Suggested PR body.
        body: String,
    },
}
