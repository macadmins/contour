//! Trainer mode for interactive learning of GitOps workflows.
//!
//! The trainer module provides step-by-step guidance for users learning
//! Contour's GitOps workflows. Each workflow is broken into discrete steps
//! with explanations, command previews, and helpful osquery snippets.

pub mod queries;
pub mod runner;
pub mod step;
pub mod workflows;

use anyhow::Result;
use std::path::PathBuf;

/// Context for trainer mode execution.
#[derive(Debug, Clone)]
pub struct TrainerContext {
    /// The current working directory.
    pub working_dir: PathBuf,
    /// Whether to use verbose output.
    pub verbose: bool,
    /// JSON output mode.
    pub json: bool,
}

impl TrainerContext {
    /// Create a new trainer context.
    #[must_use]
    pub fn new(working_dir: PathBuf) -> Self {
        Self {
            working_dir,
            verbose: false,
            json: false,
        }
    }

    /// Enable verbose output.
    #[must_use]
    pub fn with_verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    /// Enable JSON output.
    #[must_use]
    pub fn with_json(mut self, json: bool) -> Self {
        self.json = json;
        self
    }
}

impl Default for TrainerContext {
    fn default() -> Self {
        Self::new(std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
    }
}

/// Trait for workflow implementations.
pub trait TrainerWorkflow {
    /// Get the name of this workflow.
    fn name(&self) -> &'static str;

    /// Get a description of this workflow.
    fn description(&self) -> &'static str;

    /// Get the steps in this workflow.
    fn steps(&self) -> Vec<step::TrainerStep>;

    /// Run the workflow interactively.
    fn run(&self, ctx: &TrainerContext) -> Result<()> {
        runner::run_workflow(self.steps(), ctx)
    }
}
