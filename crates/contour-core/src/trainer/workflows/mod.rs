//! Workflow implementations for trainer mode.

pub mod mscp;
pub mod pppc;
pub mod profile;
pub mod santa;

pub use mscp::MscpWorkflow;
pub use pppc::PppcWorkflow;
pub use profile::ProfileWorkflow;
pub use santa::SantaWorkflow;
