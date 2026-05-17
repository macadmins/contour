//! Workflow implementations for trainer mode.

pub mod btm;
pub mod config;
pub mod mscp;
pub mod pppc;
pub mod profile;
pub mod santa;

pub use btm::BtmWorkflow;
pub use config::ConfigWorkflow;
pub use mscp::MscpWorkflow;
pub use pppc::PppcWorkflow;
pub use profile::ProfileWorkflow;
pub use santa::SantaWorkflow;
