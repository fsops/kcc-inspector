pub mod generator;
pub mod md_export;
pub mod report_index;
pub mod report_resource;

pub use generator::ReportGenerator;
// `Lang` lives in `crate::utils::lang` (neutral i18n layer); re-exported here for
// 为兼容旧引用 `kcc::reporting::Lang` 而重导出。
// `#[allow(unused_imports)]`: only consumed outside this crate (integration
// tests), so the bin target's duplicate module tree reports it as unused.
#[allow(unused_imports)]
pub use crate::utils::lang::Lang;
#[allow(unused_imports)]
pub use report_resource::{issue_to_resource_key, REPORT_RESOURCE_ORDER};
