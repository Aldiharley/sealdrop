//! Without the `test-support` feature the library (compiled without `cfg(test)`, as
//! integration tests see it) has no `memory://` shortcut.
#![cfg(not(feature = "test-support"))]

#[test]
fn memory_scheme_is_rejected_in_production_builds() {
    assert!(sealdrop_core::release::validate_service_url("memory://svc").is_err());
    assert!(sealdrop_core::release::validate_service_url("https://svc.example").is_ok());
}
