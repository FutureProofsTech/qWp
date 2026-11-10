//! Individual extended-attack tests, so failures name the broken property.

use qwp_attacks::{
    attack_cross_version, attack_ed25519_edge_cases, attack_message_boundaries,
    attack_public_key_mutations, attack_qhs6_component_binding, attack_structural_checksums,
};

#[test]
fn structural_checksums() {
    assert!(attack_structural_checksums());
}

#[test]
fn message_boundaries() {
    assert!(attack_message_boundaries());
}

#[test]
fn public_key_mutations() {
    assert!(attack_public_key_mutations());
}

#[test]
fn cross_version() {
    assert!(attack_cross_version());
}

#[test]
fn qhs6_component_binding() {
    assert!(attack_qhs6_component_binding());
}

#[test]
fn ed25519_edge_cases() {
    assert!(attack_ed25519_edge_cases());
}
