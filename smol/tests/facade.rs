#[test]
fn the_top_level_names_are_the_crate_names() {
    fn takes_session(_: Option<smol::Session>) {}
    fn takes_ctl_session(_: Option<smol::ctl::Session>) {}

    takes_session(None);
    takes_ctl_session(None);

    let _: fn(String, String) -> smol::JoinConfig = smol::JoinConfig::new;
    let _: fn(String, String) -> smol::ctl::JoinConfig = smol::ctl::JoinConfig::new;
}

#[test]
fn the_submodules_alias_each_crate() {
    assert_eq!(smol::MESH_MTU, smol::mesh::MESH_MTU);
    assert_eq!(smol::MESH_MTU, smolmesh::MESH_MTU);

    let _: smol::net::addr::MacAddr = [0; 6];
    let _: smol::NetworkId = smol::mesh::NetworkId::random();
}

#[test]
fn a_node_can_be_configured_through_the_facade() {
    let node = smol::NodeConfig::new("http://control.example", "token");

    assert_eq!(node.mtu, smol::MESH_MTU);
    assert!(node.configure_interface);
}

#[cfg(target_os = "linux")]
#[test]
fn the_runner_is_reachable_on_linux() {
    let run = smol::RunConfig::new(vec!["/bin/true".to_owned()]);

    assert_eq!(run.command, vec!["/bin/true".to_owned()]);
    assert!(!run.allow_io_uring);
}
