//! MAKI-027: export geometry must fit nbdkit's signed size interface.
use maki_format::geometry::Geometry;

#[test]
fn geometry_refuses_sizes_that_cannot_be_exported_by_nbdkit() {
    let last = (i64::MAX as u64) & !4095;
    // Keep the possible shard count within the catalog limit so this fixture
    // isolates the signed NBD export-size boundary.
    assert!(Geometry::compute(4096, 4096, 512, 4384, last, 1 << 40).is_ok());
    for size in [last + 4096, !4095_u64] {
        let error = Geometry::compute(4096, 4096, 512, 4384, size, 1 << 40)
            .expect_err("a negative get_size result cannot describe an export");
        assert!(error.to_string().contains("max_virtual_size"), "{error}");
    }
}
