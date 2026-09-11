//! MAKI-027: export geometry must fit nbdkit's signed size interface.
use maki_format::geometry::Geometry;

#[test]
fn geometry_refuses_sizes_that_cannot_be_exported_by_nbdkit() {
    let last = (i64::MAX as u64) & !4095;
    assert!(Geometry::compute(4096, 4096, 512, 4384, last, 64 << 30).is_ok());
    for size in [last + 4096, u64::MAX & !4095] {
        let error = Geometry::compute(4096, 4096, 512, 4384, size, 64 << 30)
            .expect_err("a negative get_size result cannot describe an export");
        assert!(error.to_string().contains("max_virtual_size"), "{error}");
    }
}
