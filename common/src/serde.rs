/// Check if a value is its default value.
pub fn is_default<D: Default + Eq>(value: &D) -> bool {
    value == &Default::default()
}
