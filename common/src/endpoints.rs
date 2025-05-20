pub mod guards {
    use actix_web::guard::{self, Guard, GuardContext};

    pub const JSON_MERGE_CONTENT_TYPE: &str = "application/merge-patch+json";

    pub fn json_merge(ctx: &GuardContext) -> bool {
        guard::Header("content-type", JSON_MERGE_CONTENT_TYPE).check(ctx)
    }
}
