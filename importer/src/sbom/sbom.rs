use async_trait::async_trait;
use sbom_walker::validation::{
    ValidatedSbom, ValidatedVisitor, ValidationContext, ValidationError,
};

pub struct ProcessVisitor;

#[async_trait(?Send)]
impl ValidatedVisitor for ProcessVisitor {
    type Error = anyhow::Error;
    type Context = ();

    async fn visit_context(&self, _: &ValidationContext) -> Result<Self::Context, Self::Error> {
        Ok(())
    }

    async fn visit_sbom(
        &self,
        _context: &Self::Context,
        result: Result<ValidatedSbom, ValidationError>,
    ) -> Result<(), Self::Error> {
        println!("Processing {:?}", result?.url);

        Ok(())
    }
}
