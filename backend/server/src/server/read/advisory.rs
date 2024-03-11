use crate::dto::AdvisoryDto;
use crate::server::Error;
use crate::AppState;
use actix_web::{get, post, web, HttpResponse, Responder};
use trustify_api::db::{Paginated, Transactional};

#[utoipa::path(responses((status = 200, description = "List advisories")), )]
#[get("/advisories")]
pub async fn list_advisories(
    state: web::Data<AppState>,
    paginated: web::Query<Paginated>,
) -> Result<impl Responder, Error> {
    let advisories = state
        .system
        .list_advisories(paginated.into_inner(), Transactional::None)
        .await
        .map_err(Error::System)?;

    Ok(HttpResponse::Ok()
        .append_header(("x-total", advisories.num_items))
        .json(
            advisories
                .results
                .into_iter()
                .map(|ctx| AdvisoryDto::from(ctx.advisory))
                .collect::<Vec<_>>(),
        ))
}
