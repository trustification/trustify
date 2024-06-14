use sea_orm::{
    ConnectionTrait, DbErr, EntityTrait, FromQueryResult, Paginator, PaginatorTrait, QuerySelect,
    Select, SelectModel, SelectTwo, SelectTwoModel, Selector, SelectorTrait,
};
use std::num::NonZeroU64;

pub struct Limiter<'db, C, S1, S2>
where
    C: ConnectionTrait,
    S1: SelectorTrait + 'db,
    S2: SelectorTrait + 'db,
{
    db: &'db C,
    selector: Selector<S1>,
    paginator: Paginator<'db, C, S2>,
}

impl<'db, C, S1, S2> Limiter<'db, C, S1, S2>
where
    C: ConnectionTrait,
    S1: SelectorTrait + 'db,
    S2: SelectorTrait + 'db,
{
    pub async fn fetch(self) -> Result<Vec<S1::Item>, DbErr> {
        self.selector.all(self.db).await
    }

    pub async fn total(&self) -> Result<u64, DbErr> {
        self.paginator.num_items().await
    }
}

pub trait LimiterTrait<'db, C>
where
    C: ConnectionTrait,
{
    type FetchSelector: SelectorTrait + 'db;
    type CountSelector: SelectorTrait + 'db;

    fn limiting(
        self,
        db: &'db C,
        offset: u64,
        limit: u64,
    ) -> Limiter<'db, C, Self::FetchSelector, Self::CountSelector>;
}

impl<'db, C, E, M> LimiterTrait<'db, C> for Select<E>
where
    C: ConnectionTrait,
    E: EntityTrait<Model = M>,
    M: FromQueryResult + Sized + Send + Sync + 'db,
{
    type FetchSelector = SelectModel<M>;
    type CountSelector = SelectModel<M>;

    fn limiting(
        self,
        db: &'db C,
        offset: u64,
        limit: u64,
    ) -> Limiter<'db, C, Self::FetchSelector, Self::CountSelector> {
        let selector = self
            .clone()
            .limit(NonZeroU64::new(limit).map(|limit| limit.get()))
            .offset(NonZeroU64::new(offset).map(|offset| offset.get()))
            .into_model();

        Limiter {
            db,
            paginator: self.clone().paginate(db, 1),
            selector,
        }
    }
}

pub trait LimiterAsModelTrait<'db, C>
where
    C: ConnectionTrait,
{
    fn limiting_as<M: FromQueryResult + Sync + Send>(
        self,
        db: &'db C,
        offset: u64,
        limit: u64,
    ) -> Limiter<'db, C, SelectModel<M>, SelectModel<M>>;
}

impl<'db, C, E> LimiterAsModelTrait<'db, C> for Select<E>
where
    C: ConnectionTrait,
    E: EntityTrait,
{
    fn limiting_as<M: FromQueryResult + Sync + Send>(
        self,
        db: &'db C,
        offset: u64,
        limit: u64,
    ) -> Limiter<'db, C, SelectModel<M>, SelectModel<M>> {
        let selector = self
            .clone()
            .limit(NonZeroU64::new(limit).map(|limit| limit.get()))
            .offset(NonZeroU64::new(offset).map(|offset| offset.get()))
            .into_model::<M>();

        Limiter {
            db,
            paginator: self.clone().into_model::<M>().paginate(db, 1),
            selector,
        }
    }
}

pub fn limit_selector<'db, C, E, EM, M>(
    db: &'db C,
    select: Select<E>,
    offset: u64,
    limit: u64,
) -> Limiter<'db, C, SelectModel<M>, SelectModel<EM>>
where
    C: ConnectionTrait,
    E: EntityTrait<Model = EM>,
    M: FromQueryResult + Sized + Send + Sync + 'db,
    EM: FromQueryResult + Sized + Send + Sync + 'db,
{
    let selector = select
        .clone()
        .limit(NonZeroU64::new(limit).map(|limit| limit.get()))
        .offset(NonZeroU64::new(offset).map(|offset| offset.get()))
        .into_model();

    Limiter {
        db,
        paginator: select.paginate(db, 1),
        selector,
    }
}

impl<'db, C, M1, M2, E1, E2> LimiterTrait<'db, C> for SelectTwo<E1, E2>
where
    C: ConnectionTrait,
    E1: EntityTrait<Model = M1>,
    E2: EntityTrait<Model = M2>,
    M1: FromQueryResult + Sized + Send + Sync + 'db,
    M2: FromQueryResult + Sized + Send + Sync + 'db,
{
    type FetchSelector = SelectTwoModel<M1, M2>;
    type CountSelector = SelectTwoModel<M1, M2>;

    fn limiting(
        self,
        db: &'db C,
        offset: u64,
        limit: u64,
    ) -> Limiter<'db, C, Self::FetchSelector, Self::CountSelector> {
        let selector = self
            .clone()
            .limit(NonZeroU64::new(limit).map(|limit| limit.get()))
            .offset(NonZeroU64::new(offset).map(|offset| offset.get()))
            .into_model();

        Limiter {
            db,
            paginator: self.clone().paginate(db, 1),
            selector,
        }
    }
}
