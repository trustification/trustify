use actix_web::{
    dev::{ServiceFactory, ServiceRequest},
    web, App,
};
use trustify_auth::authorizer::Authorizer;
use utoipa_actix_web::UtoipaApp;

pub trait TestApp: Sized {
    /// Add an authorizer, suitable for testing
    fn add_test_authorizer(self) -> Self;
}

impl<T> TestApp for UtoipaApp<T>
where
    T: ServiceFactory<ServiceRequest, Config = (), Error = actix_web::Error, InitError = ()>,
{
    fn add_test_authorizer(self) -> Self {
        self.map(|app| app.add_test_authorizer())
    }
}

impl<T> TestApp for App<T>
where
    T: ServiceFactory<ServiceRequest, Config = (), Error = actix_web::Error, InitError = ()>,
{
    fn add_test_authorizer(self) -> Self {
        // today we add an authorizer, with authorization disabled.
        let authorizer = Authorizer::default();
        self.app_data(web::Data::new(authorizer))
    }
}
