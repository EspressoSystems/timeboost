use std::future::{Ready, ready};

use axum::body::Body;
use http::{Request, Response, StatusCode, header::AUTHORIZATION};
use tower_http::auth::AsyncAuthorizeRequest;

#[derive(Debug, Clone)]
pub struct Authorize {
    secret: String,
}

impl Authorize {
    pub fn new(secret: String) -> Self {
        Self { secret }
    }

    #[allow(clippy::result_large_err)]
    fn check<B>(&self, r: Request<B>) -> Result<Request<B>, Response<Body>> {
        let Some(auth) = r.headers().get(AUTHORIZATION).and_then(|a| a.to_str().ok()) else {
            return Err(unauthorized());
        };
        if auth.ends_with(&self.secret) {
            return Ok(r);
        }
        Err(unauthorized())
    }
}

impl<B> AsyncAuthorizeRequest<B> for Authorize {
    type RequestBody = B;
    type ResponseBody = Body;
    type Future = Ready<Result<Request<B>, Response<Body>>>;

    fn authorize(&mut self, r: Request<B>) -> Self::Future {
        ready(self.check(r))
    }
}

fn unauthorized() -> Response<Body> {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .body(Body::empty())
        .expect("valid response")
}
