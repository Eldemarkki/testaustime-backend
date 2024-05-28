use std::collections::HashMap;

use actix_web::{
    cookie::Cookie,
    error::*,
    web::{Data, Query},
    HttpResponse, Responder,
};
use awc::Client;
use serde_derive::Deserialize;

use crate::{database::DatabaseWrapper, error::TimeError};

#[derive(Deserialize)]
struct TokenExchangeRequest {
    code: String,
}

#[derive(Deserialize, Debug)]
struct TokenResponse {
    token: String,
}

#[cfg(feature = "testausid")]
#[derive(Debug, Deserialize, Clone)]
pub struct ClientInfo {
    #[serde(rename = "client_id")]
    pub id: String,
    #[serde(rename = "client_secret")]
    pub secret: String,
    pub redirect_uri: String,
}

#[derive(Deserialize, Debug)]
struct TestausIdApiUser {
    id: String,
    name: String,
    platform: TestausIdPlatformInfo,
}

#[derive(Deserialize, Debug)]
struct TestausIdPlatformInfo {
    id: String,
}

#[get("/auth/callback")]
async fn callback(
    request: Query<TokenExchangeRequest>,
    client: Data<Client>,
    oauth_client: Data<ClientInfo>,
    db: DatabaseWrapper,
) -> Result<impl Responder, TimeError> {
    if request.code.chars().any(|c| !c.is_alphanumeric()) {
        return Err(TimeError::BadCode);
    }

    let res = client
        .post("http://id.testausserveri.fi/api/v1/token")
        .insert_header(("content-type", "application/x-www-form-urlencoded"))
        .send_form(&HashMap::from([
            ("code", &request.code),
            ("redirect_uri", &oauth_client.redirect_uri),
            ("client_id", &oauth_client.id),
            ("client_secret", &oauth_client.secret),
        ]))
        .await
        .unwrap()
        .json::<TokenResponse>()
        .await
        .unwrap();

    let res = client
        .get("http://id.testausserveri.fi/api/v1/me")
        .insert_header(("Authorization", format!("Bearer {}", res.token)))
        .send()
        .await
        .unwrap()
        .json::<TestausIdApiUser>()
        .await
        .unwrap();

    let token = db
        .testausid_login(res.id, res.name, res.platform.id)
        .await?;

    Ok(HttpResponse::PermanentRedirect()
        .insert_header(("location", "https://testaustime.fi/oauth_redirect"))
        .cookie(
            Cookie::build("testaustime_token", token)
                .domain("testaustime.fi")
                .path("/")
                .secure(true)
                .finish(),
        )
        .finish())
}
