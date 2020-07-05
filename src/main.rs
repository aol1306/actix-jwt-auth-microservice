// start db using: docker run --rm -p27017:27017 mongo

use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use chrono::offset::Utc;
use mongodb::bson;
use mongodb::bson::doc;
use mongodb::Client;
use serde::{Deserialize, Serialize};
use std::time::Instant;
/// Service listen address
static LISTEN_ADDR: &str = "127.0.0.1:8080";

/// Mongodb address
static MONGO_ADDR: &str = "mongodb://127.0.0.1:27017";

/// Mongodb database name
static DB_NAME: &str = "mydb";

/// JWT key
static JWT_KEY: &[u8; 6] = b"secret";

/// default token validity time
static TOKEN_VALID_TIME: i64 = 60 * 60; // one hour

/// Shared state for application endpoints
struct DbHandle {
    client: mongodb::Client,
}

/// Structure for user data in db
#[derive(Serialize, Deserialize, Debug)]
struct User {
    username: String,
    password: String,
}

/// JWT - https://tools.ietf.org/html/rfc7519, https://jwt.io/
#[derive(Serialize, Deserialize, Debug)]
struct Claims {
    username: String,
    exp: usize,
}

/// API landing page
async fn index() -> impl Responder {
    // measure reponse time
    let now = Instant::now();

    HttpResponse::Ok().body(format!("Hello - took {} sec", now.elapsed().as_secs_f64()))
}

// check if JWT token is valid - authorization bearer header
async fn validate(req: HttpRequest) -> impl Responder {
    use jsonwebtoken::errors::ErrorKind;
    use jsonwebtoken::{decode, DecodingKey, Validation};

    // measure reponse time
    let now = Instant::now();

    // get token from header
    let auth_header_value = match req.headers().get("Authorization") {
        Some(t) => t,
        None => {
            return HttpResponse::BadRequest().body(format!(
                "auth token missing - took {} sec",
                now.elapsed().as_secs_f64()
            ))
        }
    };
    let token = match auth_header_value.to_str() {
        Ok(v) => match v.split(" ").collect::<Vec<&str>>().get(1).copied() {
            Some(v) => v,
            None => {
                return HttpResponse::BadRequest().body(format!(
                    "error parsing token - took {} sec",
                    now.elapsed().as_secs_f64()
                ))
            }
        },
        Err(_) => {
            return HttpResponse::BadRequest().body(format!(
                "error parsing token - took {} sec",
                now.elapsed().as_secs_f64()
            ))
        }
    };

    // validate token
    let validation = Validation {
        ..Validation::default()
    };
    let token_data = match decode::<Claims>(&token, &DecodingKey::from_secret(JWT_KEY), &validation)
    {
        Ok(c) => c,
        Err(err) => match *err.kind() {
            ErrorKind::InvalidToken => {
                return HttpResponse::Ok().body(format!(
                    "token invalid - took {} sec",
                    now.elapsed().as_secs_f64()
                ))
            }
            ErrorKind::InvalidIssuer => {
                return HttpResponse::Ok().body(format!(
                    "issuer invalid - took {} sec",
                    now.elapsed().as_secs_f64()
                ))
            }
            ErrorKind::ExpiredSignature => {
                return HttpResponse::Ok().body(format!(
                    "token expired - took {} sec",
                    now.elapsed().as_secs_f64()
                ))
            }
            _ => {
                println!("other error: {:?}", err.kind());
                return HttpResponse::Ok().body(format!(
                    "other error - took {} sec",
                    now.elapsed().as_secs_f64()
                ));
            }
        },
    };

    dbg!(&token_data.claims);

    // calculate exp time (but no need to worry about validity - the library checks exp and throws ExpiredSignature)
    let token_valid_for = token_data.claims.exp - (Utc::now().timestamp() as usize);

    HttpResponse::Ok().body(format!(
        "Validated. This token will be vaild for {} sec - took {} sec",
        token_valid_for,
        now.elapsed().as_secs_f64()
    ))
}

/// Create token
async fn auth(body: web::Json<User>, dbh: web::Data<DbHandle>) -> impl Responder {
    // measure reponse time
    let now = Instant::now();

    // check if user exists in db
    let client = &dbh.client;
    let db = client.database(DB_NAME);
    let collection = db.collection("users");
    let document = match bson::to_bson(&body.0).unwrap() {
        bson::Bson::Document(doc) => doc,
        _ => panic!("failed to create document (should never happen)"),
    };
    match collection
        .find_one(document, None)
        .await
        .expect("error finding in collection")
    {
        Some(_) => {
            use jsonwebtoken::{encode, EncodingKey, Header};
            // user found - create JWT
            let claims = Claims {
                username: body.username.clone(),
                exp: (Utc::now().timestamp() + TOKEN_VALID_TIME) as usize,
            };
            let token = encode(
                &Header::default(),
                &claims,
                &EncodingKey::from_secret(JWT_KEY),
            )
            .expect("failed to create JWT token");

            dbg!(&token);

            // send JWT in custom header
            HttpResponse::Ok()
                .set_header("X-App-Token", token)
                .body(format!(
                    "Auth ok - user and pass found - took {} sec",
                    now.elapsed().as_secs_f64()
                ))
        }
        None => HttpResponse::Ok().body(format!(
            "Auth failed - user and pass not found - took {} sec",
            now.elapsed().as_secs_f64()
        )),
    }
}

/// Register new user - does not check if username is taken though
async fn register(body: web::Json<User>, dbh: web::Data<DbHandle>) -> impl Responder {
    // measure reponse time
    let now = Instant::now();

    dbg!(&body);

    // add to db
    let client = &dbh.client;
    let db = client.database(DB_NAME);
    let collection = db.collection("users");
    let new_user = User {
        username: body.username.clone(),
        password: body.password.clone(),
    };
    let document = match bson::to_bson(&new_user).unwrap() {
        bson::Bson::Document(doc) => doc,
        _ => panic!("failed to create document (should never happen)"),
    };
    collection
        .insert_one(document, None)
        .await
        .expect("error adding user to database");

    // send response
    HttpResponse::Ok().body(format!(
        "Register new user - took {} sec",
        now.elapsed().as_secs_f64()
    ))
}

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    println!("Connecting to db at {}...", MONGO_ADDR);
    let db_handle = web::Data::new(DbHandle {
        client: Client::with_uri_str(MONGO_ADDR)
            .await
            .expect("error connecting to db"),
    });

    println!("Listening on {}", LISTEN_ADDR);

    HttpServer::new(move || {
        App::new()
            .app_data(db_handle.clone())
            .route("/", web::get().to(index))
            .route("/register", web::post().to(register))
            .route("/auth", web::get().to(auth))
            .route("/validate", web::get().to(validate))
    })
    .bind(LISTEN_ADDR)?
    .run()
    .await
}
