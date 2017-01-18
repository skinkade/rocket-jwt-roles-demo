#![feature(plugin)]
#![plugin(rocket_codegen)]
#![feature(custom_derive)]

use std::io;
use std::env;
use std::collections::HashMap;

extern crate rocket;
use rocket::request::Form;
use rocket::response::NamedFile;
use rocket::response::Redirect;
use rocket::http::{Cookie, Cookies};

extern crate rocket_contrib;
use rocket_contrib::Template;

extern crate dotenv;
use dotenv::dotenv;



// DATABASE
//      Bring in Diesel and the schema for our `users` table
//      Function to establish connection for querying
//      Blatant copy-paste of Diesel how-to
//
#[macro_use]
extern crate diesel;
use diesel::prelude::*;
use diesel::pg::PgConnection;
#[macro_use]
extern crate diesel_codegen;

pub mod schema;
pub mod models;


fn establish_connection() -> PgConnection {
    dotenv().ok();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    PgConnection::establish(&database_url).expect(&format!("Error connecting to {}", database_url))
}



// JSON WEB TOKEN
//      Our `users` table contain a text array of a given user's roles
//      When we verify a user, we give them a signed token confirming their
//          identity and roles, so we don't need to handle sessions
//
extern crate time;
extern crate rustc_serialize;
extern crate jsonwebtoken as jwt;
use jwt::{encode, decode, Header, Algorithm};

extern crate argon2rs;
use argon2rs::verifier::Encoded;

// head -c16 /dev/urandom > secret.key
static KEY: &'static [u8; 16] = include_bytes!("../secret.key");
static ONE_WEEK: i64 = 60 * 60 * 24 * 7;


#[derive(Debug, RustcEncodable, RustcDecodable)]
struct UserRolesToken {
    // issued at
    iat: i64,
    // expiration
    exp: i64,
    user: String,
    roles: Vec<String>,
}

// only has_role() is used in this demo
impl UserRolesToken {
    fn is_expired(&self) -> bool {
        let now = time::get_time().sec;
        now >= self.exp
    }

    fn is_claimed_user(&self, claimed_user: String) -> bool {
        self.user == claimed_user
    }

    fn has_role(&self, role: &str) -> bool {
        self.roles.contains(&role.to_string())
    }
}


fn jwt_generate(user: String, roles: Vec<String>) -> String {
    let now = time::get_time().sec;
    let payload = UserRolesToken {
        iat: now,
        exp: now + ONE_WEEK,
        user: user,
        roles: roles,
    };

    encode(Header::default(), &payload, KEY).unwrap()
}



// AUTHENTICATION
//      Pretty self-explanatory
//          - Get row of the user
//          - Compare the password hash
//          - Generate them a JWT
//          - Stash the token in their cookie
//      If any of these steps fails, keep them on the login page
//
#[derive(FromForm)]
struct Login {
    username: String,
    password: String,
}

#[post("/login", data="<login_form>")]
fn login(cookies: &Cookies, login_form: Form<Login>) -> Redirect {
    use schema::users::dsl::*;

    let login = login_form.get();
    let connection = establish_connection();

    let user = match users.filter(username.eq(&login.username))
        .first::<models::User>(&connection) {
        Ok(u) => u,
        Err(_) => return Redirect::to("/login"),
    };

    let hash = user.pw_hash.into_bytes();

    // Argon2 password verifier
    let db_hash = Encoded::from_u8(&hash).expect("Failed to read password hash");
    if !db_hash.verify(login.password.as_ref()) {
        return Redirect::to("/login");
    }

    // Add JWT to cookies
    cookies.add(Cookie::new("jwt".into(), jwt_generate(user.username, user.user_roles)));

    Redirect::to("/")
}

#[get("/login")]
fn login_page() -> io::Result<NamedFile> {
    NamedFile::open("static/login.html")
}

#[post("/logout")]
fn logout(cookies: &Cookies) -> Redirect {
    cookies.remove("jwt");
    Redirect::to("/")
}



// ADMIN
//      By using a dynamic path in our main handler, we can use a single block
//      of cookie-check code to verify if the user has the admin role. Then,
//      pseudo-redirect the request to another function
//
//      By returning 404 instead of 403, we don't reveal that these pages exist
//      ... also trying to use Result and returning Err(Status) resulted in 500
//
#[get("/admin/<path>")]
fn admin_handler(cookies: &Cookies, path: &str) -> Option<Template> {
    let token = match cookies.find("jwt").map(|cookie| cookie.value) {
        Some(jwt) => jwt,
        _ => return None,
    };

    // You'll want to match on and log errors instead of unwrapping, of course
    let token_data = decode::<UserRolesToken>(&token, KEY, Algorithm::HS256).unwrap();

    if !token_data.claims.has_role("admin") {
        return None;
    }

    match path {
        "index" => return Some(admin_index()),
        "user" => return Some(display_user(token_data.claims.user)),
        _ => return None,
    }
}

fn admin_index() -> Template {
    let mut context = HashMap::new();
    context.insert("message", "Congrats, you're an admin.");
    Template::render("admin/index", &context)
}

fn display_user(user: String) -> Template {
    use schema::users::dsl::*;
    let connection = establish_connection();
    let user = users.filter(username.eq(&user))
        .first::<models::User>(&connection)
        .expect(&format!("Failed to retrieve {}", user));

    let mut context = HashMap::new();
    context.insert("user",
                   vec![user.username, format!("{:?}", user.user_roles)].join(", "));

    Template::render("admin/console", &context)
}



// LAUNCHER
//      Index page to redirect user to login, or render their name
//      Start application
//
#[get("/")]
fn index(cookies: &Cookies) -> Result<Template, Redirect> {
    let token = match cookies.find("jwt").map(|msg| msg.value) {
        Some(jwt) => jwt,
        None => return Err(Redirect::to("/login")),
    };

    let token_data = decode::<UserRolesToken>(&token, KEY, Algorithm::HS256).unwrap();

    let mut context = HashMap::new();
    context.insert("name", token_data.claims.user.clone());

    if token_data.claims.has_role("admin") {
        context.insert("admin", "true".to_string());
    }

    Ok(Template::render("index", &context))
}

fn main() {
    rocket::ignite()
        .mount("/",
               routes![index, login, login_page, logout, admin_handler])
        .launch();
}
