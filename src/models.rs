#[derive(Queryable)]
pub struct User {
    pub username: String,
    pub pw_hash: String,
    pub user_roles: Vec<String>,
}
