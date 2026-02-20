fn main() {
    use utoipa::OpenApi;

    let spec = iqrah_backend_api::openapi::ApiDoc::openapi()
        .to_pretty_json()
        .expect("Failed to serialize OpenAPI spec");

    print!("{spec}");
}
