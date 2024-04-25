use anyhow::Result;
use axum::{
    extract::{Path, State},
    http::{self, HeaderValue, Response, StatusCode},
    response::IntoResponse,
    routing::get,
    Router,
};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tower_http::services::ServeDir;
use tracing::{info, warn};

#[derive(Debug)]
struct HttpServeState {
    path: PathBuf,
}

pub async fn process_http_serve(path: PathBuf, port: u16) -> Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("Serving {:?} on {}", path, addr);

    let state = HttpServeState { path: path.clone() };
    // axum router
    let router = Router::new()
        .nest_service("/tower", ServeDir::new(path))
        .route("/*path", get(file_handler))
        .with_state(Arc::new(state));

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;
    Ok(())
}

async fn file_handler(
    State(state): State<Arc<HttpServeState>>,
    Path(path): Path<String>,
) -> impl IntoResponse {
    let p = std::path::Path::new(&state.path).join(path);
    info!("Reading file: {:?}", p);
    if !p.exists() {
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(format!("File {} not found", p.display()))
            .unwrap()
    } else if p.is_dir() {
        // TODO: test p is a directory
        // if it is a directory, list all files/subdirectories
        // as <li><a href="/path/to/file">file name</a></li>
        // <html><body><ul>...</ul></body></html>
        match tokio::fs::read_dir(&p).await {
            Ok(mut entries) => {
                let mut listing_html = "<ul>".to_string();
                // println!("{:?}", entries);
                while let Ok(entry_result) = entries.next_entry().await {
                    // println!("{:?}", entry_result);
                    if let Some(entry) = entry_result {
                        let file_name = entry.file_name().to_string_lossy().to_string();
                        let mut relative_path = p.clone();
                        relative_path.push(&file_name);
                        let link = format!(
                            "<li><a href={}>{}</a></li>",
                            relative_path.display(),
                            file_name
                        );
                        listing_html.push_str(&link);
                    } else {
                        warn!("Error reading directory entry");
                        break;
                    }
                }

                listing_html.push_str("</ul>");
                Response::builder()
                    .status(StatusCode::OK) // Or your appropriate status code
                    .header(
                        http::header::CONTENT_TYPE,
                        HeaderValue::from_static("text/html"),
                    )
                    .body(listing_html) // Your HTML content string
                    .unwrap()
            }
            Err(e) => {
                warn!("Error listing files: {:?}", e);
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(e.to_string())
                    .unwrap()
            }
        }
    } else {
        match tokio::fs::read_to_string(p).await {
            Ok(content) => {
                info!("Read {} bytes", content.len());
                Response::builder()
                    .status(StatusCode::OK)
                    .body(content)
                    .unwrap()
            }
            Err(e) => {
                warn!("Error reading file: {:?}", e);
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(e.to_string())
                    .unwrap()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_file_handler() {
        let state = Arc::new(HttpServeState {
            path: PathBuf::from("."),
        });
        let response = file_handler(State(state), Path("Cargo.toml".to_string()))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        // assert!(response.body().trim().starts_with("[package]"));
    }
}
