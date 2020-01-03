use bytes::buf::BufExt;
use bytes::Buf;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Client, Method, Request, Response, Server, StatusCode};
use hyper_tls::HttpsConnector;
use log::{info, trace, warn};
use serde::{Deserialize, Serialize};

type GenericError = Box<dyn std::error::Error + Send + Sync>;
type Result<T> = std::result::Result<T, GenericError>;
type HttpClient = Client<hyper_tls::HttpsConnector<hyper::client::HttpConnector>>;

#[derive(Debug, Serialize, Deserialize)]
struct DynRequest {
    domain: String,
    ip4: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct DODNSDomainRecords {
    id: u64,
    name: String,
    data: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct DODNSListDomainsResponse {
    domain_records: Vec<DODNSDomainRecords>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DODNSRecordRequest {
    name: String,
    data: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct DODNSRecordResponse {
    #[serde(rename = "type")]
    dns_type: String,
    name: String,
    data: String,
    ttl: u32,
}

#[derive(Debug)]
struct DDDError {
    msg: String,
}

impl DDDError {
    fn new(msg: &str) -> DDDError {
        DDDError {
            msg: msg.to_string(),
        }
    }
}

impl std::fmt::Display for DDDError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::result::Result<(), std::fmt::Error> {
        write!(f, "{}", self.msg)
    }
}

impl std::error::Error for DDDError {}

static DO_ACCESS_TOKEN: &str = "DO_ACCESS_TOKEN";
static DO_DOMAIN_NAME: &str = "DO_DOMAIN_NAME";

async fn get_do_subdomain_id(client: &HttpClient, domain: &str, subdomain: &str) -> Result<String> {
    trace!(
        "Resolving subdomain id for domain {} subdomain {}",
        &domain,
        &subdomain
    );
    let url = format!("https://api.digitalocean.com/v2/domains/{}/records", domain);
    let do_access_token = std::env::var(DO_ACCESS_TOKEN)?;
    let req = Request::builder()
        .method("GET")
        .uri(url)
        .header("Authorization", format!("Bearer {}", do_access_token))
        .body("".into())?;
    match client.request(req).await {
        Ok(res) => {
            trace!("Status: {}", res.status());
            if StatusCode::OK == res.status() {
                let body = hyper::body::aggregate(res).await?;
                let res: std::result::Result<DODNSListDomainsResponse, serde_json::error::Error> =
                    serde_json::from_reader(body.reader());
                match res {
                    Ok(res) => {
                        trace!("Response: {:?}", &res);
                        let res: Result<String> =
                            match res.domain_records.into_iter().find(|r| r.name == subdomain) {
                                Some(record) => {
                                    trace!("Found record: {:?}", &record);
                                    Ok(record.id.to_string())
                                }
                                None => {
                                    info!("Did not find any record for {}", &subdomain);
                                    Err(Box::new(DDDError::new(&format!(
                            "Subdomain {} does not have a record on Digital Ocean under domain {}",
                            &subdomain, &domain
                        ))))
                                }
                            };
                        res
                    }
                    Err(e) => {
                        info!("Error parsing response from DO {}", &e);
                        Err(Box::new(DDDError::new(
                            "Unable to parse response from Digital Ocean",
                        )))
                    }
                }
            } else {
                info!("Unexpected status received from DO {}", &res.status());
                Err(Box::new(DDDError::new(&format!(
                    "Digital Ocean Returned unedpected status: {}",
                    res.status()
                ))))
            }
        }
        Err(e) => {
            info!("Error fetching domain list: {}", &e);
            Err(Box::new(e))
        }
    }
}

async fn parse_request(req: Request<Body>) -> Result<DynRequest> {
    let body = hyper::body::aggregate(req).await?;
    let dyn_request: DynRequest = serde_json::from_reader(body.reader())?;
    Ok(dyn_request)
}

async fn build_do_put_request(
    domain: &str,
    domain_record_id: &str,
    do_access_token: &str,
    req: &DynRequest,
) -> Result<Request<Body>> {
    let url = format!(
        "https://api.digitalocean.com/v2/domains/{}/records/{}",
        domain, domain_record_id
    );
    info!("Set {} to {} url: {}", &req.domain, &req.ip4, &url);
    let do_request = DODNSRecordRequest {
        name: req.domain.to_string(),
        data: req.ip4.to_string(),
    };
    let payload = Body::from(serde_json::to_string(&do_request)?);
    let req = Request::builder()
        .method("PUT")
        .uri(url)
        .header("Authorization", format!("Bearer {}", do_access_token))
        .header("Content-Type", "application/json")
        .body(payload)?;
    Ok(req)
}

async fn handle(client: HttpClient, req: Request<Body>) -> Result<Response<Body>> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/") => {
            trace!("/");
            Ok(Response::new(Body::from("Ok")))
        }
        (&Method::POST, "/update") => {
            trace!("/update");
            let do_access_token = std::env::var(DO_ACCESS_TOKEN)?;
            let do_domain_name = std::env::var(DO_DOMAIN_NAME)?;
            let req = parse_request(req).await?;
            let subdomain_id = get_do_subdomain_id(&client, &do_domain_name, &req.domain).await?;
            let req = build_do_put_request(&do_domain_name, &subdomain_id, &do_access_token, &req)
                .await?;
            let res = match client.request(req).await {
                Ok(res) => {
                    let status = res.status();
                    let res_body = hyper::body::aggregate(res).await?.to_bytes();
                    trace!("Received response from DO: {}", &status);
                    match status {
                        StatusCode::OK => {
                            let body = Body::from("Ok");
                            Response::builder().status(StatusCode::OK).body(body)?
                        }
                        _ => {
                            let body = Body::from(res_body);
                            Response::builder()
                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                .body(body)?
                        }
                    }
                }
                Err(e) => {
                    warn!("Internal Server Error: {}", &e);
                    Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body("Internal Server Error".into())?
                }
            };
            Ok(res)
        }
        (_, _) => {
            trace!("Bad Request");
            let res = Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body("Bad Request".into())?;
            Ok(res)
        }
    }
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install ctrl-c signal handler");
}

#[tokio::main]
async fn main() -> Result<()> {
    pretty_env_logger::init();
    std::env::var(DO_ACCESS_TOKEN).expect("DO_ACCESS_TOKEN not set");
    std::env::var(DO_DOMAIN_NAME).expect("DO_DOMAIN_NAME not set");
    let addr = ([0, 0, 0, 0], 8080).into();
    let https = HttpsConnector::new();
    let client = Client::builder().build::<_, hyper::Body>(https);
    let service = make_service_fn(move |_| {
        let client = client.clone();
        async move { Ok::<_, hyper::Error>(service_fn(move |req| handle(client.clone(), req))) }
    });
    let server = Server::bind(&addr).serve(service);
    info!("Listening on: {}", &addr);
    let graceful = server.with_graceful_shutdown(shutdown_signal());
    graceful.await?;
    Ok(())
}
