use acme2_slim::Directory;
use acme2_slim::{cert::SignedCertificate, error::Error as AcmeClientError};
use log::{error, info};
use openssl::{
    asn1::Asn1Time,
    pkey::{PKey, Private},
    x509::{X509Req, X509},
};
use rusoto_credential::StaticProvider;
use rusoto_route53::{Route53, Route53Client};
use serde::{Deserialize, Serialize};
use tokio_compat_02::FutureExt;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::{cmp::Ordering, io::Read};
use std::{fs::File, time::Duration};

type Error = Box<dyn std::error::Error>;

#[derive(Debug)]
enum AcmeError {
    Route53PropigateTimeout(u64),
    Route53InvalidChangeResponse(String),
    NoAcmeDnsChallenge,
    AcmeClient(AcmeClientError),
}

impl std::fmt::Display for AcmeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AcmeError::Route53PropigateTimeout(s) => {
                write!(f, "dns failed to propigate after {}s", s)
            }
            AcmeError::Route53InvalidChangeResponse(e) => {
                write!(f, "route 53 change failed: {}", e)
            }
            AcmeError::NoAcmeDnsChallenge => {
                write!(f, "acme response did not contain DNS challenge")
            }
            AcmeError::AcmeClient(e) => write!(f, "acme client error: {}", e),
        }
    }
}

impl std::error::Error for AcmeError {}

impl From<AcmeClientError> for AcmeError {
    fn from(err: AcmeClientError) -> Self {
        AcmeError::AcmeClient(err)
    }
}

async fn save_signed_certificate_with_intermediate<P: AsRef<Path>>(
    cert: &SignedCertificate,
    path: P,
    intermediate: Option<&[u8]>,
) -> Result<(), Error> {
    cert.save_signed_certificate(path.as_ref()).compat().await?;
    if let Some(intermediate_bytes) = intermediate {
        let mut file = tokio::fs::OpenOptions::new()
            .append(true)
            .open(path.as_ref())
            .await?;
        use tokio::io::AsyncWriteExt;
        file.write_all(intermediate_bytes.as_ref()).await?;
    }

    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ConfigCertificate {
    domains: Vec<String>,
    name: String,
}

impl ConfigCertificate {
    fn directory<P: AsRef<Path>>(&self, root_path: P) -> PathBuf {
        let mut path = PathBuf::from(root_path.as_ref());
        path.push(&*self.name);

        path
    }

    fn csr_path<P: AsRef<Path>>(&self, root_path: P) -> PathBuf {
        let mut path = self.directory(root_path);
        path.push(format!("{}.csr", self.name));

        path
    }

    fn key_path<P: AsRef<Path>>(&self, root_path: P) -> PathBuf {
        let mut path = self.directory(root_path);
        path.push(format!("{}.key", self.name));

        path
    }

    fn cert_path<P: AsRef<Path>>(&self, root_path: P) -> PathBuf {
        let mut path = self.directory(root_path);
        path.push(format!("{}.cert", self.name));

        path
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Config {
    certs: Vec<ConfigCertificate>,
    certificate_directory: String,
    aws_access_key: String,
    aws_secret_key: String,
    aws_region: String,
    aws_zone_id: String,
    aws_max_wait: u64,
    directory_url: Option<String>,
    intermediate_url: Option<String>,
    email_address: String,
    reload_nginx: bool,
    days_before_renew: u32,
    nginx_path: String,
}

impl Config {
    fn account_key_path(&self) -> PathBuf {
        let mut path = PathBuf::from(&self.certificate_directory);
        path.push("account.pem");

        path
    }
}

fn main() {
    let mut builder = ::env_logger::Builder::new();
    builder.filter(None, ::log::LevelFilter::Info);
    builder.init();

    let rt = tokio::runtime::Runtime::new().expect("FATAL: unable to create tokio runtime");
    let result = rt.block_on(run());
    let code = match result {
        Err(e) => {
            error!("{}", e);
            1
        }
        _ => {
            info!("Success");
            0
        }
    };

    std::process::exit(code)
}

async fn run() -> Result<(), Error> {
    let mut args = std::env::args();
    let _executable_name = args.next();
    let config = args.next().unwrap_or(String::from("config.json"));

    info!("Loading config from: {}", config);
    let config = load_config(&config)?;
    info!("Config loaded");
    let _ = tokio::fs::create_dir_all(&*config.certificate_directory).await?;

    let renew_days = Asn1Time::days_from_now(config.days_before_renew)?;
    let mut expiring_certs = Vec::new();
    for cert in &config.certs {
        let cert_path = cert.cert_path(&config.certificate_directory);

        info!("Checking for existing cert: {}", cert_path.display());
        if tokio::fs::metadata(&cert_path).await.is_err() {
            info!(
                "Cert does not exist, will be created: {}",
                cert_path.display()
            );
            expiring_certs.push(cert);
            continue;
        }
        let cert_contents = tokio::fs::read(&cert_path).await?;
        let parsed_cert = X509::from_pem(&cert_contents)?;
        match parsed_cert.not_after().compare(&renew_days)? {
            Ordering::Less => {
                info!(
                    "Cert expires in less than {} days, will be renewed: {}",
                    config.days_before_renew,
                    cert_path.display()
                );
                expiring_certs.push(cert)
            }
            _ => {
                info!(
                    "Cert up to date, will not be renewed: {}",
                    cert_path.display()
                );
            }
        }
    }

    if expiring_certs.is_empty() {
        info!("All certificates up to date");
        return Ok(());
    }

    let dns_client = DnsClient::new(&config)?;

    let dir_url = &*config
        .directory_url
        .as_ref()
        .map(String::as_str)
        .unwrap_or(acme2_slim::LETSENCRYPT_DIRECTORY_URL);
    info!("Creating ACME directory: {}", dir_url);
    let dir = Directory::from_url(dir_url).compat().await?;

    let mut account = {
        let account_key_path = config.account_key_path();
        info!(
            "Checking for account key in: {}",
            account_key_path.display()
        );
        if let Some(account_key) = load_key(&account_key_path)? {
            info!("Account key found");
            info!("Registering account");
            dir.account_registration()
                .email(&*config.email_address)
                .pkey(account_key)
                .register()
                .compat()
                .await?
        } else {
            info!("No account key found, generating");
            info!("Registering account");
            let account = dir
                .account_registration()
                .email(&*config.email_address)
                .register()
                .compat()
                .await?;

            info!("Storing account key in: {}", account_key_path.display());
            account.save_private_key(account_key_path).compat().await?;

            account
        }
    };

    let intermediate_cert = if let Some(url) = config.intermediate_url.as_ref() {
        info!("Downloading intermediate from: {}", url);
        let bytes = reqwest::get(url).await?.bytes().await?;
        Some(bytes)
    } else {
        None
    };

    for cert in &expiring_certs {
        info!("Begin certificate: {}", cert.name);
        let order = account.create_order(&cert.domains).compat().await?;
        for challenge in order.get_dns_challenges() {
            let dns_name = format!(
                "_acme-challenge.{}",
                challenge.domain().ok_or(AcmeError::NoAcmeDnsChallenge)?
            );
            let dns_value = challenge.signature()?;

            dns_client.set_dns_record(dns_name, dns_value).await?;

            challenge
                .validate(&account, Duration::from_secs(5))
                .compat()
                .await?;
        }

        let cert_dir = cert.directory(&*config.certificate_directory);
        info!("Creating certificate directory: {}", cert_dir.display());
        let _ = tokio::fs::create_dir_all(cert_dir).await?;

        let mut cert_signer = account.certificate_signer();
        let mut write_csr = true;
        let mut write_key = true;

        let csr_file = cert.csr_path(&*config.certificate_directory);
        info!("Checking for existing CSR in: {}", csr_file.display());
        if let Some(csr) = load_csr(&csr_file)? {
            info!("Existing CSR found");
            cert_signer = cert_signer.csr(csr);
            write_csr = false;
        } else {
            info!("No CSR found, generating");
        }

        let key_file = cert.key_path(&*config.certificate_directory);
        info!("Checking for existing key in: {}", key_file.display());
        if let Some(key) = load_key(&key_file)? {
            info!("Existing key found");
            cert_signer = cert_signer.pkey(key);
            write_key = false;
        } else {
            info!("No key found, generating");
        }

        info!("Signing cert");
        let signed_cert = cert_signer.sign_certificate(&order).compat().await?;

        if write_csr {
            info!("Saving CSR to: {}", csr_file.display());
            signed_cert
                .save_csr(cert.csr_path(&*config.certificate_directory))
                .compat()
                .await?;
        }

        if write_key {
            info!("Saving key to: {}", key_file.display());
            signed_cert.save_private_key(key_file).compat().await?;
        }

        let cert_file = cert.cert_path(&*config.certificate_directory);
        info!(
            "Saving signed cert and intermediate to: {}",
            cert_file.display()
        );

        let intermediate = intermediate_cert.as_ref().map(|b| b.as_ref());
        save_signed_certificate_with_intermediate(&signed_cert, &cert_file, intermediate).await?;
    }

    if config.reload_nginx {
        info!("Sending reload signal to nginx");
        let mut cmd = Command::new(&config.nginx_path);
        cmd.args(&["-s", "reload"]);

        let status = cmd.spawn()?.wait()?;
        info!("nginx signal exited with status: {}", status);
    }

    Ok(())
}

fn load_config<P: AsRef<Path>>(path: P) -> Result<Config, Error> {
    let path = path.as_ref();

    let file = File::open(path)?;

    Ok(serde_json::from_reader(file)?)
}

fn load_key<P: AsRef<Path>>(path: P) -> Result<Option<PKey<Private>>, Error> {
    let path = path.as_ref();
    if !path.is_file() {
        return Ok(None);
    }

    let mut buf = Vec::new();
    let mut file = File::open(path)?;
    let _ = file.read_to_end(&mut buf)?;

    Ok(Some(PKey::private_key_from_pem(&*buf)?))
}

fn load_csr<P: AsRef<Path>>(path: P) -> Result<Option<X509Req>, Error> {
    let path = path.as_ref();
    if !path.is_file() {
        return Ok(None);
    }

    let mut buf = Vec::new();
    let mut file = File::open(path)?;
    let _ = file.read_to_end(&mut buf)?;

    Ok(Some(X509Req::from_pem(&*buf)?))
}

struct DnsClient {
    config: Config,
}

impl DnsClient {
    fn new(config: &Config) -> Result<DnsClient, Error> {
        let config = config.clone();
        Ok(DnsClient { config })
    }

    fn create_client(&self) -> Result<Route53Client, Error> {
        let creds = StaticProvider::new_minimal(
            self.config.aws_access_key.clone(),
            self.config.aws_secret_key.clone(),
        );
        let http_client = rusoto_core::HttpClient::new()?;
        let client = Route53Client::new_with(http_client, creds, self.config.aws_region.parse()?);
        Ok(client)
    }

    async fn set_dns_record<S: AsRef<str>, T: AsRef<str>>(
        &self,
        name: S,
        value: T,
    ) -> Result<(), Error> {
        use rusoto_route53::{
            Change, ChangeBatch, ChangeResourceRecordSetsRequest, ResourceRecord, ResourceRecordSet,
        };
        let client = self.create_client()?;
        let name = name.as_ref().to_string();
        let value = format!("\"{}\"", value.as_ref());

        let record = ResourceRecord { value };

        let record_set = ResourceRecordSet {
            name,
            resource_records: Some(vec![record]),
            ttl: Some(60),
            type_: String::from("TXT"),
            ..Default::default()
        };

        let change = Change {
            action: String::from("UPSERT"),
            resource_record_set: record_set,
        };

        let change_batch = ChangeBatch {
            changes: vec![change],
            comment: Some(String::from("Automated ACME verification")),
        };

        let change_req = ChangeResourceRecordSetsRequest {
            change_batch,
            hosted_zone_id: self.config.aws_zone_id.clone(),
        };

        info!("Submitting DNS change");
        let change = client.change_resource_record_sets(change_req).await?;
        info!("DNS change submitted");

        self.wait_for_change(change.change_info.id).await
    }

    async fn wait_for_change(&self, change_id: String) -> Result<(), Error> {
        use rusoto_route53::GetChangeRequest;
        let client = self.create_client()?;
        let id = change_id
            .get(8..)
            .expect("Id should be prefixed with '/change/'"); //Remove '/change/' prefix

        let get_change = GetChangeRequest {
            id: String::from(id),
        };

        let mut total_time = self.config.aws_max_wait as i64;
        let next_delay = 20;
        loop {
            let res = client.get_change(get_change.clone()).await?;

            match &*res.change_info.status {
                "INSYNC" => return Ok(()),
                "PENDING" => (),
                s @ _ => Err(AcmeError::Route53InvalidChangeResponse(s.to_string()))?,
            }

            info!(
                "DNS update still pending, retrying in {} seconds",
                next_delay
            );

            total_time -= next_delay;
            if total_time < 0 {
                Err(AcmeError::Route53PropigateTimeout(self.config.aws_max_wait))?
            }
            tokio::time::sleep(Duration::from_secs(next_delay as u64)).await;
        }
    }
}
