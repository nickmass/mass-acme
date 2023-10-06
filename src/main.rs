use acme2::{
    AccountBuilder, AuthorizationStatus, ChallengeStatus, Csr, DirectoryBuilder, OrderBuilder,
    OrderStatus, ServerError,
};
use openssl::{
    asn1::Asn1Time,
    pkey::{PKey, Private},
    x509::{X509Req, X509},
};
use rusoto_credential::StaticProvider;
use rusoto_route53::{Route53, Route53Client};
use serde::{Deserialize, Serialize};
use tracing::{error, info};

use std::{
    cmp::Ordering,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

type Error = Box<dyn std::error::Error>;

#[derive(Debug)]
enum AcmeError {
    Route53PropigateTimeout(u64),
    Route53InvalidChangeResponse(String),
    NoSubjectCertificate,
    NoAcmeDnsChallenge,
    AcmeChallengeInvalid(Option<ServerError>),
    AcmeAuthorizationInvalid,
    AcmeOrderInvalid(Option<ServerError>),
    NoAcmeOrderCertificates,
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
            AcmeError::AcmeChallengeInvalid(err) => write!(f, "acme challenge invalid: {:?}", err),
            AcmeError::AcmeAuthorizationInvalid => write!(f, "acme authorization invalid"),
            AcmeError::AcmeOrderInvalid(err) => write!(f, "acme order invalid: {:?}", err),
            AcmeError::NoAcmeOrderCertificates => {
                write!(f, "acme order did not include any certificates")
            }
            AcmeError::NoSubjectCertificate => write!(
                f,
                "existing certificate file did not contain subject certificate"
            ),
        }
    }
}

impl std::error::Error for AcmeError {}

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

const LETS_ENCRYPT_DIRECTORY_URL: &'static str = "https://acme-v02.api.letsencrypt.org/directory";
const LETS_ENCRYPT_STAGING_DIRECTORY_URL: &'static str =
    "https://acme-staging-v02.api.letsencrypt.org/directory";

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Config {
    certs: Vec<ConfigCertificate>,
    certificate_directory: String,
    aws_access_key: String,
    aws_secret_key: String,
    aws_region: String,
    aws_zone_id: String,
    aws_max_wait: u64,
    directory_url: Option<DirectoryUrl>,
    intermediate_url: Option<String>,
    email_address: String,
    reload_nginx: bool,
    days_before_renew: u32,
    nginx_path: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum DirectoryUrl {
    LetsEncrypt,
    LetsEncryptStaging,
    Custom(String),
}

impl DirectoryUrl {
    fn as_url(&self) -> &str {
        match self {
            DirectoryUrl::LetsEncrypt => LETS_ENCRYPT_DIRECTORY_URL,
            DirectoryUrl::LetsEncryptStaging => LETS_ENCRYPT_STAGING_DIRECTORY_URL,
            DirectoryUrl::Custom(url) => url.as_str(),
        }
    }
}

impl Config {
    fn account_key_path(&self) -> PathBuf {
        let mut path = PathBuf::from(&self.certificate_directory);
        path.push("account.pem");

        path
    }
}

fn main() {
    tracing_subscriber::fmt::init();

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
    let config = args.next().unwrap_or(String::from("config.toml"));

    info!("Loading config from: {}", config);
    let config = load_config(&config).await?;
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
        let mut parsed_certs = X509::stack_from_pem(&cert_contents)?.into_iter();
        let subject_cert = parsed_certs.next().ok_or(AcmeError::NoSubjectCertificate)?;

        match subject_cert.not_after().compare(&renew_days)? {
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

    let dir_url = config
        .directory_url
        .as_ref()
        .map(DirectoryUrl::as_url)
        .unwrap_or(LETS_ENCRYPT_DIRECTORY_URL)
        .to_string();
    info!("Creating ACME directory: {}", dir_url);

    let dir = DirectoryBuilder::new(dir_url).build().await?;

    let account = {
        let account_key_path = config.account_key_path();
        info!(
            "Checking for account key in: {}",
            account_key_path.display()
        );

        let mut account_builder = AccountBuilder::new(dir.clone());
        account_builder.contact(vec![format!("mailto:{}", config.email_address)]);
        account_builder.terms_of_service_agreed(true);

        let generate_key = if let Some(account_key) = load_key(&account_key_path).await? {
            info!("Account key found");
            account_builder.private_key(account_key);
            false
        } else {
            info!("No account key found, generating");
            true
        };

        info!("Registering account");
        let account = account_builder.build().await?;

        if generate_key {
            info!("Storing account key in: {}", account_key_path.display());
            save_key(&account_key_path, &account.private_key()).await?;
        }

        account
    };

    let dns_client = DnsClient::new(&config)?;

    for cert in &expiring_certs {
        info!("Begin certificate: {}", cert.name);
        let mut order_builder = OrderBuilder::new(account.clone());
        for domain in cert.domains.iter() {
            order_builder.add_dns_identifier(domain.clone());
        }
        let order = order_builder.build().await?;

        let authorizations = order.authorizations().await?;

        for auth in authorizations {
            let challenge = auth
                .get_challenge("dns-01")
                .ok_or(AcmeError::NoAcmeDnsChallenge)?;

            info!(
                "Performing challenge {} {}",
                auth.identifier.r#type, auth.identifier.value
            );

            let domain = if auth.wildcard.unwrap_or(false) {
                auth.identifier.value.trim_start_matches("*.").to_string()
            } else {
                auth.identifier.value.clone()
            };

            let dns_name = format!("_acme-challenge.{}", domain);
            let dns_value = challenge
                .key_authorization_encoded()?
                .ok_or(AcmeError::NoAcmeDnsChallenge)?;
            info!("Setting DNS challenge token: {}={}", dns_name, dns_value);
            dns_client.set_dns_record(dns_name, dns_value).await?;

            info!("Validating DNS challenge");
            challenge.validate().await?;
            let challenge = challenge.wait_done(Duration::from_secs(5), 12).await?;
            if challenge.status != ChallengeStatus::Valid {
                error!("Challenge validation failed: {:?}", challenge.status);
                return Err(AcmeError::AcmeChallengeInvalid(challenge.error).into());
            }

            let auth = auth.wait_done(Duration::from_secs(5), 12).await?;
            if auth.status != AuthorizationStatus::Valid {
                error!("Authorization validation failed: {:?}", auth.status);
                return Err(AcmeError::AcmeAuthorizationInvalid.into());
            }
        }

        let order = order.wait_ready(Duration::from_secs(5), 12).await?;
        if order.status != OrderStatus::Ready {
            error!("Order validation failed: {:?}", order.status);
            return Err(AcmeError::AcmeOrderInvalid(order.error).into());
        }

        let cert_dir = cert.directory(&*config.certificate_directory);
        info!("Creating certificate directory: {}", cert_dir.display());
        let _ = tokio::fs::create_dir_all(cert_dir).await?;

        let key_file = cert.key_path(&*config.certificate_directory);
        info!("Checking for existing key in: {}", key_file.display());
        let key = if let Some(key) = load_key(&key_file).await? {
            info!("Existing key found");
            key
        } else {
            info!("No key found, generating");
            let key = acme2::gen_rsa_private_key(4096)?;
            info!("Saving key to: {}", key_file.display());
            save_key(key_file, &key).await?;
            key
        };

        let csr_file = cert.csr_path(&*config.certificate_directory);
        info!("Checking for existing CSR in: {}", csr_file.display());
        let csr = if let Some(csr) = load_csr(&csr_file).await? {
            info!("Existing CSR found");
            Csr::Custom(csr)
        } else {
            info!("No CSR found, generating");
            Csr::Automatic(key)
        };

        info!("Finalizing cert");
        let order = order.finalize(csr).await?;
        let order = order.wait_done(Duration::from_secs(5), 12).await?;
        if order.status != OrderStatus::Valid {
            error!("Order finalization failed: {:?}", order.status);
            return Err(AcmeError::AcmeOrderInvalid(order.error).into());
        }

        let certificates = order
            .certificate()
            .await?
            .ok_or(AcmeError::NoAcmeOrderCertificates)?;

        let cert_file = cert.cert_path(&*config.certificate_directory);
        info!(
            "Saving signed cert and intermediate to: {}",
            cert_file.display()
        );

        save_signed_certificate(&certificates, &cert_file).await?;
    }

    if config.reload_nginx {
        if let Some(nginx_path) = config.nginx_path.as_ref() {
            info!("Sending reload signal to nginx");
            let mut cmd = Command::new(nginx_path);
            cmd.args(&["-s", "reload"]);

            let status = cmd.spawn()?.wait()?;
            info!("nginx signal exited with status: {}", status);
        } else {
            error!("Unable to reload nginx, nginx_path unset");
        }
    }

    Ok(())
}

async fn load_config<P: AsRef<Path>>(path: P) -> Result<Config, Error> {
    let path = path.as_ref();

    let text = tokio::fs::read_to_string(path).await?;

    Ok(toml::from_str(text.as_str())?)
}

async fn load_key<P: AsRef<Path>>(path: P) -> Result<Option<PKey<Private>>, Error> {
    let path = path.as_ref();
    if !tokio::fs::metadata(path)
        .await
        .map(|m| m.is_file())
        .unwrap_or(false)
    {
        return Ok(None);
    }

    let bytes = tokio::fs::read(path).await?;

    Ok(Some(PKey::private_key_from_pem(&bytes)?))
}

async fn save_key<P: AsRef<Path>>(path: P, key: &PKey<Private>) -> Result<(), Error> {
    let path = path.as_ref();

    let bytes = key.private_key_to_pem_pkcs8()?;
    tokio::fs::write(path, bytes).await?;

    Ok(())
}

async fn load_csr<P: AsRef<Path>>(path: P) -> Result<Option<X509Req>, Error> {
    let path = path.as_ref();
    if !tokio::fs::metadata(path)
        .await
        .map(|m| m.is_file())
        .unwrap_or(false)
    {
        return Ok(None);
    }

    let bytes = tokio::fs::read(path).await?;

    Ok(Some(X509Req::from_pem(&bytes)?))
}

async fn save_signed_certificate<P: AsRef<Path>>(certs: &Vec<X509>, path: P) -> Result<(), Error> {
    let mut bytes = Vec::new();

    for cert in certs {
        bytes.extend(cert.to_pem()?);
    }

    tokio::fs::write(path.as_ref(), bytes).await?;

    Ok(())
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
