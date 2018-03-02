extern crate acme_client;
extern crate clap;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate failure_derive;
#[macro_use]
extern crate log;
extern crate env_logger;
extern crate rusoto_core;
extern crate rusoto_credential;
extern crate rusoto_route53;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;

use acme_client::Directory;
use acme_client::openssl::pkey::PKey;
use acme_client::openssl::x509::X509Req;
use failure::Error;
use rusoto_credential::StaticProvider;
use rusoto_core::DispatchSignedRequest;
use rusoto_route53::{Route53, Route53Client};

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ConfigCertificate {
    domains: Vec<String>,
    name: String
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

    let mut args = std::env::args();
    let _executable_name = args.next();
    let config = args.next().unwrap_or(String::from("config.json"));

    info!("Loading config from: {}", config);
    let config = load_config(&config).expect(&format!("Unable to load config: {}", config));
    info!("Config loaded");

    let dns_client = DnsClient::new(&config).expect("Could not create route53 client");

    let _ = std::fs::create_dir_all(&*config.certificate_directory).expect("Count not create SSL directory");

    let dir_url = &*config.directory_url
        .as_ref()
        .map(String::as_str)
        .unwrap_or(acme_client::LETSENCRYPT_DIRECTORY_URL);
    info!("Creating ACME directory: {}", dir_url);
    let dir = Directory::from_url(dir_url)
        .expect("Unable to create ACME Directory");

    let account = {
        let account_key_path = config.account_key_path();
        info!("Checking for account key in: {}", account_key_path.display());
        if let Some(account_key) = load_key(&account_key_path)
            .expect("Could not open account key") {
                info!("Account key found");
                info!("Registering account");
                dir.account_registration()
                    .email(&*config.email_address)
                    .pkey(account_key)
                    .register()
                    .expect("Unable to register account")
            } else {
                info!("No account key found, generating");
                info!("Registering account");
                let account = dir.account_registration()
                    .email(&*config.email_address)
                    .register()
                    .expect("Unable to register account and generate account key");

                info!("Storing account key in: {}", account_key_path.display());
                account.save_private_key(account_key_path)
                    .expect("Unable to save account key");

                account
            }
    };

    for cert in &config.certs {
        info!("Begin certificate: {}", cert.name);
        for domain in &cert.domains {
            info!("Begin authenticating: {}", domain);
            let auth = account.authorization(domain)
                .expect(&*format!("Unable to create auhtorization for: {}", domain));

            info!("Getting DNS challenge");
            let challenge = auth
                .get_dns_challenge()
                .expect(&*format!("Unable to get DNS challenge for: {}", domain));

            let dns_name = format!("_acme-challenge.{}", domain);
            let dns_value = challenge
                .signature()
                .expect(&*format!("Unable to get DNS signature for: {}", domain));

            info!("Setting challenge record on: {}", dns_name);
            dns_client.set_dns_record(&*dns_name, &*dns_value)
                .expect(&*format!("Unable to set DNS record: {}", dns_name));;

            info!("Validating domain: {}", domain);
            challenge.validate().expect(&*format!("Validation failed for: {}", domain));
        }

        let cert_dir = cert.directory(&*config.certificate_directory);
        info!("Creating certificate directory: {}", cert_dir.display());
        let _ = std::fs::create_dir_all(cert_dir)
            .expect(&*format!("Unable to create cert directory for: {}", cert.name));

        let domains: Vec<_> = cert.domains.iter().map(String::as_str).collect();
        let mut cert_signer = account.certificate_signer(&*domains);
        let mut write_csr = true;
        let mut write_key = true;

        let csr_file = cert.csr_path(&*config.certificate_directory);
        info!("Checking for existing CSR in: {}", csr_file.display());
        if let Some(csr) = load_csr(&csr_file)
            .expect(&*format!("Unable to read csr for: {}", cert.name)) {
                info!("Existing CSR found");
                cert_signer = cert_signer.csr(csr);
                write_csr = false;
            } else {
                info!("No CSR found, generating");
            }

        let key_file = cert.key_path(&*config.certificate_directory);
        info!("Checking for existing key in: {}", key_file.display());
        if let Some(key) = load_key(&key_file)
            .expect(&*format!("Unable to read key for: {}", cert.name)) {
                info!("Existing key found");
                cert_signer = cert_signer.pkey(key);
                write_key = false;
            } else {
                info!("No key found, generating");
            }

        info!("Signing cert");
        let signed_cert = cert_signer.sign_certificate()
            .expect(&*format!("Unable to sign certificate for: {}", cert.name));

        if write_csr {
            info!("Saving CSR to: {}", csr_file.display());
            signed_cert.save_csr(cert.csr_path(&*config.certificate_directory))
                .expect(&*format!("Unable to save CSR for: {}", cert.name));
        }

        if write_key {
            info!("Saving key to: {}", key_file.display());
            signed_cert.save_private_key(key_file)
                .expect(&*format!("Unable to save Key for: {}", cert.name));
        }

        let cert_file = cert.cert_path(&*config.certificate_directory);
        info!("Saving signed cert and intermediate to: {}", cert_file.display());
        signed_cert.save_signed_certificate_and_chain(config.intermediate_url
                                                      .as_ref()
                                                      .map(String::as_str),
                                                      cert_file)
            .expect(&*format!("Unable to save Certificate for: {}", cert.name));
    }

    info!("Success");
}

fn load_config<P: AsRef<Path>>(path: P) -> Result<Config, Error> {
    let path = path.as_ref();

    let file = File::open(path)?;

    Ok(serde_json::from_reader(file)?)
}

fn load_key<P: AsRef<Path>>(path: P) -> Result<Option<PKey>, Error> {
    let path = path.as_ref();
    if !path.is_file() { return Ok(None); }

    let mut buf = Vec::new();
    let mut file = File::open(path)?;
    let _ = file.read_to_end(&mut buf)?;

    Ok(Some(PKey::private_key_from_pem(&*buf)?))
}

fn load_csr<P: AsRef<Path>>(path: P) -> Result<Option<X509Req>, Error> {
    let path = path.as_ref();
    if !path.is_file() { return Ok(None); }

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
        Ok(DnsClient {
            config
        })
    }

    //This SUCKS I would want to make this on new, but there is something up with connection pooling in rusoto/hyper that fails after a long thread::sleep
    fn create_client<D: DispatchSignedRequest>(&self, client: D) -> Result<Route53Client<StaticProvider, D>, Error> {
        let creds = StaticProvider::new_minimal(
            String::from(&*self.config.aws_access_key),
            String::from(&*self.config.aws_secret_key));
        let client = Route53Client::new(client, creds,
                                        self.config.aws_region.parse()?);

        Ok(client)
    }

    fn set_dns_record<S: AsRef<str>, T: AsRef<str>>(&self, name: S, value: T) -> Result<(), Error> {
        use rusoto_route53::{ChangeResourceRecordSetsRequest, Change, ChangeBatch, ResourceRecordSet, ResourceRecord};
        let client = self.create_client(rusoto_core::default_tls_client()?)?;

        let name = name.as_ref().to_string();
        let value = format!("\"{}\"", value.as_ref());

        let record = ResourceRecord {
            value: value
        };

        let record_set = ResourceRecordSet {
            name:  name,
            resource_records: Some(vec![record]),
            ttl: Some(60),
            type_: String::from("TXT"),
            .. Default::default()
        };

        let change = Change {
            action: String::from("UPSERT"),
            resource_record_set: record_set
        };

        let change_batch = ChangeBatch {
            changes: vec![change],
            comment: Some(String::from("Automated ACME verification")),
        };

        let change_req = ChangeResourceRecordSetsRequest {
            change_batch: change_batch,
            hosted_zone_id: self.config.aws_zone_id.clone(),
        };

        info!("Submitting DNS change");
        let change = client.change_resource_record_sets(&change_req)?;
        info!("DNS change submitted");

        self.wait_for_change(change.change_info.id)
    }

    fn wait_for_change(&self, change_id: String) -> Result<(), Error> {
        use rusoto_route53::GetChangeRequest;
        let id = change_id.get(8..).expect("Id should be prefixed with '/change/'"); //Remove '/change/' prefix

        let get_change = GetChangeRequest {
            id: String::from(id)
        };

        let mut total_time = self.config.aws_max_wait as i64;
        let next_delay = 20;
        loop {
            let client = self.create_client(rusoto_core::default_tls_client()?)?;

            let res = client.get_change(&get_change)?;

            match &*res.change_info.status {
                "INSYNC" => return Ok(()),
                "PENDING" => (),
                s @  _ => bail!("Invalid response from Route53 get_change: {}", s),
            }

            info!("DNS update still pending, retrying in {} seconds", next_delay);

            total_time -= next_delay;
            if total_time < 0 { bail!("Ran out of time waiting for route53 to propigate") }
            std::thread::sleep(std::time::Duration::from_secs(next_delay as u64));
        }
    }
}

