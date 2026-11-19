//! Pinned circuit statements, local witness execution and independent BB 6 verification.
use alloy_primitives::{B256, U256};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fmt, fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};
pub type Result<T> = std::result::Result<T, String>;
const MANIFEST: &str = include_str!("../assets/prover/witness-layouts.json");
const RECURSIVE_KEYS: &str = include_str!("../assets/prover/recursive-key.json");
#[derive(Deserialize)]
struct Layout {
    #[serde(rename = "public")]
    public_fields: Vec<PublicField>,
    private: Vec<String>,
}
#[derive(Deserialize)]
struct PublicField {
    name: String,
    count: usize,
    #[serde(default)]
    array: bool,
}
fn layouts() -> Result<BTreeMap<String, Layout>> {
    serde_json::from_str(MANIFEST).map_err(|_| "invalid bundled proving manifest".into())
}
pub fn sha256(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}
pub use invisi_sdk_protocol::statements::{statement, ProofStatement};
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProofBundle {
    pub format_version: u32,
    pub circuit_name: String,
    pub target: String,
    pub bb_version: String,
    pub artifact_sha256: String,
    pub vk_sha256: String,
    #[serde(rename = "proofHex", with = "crate::note::bytes_hex")]
    pub proof: Vec<u8>,
    pub proof_sha256: String,
    pub public_inputs: Vec<B256>,
}
pub fn assert_bundle(bundle: &ProofBundle, expected: &ProofStatement) -> Result<()> {
    let pinned = statement(
        &expected.circuit_name,
        &expected.target,
        expected.expected_public_inputs.clone(),
    )?;
    if &pinned != expected
        || bundle.format_version != 1
        || bundle.bb_version != "6.0.0"
        || bundle.circuit_name != expected.circuit_name
        || bundle.target != expected.target
        || bundle.artifact_sha256 != expected.artifact_sha256
        || bundle.vk_sha256 != expected.vk_sha256
        || bundle.public_inputs != expected.expected_public_inputs
    {
        return Err("proof identity or statement mismatch".into());
    }
    if bundle.proof.is_empty()
        || bundle.proof.len() % 32 != 0
        || (bundle.target == "noir-recursive" && bundle.proof.len() != 458 * 32)
        || sha256(&bundle.proof) != bundle.proof_sha256
    {
        return Err("invalid proof encoding or digest".into());
    }
    Ok(())
}
pub struct LocalWitness {
    encoded: Zeroizing<Vec<u8>>,
}
impl fmt::Debug for LocalWitness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LocalWitness([redacted])")
    }
}
fn wipe(value: &mut Value) {
    match value {
        Value::String(s) => s.zeroize(),
        Value::Array(a) => {
            for v in a {
                wipe(v)
            }
        }
        Value::Object(m) => {
            for v in m.values_mut() {
                wipe(v)
            }
        }
        _ => {}
    }
    *value = Value::Null;
}
impl LocalWitness {
    pub fn new(mut inputs: Value) -> Result<Self> {
        if !inputs.is_object() {
            return Err("local witness must be an object".into());
        }
        let encoded = serde_json::to_vec(&inputs).map_err(|_| "invalid local witness");
        wipe(&mut inputs);
        Ok(Self {
            encoded: Zeroizing::new(encoded?),
        })
    }
    pub fn with_inputs<T>(&self, consumer: impl FnOnce(&Value) -> Result<T>) -> Result<T> {
        let mut inputs: Value =
            serde_json::from_slice(&self.encoded).map_err(|_| "invalid local witness")?;
        let result = consumer(&inputs);
        wipe(&mut inputs);
        result
    }
}
pub struct ProvingRequest {
    pub statement: ProofStatement,
    pub witness: LocalWitness,
}
pub fn request(
    name: &str,
    target: &str,
    private: Value,
    inputs: Vec<B256>,
) -> Result<ProvingRequest> {
    if name.starts_with("transact_aggregate_") {
        return Err("recursive witnesses require Aggregator".into());
    }
    let statement = statement(name, target, inputs)?;
    let all = layouts()?;
    let layout = &all[name];
    let mut fields = match private {
        Value::Object(fields) => fields,
        _ => return Err("private inputs must be an object".into()),
    };
    if fields.len() != layout.private.len()
        || layout.private.iter().any(|k| !fields.contains_key(k))
    {
        return Err("private witness layout mismatch".into());
    }
    let mut offset = 0;
    for p in &layout.public_fields {
        let values: Vec<Value> = statement.expected_public_inputs[offset..offset + p.count]
            .iter()
            .map(|x| Value::String(U256::from_be_slice(x.as_slice()).to_string()))
            .collect();
        fields.insert(
            p.name.clone(),
            if p.array {
                Value::Array(values)
            } else {
                values[0].clone()
            },
        );
        offset += p.count;
    }
    Ok(ProvingRequest {
        statement,
        witness: LocalWitness::new(Value::Object(fields))?,
    })
}
pub trait Prover: Send + Sync {
    fn get_provenance_capability(&self) -> Result<Option<ProvenanceCapability>> {
        Ok(None)
    }
    fn prove(&self, request: &ProvingRequest) -> Result<ProofBundle>;
    fn verify(&self, bundle: &ProofBundle, statement: &ProofStatement) -> Result<bool>;
}
// Asset paths are explicit host configuration; integrity comes from the bundled release manifest.
pub trait Assets: Send + Sync {
    fn load_provenance_resource(&self, path: &str) -> Result<Vec<u8>> {
        ResourceProvider::default().load_resource(&format!("provenance/{path}"))
    }
    fn load(&self, statement: &ProofStatement) -> Result<(Vec<u8>, Vec<u8>)>;
}
/// Configuration for public circuit resources. Witnesses never enter this transport.
#[derive(Clone, Debug)]
pub struct ResourceOptions {
    /// HTTPS base URL or directory containing index.json and content-addressed objects.
    pub source: String,
    pub cache: PathBuf,
    /// Optional published object directory; logical layouts remain supported.
    pub directory: Option<PathBuf>,
    pub offline: bool,
    pub timeout: Duration,
    /// Trust anchor, configured independently from the download source.
    pub index_sha256: String,
}
fn resource_release_source(pin: &str) -> String {
    format!("https://assets.invisipay.fi/prover/sets/{pin}/")
}
impl Default for ResourceOptions {
    fn default() -> Self {
        let release: Value =
            serde_json::from_str(include_str!("../assets/prover/resource-release.json"))
                .expect("generated resource pin");
        let pin = release["indexSha256"].as_str().unwrap().to_owned();
        let cache = std::env::var_os("INVISI_PROVER_CACHE_DIR")
            .filter(|p| !p.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                let home = || std::env::var_os("HOME").map(PathBuf::from);
                let base = if cfg!(target_os = "macos") {
                    home().map(|p| p.join("Library/Caches"))
                } else if cfg!(target_os = "windows") {
                    std::env::var_os("LOCALAPPDATA")
                        .filter(|p| !p.is_empty())
                        .map(PathBuf::from)
                } else {
                    std::env::var_os("XDG_CACHE_HOME")
                        .filter(|p| !p.is_empty())
                        .map(PathBuf::from)
                        .or_else(|| home().map(|p| p.join(".cache")))
                };
                base.unwrap_or_else(std::env::temp_dir)
                    .join("invisi/prover-assets")
            });
        Self {
            source: std::env::var("INVISI_PROVER_SOURCE")
                .unwrap_or_else(|_| resource_release_source(&pin)),
            cache,
            directory: std::env::var_os("INVISI_PROVER_ASSETS").map(PathBuf::from),
            offline: std::env::var("INVISI_PROVER_OFFLINE").is_ok_and(|v| v == "1" || v == "true"),
            timeout: Duration::from_secs(120),
            index_sha256: pin,
        }
    }
}
#[derive(Clone, Debug, Default)]
pub struct ResourceProvider {
    pub options: ResourceOptions,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ResourceIndex {
    format: String,
    noir_version: String,
    bb_version: String,
    files: BTreeMap<String, ResourceEntry>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourceEntry {
    sha256: String,
    size: u64,
}
// Serializes cache misses across provider instances; successful followers re-read and verify disk.
static RESOURCE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
fn resource_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn resource_path(value: &str) -> bool {
    !value.is_empty()
        && !value.contains('\\')
        && value
            .split('/')
            .all(|p| !p.is_empty() && p != "." && p != "..")
        && !Path::new(value).is_absolute()
}
fn bounded_read(path: &Path, limit: u64) -> Result<Vec<u8>> {
    use std::io::Read;
    let file = fs::File::open(path).map_err(|_| "resource unavailable")?;
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "resource read failed")?;
    if bytes.len() as u64 > limit {
        return Err("resource size exceeds bound".into());
    }
    Ok(bytes)
}
impl ResourceProvider {
    pub fn new(options: ResourceOptions) -> Self {
        Self { options }
    }
    fn object_path(&self, digest: &str, extension: &str) -> PathBuf {
        self.options.cache.join(format!("{digest}.{extension}"))
    }
    fn fetch(&self, filename: &str, limit: u64) -> Result<Vec<u8>> {
        if self.options.offline {
            return Err("resource unavailable in offline cache".into());
        }
        if self.options.timeout.is_zero() {
            return Err("resource timeout must be positive".into());
        }
        if !self.options.source.starts_with("https://")
            && !self.options.source.starts_with("http://")
        {
            return bounded_read(&PathBuf::from(&self.options.source).join(filename), limit);
        }
        let url = format!("{}/{}", self.options.source.trim_end_matches('/'), filename);
        let timeout = self.options.timeout;
        // Build, use and drop the blocking client off any caller's async runtime.
        std::thread::spawn(move || -> Result<Vec<u8>> {
            use std::io::Read;
            let url = reqwest::Url::parse(&url).map_err(|_| "invalid resource source")?;
            if url.scheme() != "https"
                && !(url.scheme() == "http"
                    && matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "::1")))
            {
                return Err("resource transport requires HTTPS".into());
            }
            let client = reqwest::blocking::Client::builder()
                .timeout(timeout)
                .redirect(reqwest::redirect::Policy::limited(10))
                .build()
                .map_err(|_| "resource transport unavailable")?;
            let response = client
                .get(url)
                .send()
                .and_then(|r| r.error_for_status())
                .map_err(|_| "resource download failed")?;
            if response.url().scheme() != "https"
                && !matches!(
                    response.url().host_str(),
                    Some("127.0.0.1" | "localhost" | "::1")
                )
            {
                return Err("insecure resource redirect".into());
            }
            if response.content_length().is_some_and(|s| s > limit) {
                return Err("resource size exceeds bound".into());
            }
            let mut bytes = Vec::new();
            response
                .take(limit + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| "resource download failed")?;
            if bytes.len() as u64 > limit {
                return Err("resource size exceeds bound".into());
            }
            Ok(bytes)
        })
        .join()
        .map_err(|_| "resource transport worker failed")?
    }
    fn cache_write(&self, path: &Path, bytes: &[u8]) -> Result<()> {
        fs::create_dir_all(&self.options.cache).map_err(|_| "resource cache unavailable")?;
        let temporary = self
            .options
            .cache
            .join(format!(".{}.tmp", uuid::Uuid::new_v4()));
        let result = (|| {
            use std::io::Write;
            let mut file = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temporary)
                .map_err(|_| "resource cache unavailable")?;
            file.write_all(bytes)
                .and_then(|_| file.sync_all())
                .map_err(|_| "resource cache write failed")?;
            fs::rename(&temporary, path).map_err(|_| "resource cache publish failed")
        })();
        let _ = fs::remove_file(temporary);
        Ok(result?)
    }
    pub fn load_resource(&self, logical: &str) -> Result<Vec<u8>> {
        if !resource_path(logical) || !resource_digest(&self.options.index_sha256) {
            return Err("invalid resource identity".into());
        }
        let _lock = RESOURCE_LOCK
            .lock()
            .map_err(|_| "resource cache lock failed")?;
        let index_path = self.object_path(&self.options.index_sha256, "index.json");
        let index_bytes = match bounded_read(&index_path, 1024 * 1024) {
            Ok(bytes) if sha256(&bytes) == self.options.index_sha256 => bytes,
            _ => {
                let bytes = if let Some(directory) = &self.options.directory {
                    bounded_read(&directory.join("index.json"), 1024 * 1024)?
                } else {
                    self.fetch("index.json", 1024 * 1024)?
                };
                if sha256(&bytes) != self.options.index_sha256 {
                    return Err("resource index digest mismatch".into());
                }
                self.cache_write(&index_path, &bytes)?;
                bytes
            }
        };
        let index: ResourceIndex =
            serde_json::from_slice(&index_bytes).map_err(|_| "invalid resource index")?;
        if index.format != "invisi.prover-assets.v1"
            || index.noir_version != "1.0.0"
            || index.bb_version != "6.0.0"
            || index.files.iter().any(|(path, entry)| {
                !resource_path(path)
                    || !resource_digest(&entry.sha256)
                    || entry.size == 0
                    || entry.size > 512 * 1024 * 1024
            })
        {
            return Err("unsupported resource index".into());
        }
        let entry = index
            .files
            .get(logical)
            .ok_or("resource absent from pinned index")?;
        let extension = if logical.ends_with(".json") {
            "json"
        } else if logical.ends_with(".vk") || logical.ends_with("/vk") {
            "vk"
        } else {
            return Err("unsupported resource object".into());
        };
        let valid =
            |bytes: &[u8]| bytes.len() as u64 == entry.size && sha256(bytes) == entry.sha256;
        if let Some(directory) = &self.options.directory {
            let logical_path = directory.join(logical);
            let resource_path = if logical_path.exists() {
                logical_path
            } else {
                directory.join(format!("{}.{}", entry.sha256, extension))
            };
            let bytes = bounded_read(&resource_path, entry.size)?;
            return if valid(&bytes) {
                Ok(bytes)
            } else {
                Err("local resource digest mismatch".into())
            };
        }
        let path = self.object_path(&entry.sha256, extension);
        if let Ok(bytes) = bounded_read(&path, entry.size) {
            if valid(&bytes) {
                return Ok(bytes);
            }
        }
        let bytes = self.fetch(&format!("{}.{}", entry.sha256, extension), entry.size)?;
        if !valid(&bytes) {
            return Err("resource digest or size mismatch".into());
        }
        self.cache_write(&path, &bytes)?;
        Ok(bytes)
    }
}
impl Assets for ResourceProvider {
    fn load(&self, s: &ProofStatement) -> Result<(Vec<u8>, Vec<u8>)> {
        if statement(&s.circuit_name, &s.target, s.expected_public_inputs.clone())? != *s {
            return Err("untrusted circuit metadata".into());
        }
        let mut provider = self.clone();
        if s.circuit_name == "create_credit_initial_payment" {
            let release: Value = serde_json::from_str(include_str!(
                "../assets/prover/initial-payment-resource-release.json"
            ))
            .map_err(|_| "invalid combined circuit resource pin")?;
            let pin = release["indexSha256"]
                .as_str()
                .ok_or("missing combined circuit resource pin")?;
            if provider.options.source == resource_release_source(&provider.options.index_sha256) {
                provider.options.source = resource_release_source(pin);
            }
            provider.options.index_sha256 = pin.into();
        }
        let artifact = provider.load_resource(&format!("circuits/{}.json", s.circuit_name))?;
        let key =
            provider.load_resource(&format!("circuits/{}.{}.vk", s.circuit_name, s.target))?;
        validate_assets(s, &artifact, &key)?;
        Ok((artifact, key))
    }
    fn load_provenance_resource(&self, path: &str) -> Result<Vec<u8>> {
        self.load_resource(&format!("provenance/{path}"))
    }
}

pub struct DirectoryAssets {
    pub directory: PathBuf,
}
impl Assets for DirectoryAssets {
    fn load(&self, s: &ProofStatement) -> Result<(Vec<u8>, Vec<u8>)> {
        let expected = statement(&s.circuit_name, &s.target, s.expected_public_inputs.clone())?;
        if &expected != s {
            return Err("untrusted circuit metadata".into());
        }
        let artifact = fs::read(self.directory.join(format!("{}.json", s.circuit_name)))
            .map_err(|_| "circuit artifact unavailable")?;
        let key = fs::read(
            self.directory
                .join(format!("{}.{}.vk", s.circuit_name, s.target)),
        )
        .map_err(|_| "verification key unavailable")?;
        validate_assets(s, &artifact, &key)?;
        Ok((artifact, key))
    }
}
fn raw_abi(source: &str) -> Result<String> {
    let start = source.find("\"abi\"").ok_or("artifact ABI unavailable")?;
    let colon = source[start + 5..].find(':').ok_or("invalid artifact")? + start + 5;
    let mut begin = colon + 1;
    while source
        .as_bytes()
        .get(begin)
        .is_some_and(u8::is_ascii_whitespace)
    {
        begin += 1;
    }
    let bytes = source.as_bytes();
    let mut depth = 0i32;
    let mut string = false;
    let mut escape = false;
    let mut out = String::new();
    for &b in &bytes[begin..] {
        if string {
            out.push(b as char);
            if escape {
                escape = false
            } else if b == b'\\' {
                escape = true
            } else if b == b'"' {
                string = false
            }
        } else {
            match b {
                b'"' => {
                    string = true;
                    out.push('"')
                }
                b'{' | b'[' => {
                    depth += 1;
                    out.push(b as char)
                }
                b'}' | b']' => {
                    depth -= 1;
                    out.push(b as char);
                    if depth == 0 {
                        return Ok(out);
                    }
                }
                b if b.is_ascii_whitespace() => {}
                _ => out.push(b as char),
            }
        }
    }
    Err("invalid artifact ABI".into())
}
pub fn validate_assets(s: &ProofStatement, artifact: &[u8], key: &[u8]) -> Result<()> {
    let expected = statement(&s.circuit_name, &s.target, s.expected_public_inputs.clone())?;
    if &expected != s {
        return Err("untrusted circuit metadata".into());
    }
    let source = std::str::from_utf8(artifact).map_err(|_| "invalid circuit artifact")?;
    let value: Value = serde_json::from_slice(artifact).map_err(|_| "invalid circuit artifact")?;
    let abi = raw_abi(source)?;
    if serde_json::from_str::<Value>(&abi).map_err(|_| "invalid ABI")? != value["abi"] {
        return Err("ambiguous artifact ABI".into());
    }
    let identity = format!(
        "{{\"noirVersion\":{},\"abi\":{},\"bytecode\":{}}}",
        serde_json::to_string(&value["noir_version"]).unwrap(),
        abi,
        serde_json::to_string(&value["bytecode"]).unwrap()
    );
    if sha256(identity.as_bytes()) != s.artifact_sha256 || sha256(key) != s.vk_sha256 {
        return Err("circuit or verification key checksum mismatch".into());
    }
    Ok(())
}
struct PrivateDir(PathBuf);
impl PrivateDir {
    fn new() -> Result<Self> {
        let path = std::env::temp_dir().join(format!("invisi-proof-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&path).map_err(|_| "cannot create private proving directory")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .map_err(|_| "cannot secure proving directory")?;
        }
        Ok(Self(path))
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}
impl Drop for PrivateDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|_| "cannot create private proving file")?;
    file.write_all(bytes)
        .map_err(|_| "cannot write private proving file".into())
}
fn run_local(command: &mut Command, timeout: Duration) -> Result<()> {
    let mut child = command
        .spawn()
        .map_err(|_| "local proving executable unavailable")?;
    let start = Instant::now();
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|_| "cannot monitor local prover")?
        {
            return if status.success() {
                Ok(())
            } else {
                Err("local proving execution failed".into())
            };
        }
        if start.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err("local proving execution timed out".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn version(binary: &Path, args: &[&str], expected: &str, timeout: Duration) -> Result<()> {
    let dir = PrivateDir::new()?;
    let path = dir.path("version");
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let output = options
        .open(&path)
        .map_err(|_| "cannot create version output")?;
    run_local(
        Command::new(binary)
            .args(args)
            .stdout(output)
            .stderr(Stdio::null()),
        timeout,
    )?;
    if fs::metadata(&path)
        .map_err(|_| "tool version unavailable")?
        .len()
        > 4096
    {
        return Err("invalid tool version output".into());
    }
    let bytes = fs::read(&path).map_err(|_| "tool version unavailable")?;
    if String::from_utf8_lossy(&bytes)
        .split_whitespace()
        .all(|v| v != expected)
    {
        return Err(format!(
            "required local tool version {expected} unavailable"
        ));
    }
    Ok(())
}

pub trait WitnessExecutor: Send + Sync {
    fn execute(&self, artifact: &[u8], inputs: &LocalWitness) -> Result<Zeroizing<Vec<u8>>>;
}
pub struct NoirCli {
    pub binary: PathBuf,
    pub timeout: Duration,
}
fn executable_artifact(artifact: &[u8]) -> Result<Vec<u8>> {
    let mut executable: Value = serde_json::from_slice(artifact).map_err(|_| "invalid artifact")?;
    if executable["noir_version"] != "1.0.0+275d3ab1a5c916c6ea73e8d6b943f685f574500c" {
        return Err("unsupported Noir artifact version".into());
    }
    // Release metadata omits debug data; this raw DEFLATE blob encodes {"debug_infos":[]}.
    executable
        .as_object_mut()
        .ok_or("invalid artifact")?
        .entry("debug_symbols")
        .or_insert(json!("q1ZKSU0qTY/PzEvLL1ayio6tBQA="));
    executable
        .as_object_mut()
        .unwrap()
        .entry("file_map")
        .or_insert(json!({}));
    executable
        .as_object_mut()
        .unwrap()
        .entry("hash")
        .or_insert(json!(0));
    serde_json::to_vec(&executable).map_err(|_| "invalid artifact".into())
}

impl WitnessExecutor for NoirCli {
    fn execute(&self, artifact: &[u8], inputs: &LocalWitness) -> Result<Zeroizing<Vec<u8>>> {
        version(&self.binary, &["--version"], "1.0.0", self.timeout)?;
        let executable = executable_artifact(artifact)?;
        let dir = PrivateDir::new()?;
        write_private(&dir.path("circuit.json"), &executable)?;
        write_private(&dir.path("inputs.json"), &inputs.encoded)?;
        run_local(
            Command::new(&self.binary)
                .arg("--artifact-path")
                .arg(dir.path("circuit.json"))
                .arg("--prover-file")
                .arg(dir.path("inputs.json"))
                .arg("--output-dir")
                .arg(&dir.0)
                .args(["--witness-name", "witness"])
                .stdout(Stdio::null())
                .stderr(Stdio::null()),
            self.timeout,
        )?;
        let witness = Zeroizing::new(
            fs::read(dir.path("witness.gz")).map_err(|_| "local witness output unavailable")?,
        );
        if witness.len() < 2 || witness.len() > 512 * 1024 * 1024 || witness[..2] != [0x1f, 0x8b] {
            return Err("invalid local ACVM witness".into());
        }
        Ok(witness)
    }
}
pub struct NativeProver {
    pub bb_binary: PathBuf,
    pub timeout: Duration,
    pub threads: usize,
    pub assets: Arc<dyn Assets>,
    pub witness_executor: Arc<dyn WitnessExecutor>,
}
fn word(value: &Value) -> Result<B256> {
    let text = value.as_str().ok_or("proof word must be a string")?;
    let n = if let Some(raw) = text.strip_prefix("0x") {
        U256::from_str_radix(raw, 16)
    } else {
        U256::from_str_radix(text, 10)
    }
    .map_err(|_| "invalid proof word")?;
    Ok(B256::from(n.to_be_bytes::<32>()))
}
impl NativeProver {
    /// Construct the native prover with lazy, authenticated public resources.
    pub fn new(bb_binary: PathBuf, witness_executor: Arc<dyn WitnessExecutor>) -> Self {
        Self {
            bb_binary,
            timeout: Duration::from_secs(120),
            threads: 1,
            assets: Arc::new(ResourceProvider::default()),
            witness_executor,
        }
    }
    fn command(&self) -> Result<Command> {
        if self.threads == 0 || self.timeout.is_zero() {
            return Err("invalid local prover options".into());
        }
        version(&self.bb_binary, &["--version"], "6.0.0", self.timeout)?;
        let mut c = Command::new(&self.bb_binary);
        c.env("HARDWARE_CONCURRENCY", self.threads.to_string());
        if std::env::var_os("BB_MSM_LEGACY").is_none() {
            c.env("BB_MSM_LEGACY", "1");
        }
        Ok(c)
    }
}
impl Prover for NativeProver {
    fn get_provenance_capability(&self) -> Result<Option<ProvenanceCapability>> {
        self.provenance_capability().map(Some)
    }
    fn prove(&self, request: &ProvingRequest) -> Result<ProofBundle> {
        let (artifact, key) = self.assets.load(&request.statement)?;
        validate_assets(&request.statement, &artifact, &key)?;
        let witness = self.witness_executor.execute(&artifact, &request.witness)?;
        let dir = PrivateDir::new()?;
        for (name, bytes) in [
            ("circuit.json", artifact.as_slice()),
            ("vk", key.as_slice()),
            ("witness.gz", witness.as_slice()),
        ] {
            write_private(&dir.path(name), bytes)?;
        }
        let mut command = self.command()?;
        run_local(
            command
                .args(["prove", "-t", &request.statement.target, "-b"])
                .arg(dir.path("circuit.json"))
                .arg("-w")
                .arg(dir.path("witness.gz"))
                .arg("-k")
                .arg(dir.path("vk"))
                .arg("-o")
                .arg(&dir.0)
                .args(["--output_format", "json"])
                .stdout(Stdio::null())
                .stderr(Stdio::null()),
            self.timeout,
        )?;
        let output: Value = serde_json::from_slice(
            &fs::read(dir.path("proof.json")).map_err(|_| "proof output unavailable")?,
        )
        .map_err(|_| "invalid proof output")?;
        if output["bb_version"] != "6.0.0" || output["scheme"] != "ultra_honk" {
            return Err("unsupported native proof output".into());
        }
        let mut proof = Vec::new();
        for v in output["proof"]
            .as_array()
            .ok_or("proof fields unavailable")?
        {
            proof.extend_from_slice(word(v)?.as_slice());
        }
        let public: Value = serde_json::from_slice(
            &fs::read(dir.path("public_inputs.json")).map_err(|_| "public inputs unavailable")?,
        )
        .map_err(|_| "invalid public inputs")?;
        let inputs = public["public_inputs"]
            .as_array()
            .ok_or("public inputs unavailable")?
            .iter()
            .map(word)
            .collect::<Result<Vec<_>>>()?;
        let s = &request.statement;
        let bundle = ProofBundle {
            format_version: 1,
            circuit_name: s.circuit_name.clone(),
            target: s.target.clone(),
            bb_version: "6.0.0".into(),
            artifact_sha256: s.artifact_sha256.clone(),
            vk_sha256: s.vk_sha256.clone(),
            proof_sha256: sha256(&proof),
            proof,
            public_inputs: inputs,
        };
        assert_bundle(&bundle, s)?;
        if !self.verify(&bundle, s)? {
            return Err("local proof verification failed".into());
        }
        Ok(bundle)
    }
    fn verify(&self, bundle: &ProofBundle, s: &ProofStatement) -> Result<bool> {
        assert_bundle(bundle, s)?;
        let (artifact, key) = self.assets.load(s)?;
        validate_assets(s, &artifact, &key)?;
        let dir = PrivateDir::new()?;
        let inputs: Vec<u8> = bundle
            .public_inputs
            .iter()
            .flat_map(|v| v.as_slice().to_vec())
            .collect();
        for (name, bytes) in [
            ("vk", key.as_slice()),
            ("proof", bundle.proof.as_slice()),
            ("public_inputs", inputs.as_slice()),
        ] {
            write_private(&dir.path(name), bytes)?;
        }
        let mut output_options = fs::OpenOptions::new();
        output_options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            output_options.mode(0o600);
        }
        let output = output_options
            .open(dir.path("verify-output"))
            .map_err(|_| "cannot create verification output")?;
        let error_output = output
            .try_clone()
            .map_err(|_| "cannot capture verification output")?;
        let mut command = self.command()?;
        run_local(
            command
                .stdout(output)
                .stderr(error_output)
                .args(["verify", "-t", &bundle.target, "-k"])
                .arg(dir.path("vk"))
                .arg("-p")
                .arg(dir.path("proof"))
                .arg("-i")
                .arg(dir.path("public_inputs")),
            self.timeout,
        )?;
        let path = dir.path("verify-output");
        if fs::metadata(&path)
            .map_err(|_| "verification output unavailable")?
            .len()
            > 65536
        {
            return Err("verification output exceeds limit".into());
        }
        let output = fs::read_to_string(path).map_err(|_| "invalid verification output")?;
        Ok(output.contains("Proof verified successfully"))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_unknown_circuit() {
        assert!(statement("not-a-circuit", "evm", vec![]).is_err());
    }
    #[test]
    fn rejects_wrong_statement_width() {
        assert!(statement("transact_user_slots1", "evm", vec![]).is_err());
    }
}

#[derive(Clone, Debug)]
pub struct AggregateMember {
    pub bundle: ProofBundle,
    pub statement: ProofStatement,
}
fn validate_recursive_member(member: &AggregateMember) -> Result<usize> {
    assert_bundle(&member.bundle, &member.statement)?;
    let name = &member.bundle.circuit_name;
    let capacity = name
        .strip_prefix("transact_user_slots")
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|c| (1..=10).contains(c))
        .ok_or("aggregation requires C1 through C10 native members")?;
    if member.bundle.target != "noir-recursive" {
        return Err("aggregation requires recursive member target".into());
    }
    let inputs = &member.bundle.public_inputs;
    if inputs.len() != 17 + 3 * capacity {
        return Err("invalid recursive member width".into());
    }
    let n = usize::try_from(U256::from_be_slice(inputs[3].as_slice()))
        .map_err(|_| "invalid input count")?;
    let m = usize::try_from(U256::from_be_slice(inputs[4].as_slice()))
        .map_err(|_| "invalid output count")?;
    if n + m != capacity {
        return Err("recursive member capacity must be canonical".into());
    }
    let words: Vec<String> = inputs[..inputs.len() - 2]
        .iter()
        .map(|v| U256::from_be_slice(v.as_slice()).to_string())
        .collect();
    let digest = crate::wallet::authorization_digest(
        &json!({"operation":"transact","capacity":capacity,"context":{"chainId":U256::from_be_slice(inputs[0].as_slice()).to_string(),"protocolAddress":U256::from_be_slice(inputs[1].as_slice()).to_string()},"words":words}),
    )?;
    if U256::from_be_slice(inputs[inputs.len() - 2].as_slice())
        != U256::from_be_slice(&digest[..16])
        || U256::from_be_slice(inputs[inputs.len() - 1].as_slice())
            != U256::from_be_slice(&digest[16..])
    {
        return Err("recursive member authorization digest mismatch".into());
    }
    Ok(capacity)
}
pub fn aggregate(backend: &dyn Prover, members: &[AggregateMember]) -> Result<ProofBundle> {
    if members.is_empty() || members.len() > 5 {
        return Err("aggregation requires one through five members".into());
    }
    let mut capacities = Vec::new();
    let mut seen_inputs = std::collections::BTreeSet::new();
    let mut seen_outputs = std::collections::BTreeSet::new();
    let mut proof_rows = Vec::new();
    let mut statements = Vec::new();
    for member in members {
        let c = validate_recursive_member(member)?;
        capacities.push(c);
        let words = &member.bundle.public_inputs;
        if words[..2] != members[0].bundle.public_inputs[..2] {
            return Err("aggregate deployment mismatch".into());
        }
        let n = U256::from_be_slice(words[3].as_slice()).to::<usize>();
        let m = U256::from_be_slice(words[4].as_slice()).to::<usize>();
        for i in 0..n + m {
            let value = words[6 + 2 * c + i];
            if value == B256::ZERO
                || !(if i < n {
                    &mut seen_inputs
                } else {
                    &mut seen_outputs
                })
                .insert(value)
            {
                return Err("zero or duplicate aggregate nullifier/output".into());
            }
        }
        if !backend.verify(&member.bundle, &member.statement)? {
            return Err("aggregate member verification failed".into());
        }
        proof_rows.push(
            member
                .bundle
                .proof
                .chunks_exact(32)
                .map(|v| format!("0x{}", hex::encode(v)))
                .collect::<Vec<_>>(),
        );
        statements.push(words.iter().map(|v| format!("{v:#x}")).collect::<Vec<_>>());
    }
    let same = capacities.iter().all(|v| *v == capacities[0]);
    let dedicated = same && [1, 2, 5].contains(&members.len());
    if !dedicated && (members.len() < 2 || capacities.iter().any(|c| *c > 5)) {
        return Err("unsupported aggregate capacity/count combination".into());
    }
    let keys: Value = serde_json::from_str(RECURSIVE_KEYS)
        .map_err(|_| "invalid trusted recursive key manifest")?;
    let mut inputs = Vec::new();
    let mut values = json!({"proofs":proof_rows,"statements":statements});
    let name;
    if dedicated {
        let key = &keys[capacities[0].to_string()];
        if key["verificationKeyFields"].as_array().map(Vec::len) != Some(115) {
            return Err("missing pinned recursive key".into());
        }
        for m in members {
            inputs.extend_from_slice(&m.bundle.public_inputs);
        }
        inputs.push(word(&key["innerVkCommitment"])?);
        values["verification_key"] = key["verificationKeyFields"].clone();
        values["key_hash"] = key["keyHash"].clone();
        values["inner_vk_commitment"] = key["innerVkCommitment"].clone();
        name = format!("transact_aggregate_{}_{}", capacities[0], members.len());
    } else {
        for c in &capacities {
            inputs.push(B256::from(U256::from(*c).to_be_bytes::<32>()));
        }
        for row in &mut statements {
            while row.len() < 32 {
                row.push(format!("{:#x}", B256::ZERO));
            }
            for value in row {
                inputs.push(word(&json!(value))?);
            }
        }
        let mut all_keys = Vec::new();
        let mut hashes = Vec::new();
        let mut pins = Vec::new();
        for c in 1..=5 {
            let key = &keys[c.to_string()];
            if key["verificationKeyFields"].as_array().map(Vec::len) != Some(115) {
                return Err("missing pinned mixed recursive key".into());
            }
            all_keys.push(key["verificationKeyFields"].clone());
            hashes.push(key["keyHash"].clone());
            pins.push(key["innerVkCommitment"].clone());
            inputs.push(word(&key["innerVkCommitment"])?);
        }
        values["statements"] = json!(statements);
        values["capacities"] = json!(capacities.iter().map(usize::to_string).collect::<Vec<_>>());
        values["verification_keys"] = json!(all_keys);
        values["key_hashes"] = json!(hashes);
        values["inner_vk_commitments"] = json!(pins);
        name = format!("transact_aggregate_mixed_1_5_{}", members.len());
    }
    let expected = statement(&name, "evm", inputs)?;
    let request = ProvingRequest {
        statement: expected.clone(),
        witness: LocalWitness::new(values)?,
    };
    let bundle = backend.prove(&request)?;
    assert_bundle(&bundle, &expected)?;
    if !backend.verify(&bundle, &expected)? {
        return Err("aggregate proof verification failed".into());
    }
    Ok(bundle)
}

#[cfg(test)]
mod native_tests {
    use super::*;
    #[test]
    fn validates_pinned_release_asset_identity() {
        let statement = statement("transact_user_slots1", "evm", vec![B256::ZERO; 20]).unwrap();
        let artifact = include_bytes!("../assets/prover/testdata/transact_user_slots1.json");
        let key = include_bytes!("../assets/prover/testdata/transact_user_slots1.evm.vk");
        validate_assets(&statement, artifact, key).unwrap();
        let mut wrong = key.to_vec();
        wrong[0] ^= 1;
        assert!(validate_assets(&statement, artifact, &wrong).is_err());
    }
    #[test]
    #[ignore = "requires explicit INVISI_BB, INVISI_NOIR_EXECUTE and INVISI_PROVER_ASSETS"]
    fn real_native_c1_proves_and_independently_verifies() {
        let fixtures: Value = serde_json::from_str(include_str!(
            "../assets/prover/testdata/current-proving.json"
        ))
        .unwrap();
        let fixture = fixtures["fixtures"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["name"] == "transact_user_slots1")
            .expect("independent native C1 fixture");
        let inputs: Vec<B256> = serde_json::from_value(fixture["publicInputs"].clone()).unwrap();
        let name = fixture["name"].as_str().unwrap();
        let target = "evm";
        let expected = statement(name, target, inputs).unwrap();
        let request = ProvingRequest {
            statement: expected.clone(),
            witness: LocalWitness::new(fixture["witness"].clone()).unwrap(),
        };
        let assets = DirectoryAssets {
            directory: std::env::var_os("INVISI_PROVER_ASSETS")
                .expect("explicit pinned assets required")
                .into(),
        };
        let executor: Arc<dyn WitnessExecutor> =
            if let Some(path) = std::env::var_os("INVISI_TEST_WITNESS_DIR") {
                struct FixtureExecutor(Vec<u8>);
                impl WitnessExecutor for FixtureExecutor {
                    fn execute(&self, _: &[u8], _: &LocalWitness) -> Result<Zeroizing<Vec<u8>>> {
                        Ok(Zeroizing::new(self.0.clone()))
                    }
                }
                let label = fixture["label"].as_str().unwrap();
                Arc::new(FixtureExecutor(
                    fs::read(PathBuf::from(path).join(format!("{label}.gz")))
                        .expect("independent Noir-generated ACVM fixture required"),
                ))
            } else {
                Arc::new(NoirCli {
                    binary: std::env::var_os("INVISI_NOIR_EXECUTE")
                        .expect("explicit Noir executor required")
                        .into(),
                    timeout: Duration::from_secs(120),
                })
            };
        let backend = NativeProver {
            bb_binary: std::env::var_os("INVISI_BB")
                .expect("explicit BB6 binary required")
                .into(),
            timeout: Duration::from_secs(600),
            threads: 4,
            assets: Arc::new(assets),
            witness_executor: executor,
        };
        let bundle = backend.prove(&request).unwrap();
        assert_bundle(&bundle, &expected).unwrap();
        assert!(backend.verify(&bundle, &expected).unwrap());
        let mut wrong = expected.clone();
        wrong.expected_public_inputs[0] = B256::ZERO;
        assert!(assert_bundle(&bundle, &wrong).is_err());
    }
}

#[cfg(all(test, unix))]
mod timeout_tests {
    use super::*;
    #[test]
    fn tool_version_obeys_timeout() {
        use std::os::unix::fs::PermissionsExt;
        let dir = PrivateDir::new().unwrap();
        let binary = dir.path("stalled-version");
        write_private(&binary, b"#!/bin/sh\nwhile :; do :; done\n").unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
        let start = Instant::now();
        assert!(version(&binary, &["--version"], "6.0.0", Duration::from_millis(20)).is_err());
        assert!(start.elapsed() < Duration::from_secs(2));
    }
}

mod source_native;
pub use source_native::{NativeSourceProver, ProvenanceCapability};

#[cfg(test)]
mod resource_tests {
    use super::*;
    fn fixture() -> (PrivateDir, ResourceProvider) {
        let dir = PrivateDir::new().unwrap();
        let source = dir.path("source");
        fs::create_dir(&source).unwrap();
        let bytes = b"public resource";
        let digest = sha256(bytes);
        fs::write(source.join(format!("{digest}.json")), bytes).unwrap();
        let index = serde_json::to_vec(&json!({"format":"invisi.prover-assets.v1","noirVersion":"1.0.0","bbVersion":"6.0.0","files":{"circuits/example.json":{"sha256":digest,"size":bytes.len()}}})).unwrap();
        fs::write(source.join("index.json"), &index).unwrap();
        let provider = ResourceProvider::new(ResourceOptions {
            source: source.to_string_lossy().into_owned(),
            cache: dir.path("cache"),
            directory: None,
            offline: false,
            timeout: Duration::from_secs(3),
            index_sha256: sha256(&index),
        });
        (dir, provider)
    }
    #[test]
    fn resource_cache_is_authenticated_and_offline() {
        let (dir, provider) = fixture();
        assert_eq!(
            provider.load_resource("circuits/example.json").unwrap(),
            b"public resource"
        );
        fs::remove_dir_all(dir.path("source")).unwrap();
        let mut options = provider.options.clone();
        options.offline = true;
        let offline = ResourceProvider::new(options);
        assert!(offline.load_resource("circuits/example.json").is_ok());
        fs::write(
            offline.object_path(&sha256(b"public resource"), "json"),
            b"corrupted",
        )
        .unwrap();
        assert!(offline.load_resource("circuits/example.json").is_err());
    }
    #[test]
    fn resource_rejects_tampered_index_and_object() {
        let (dir, provider) = fixture();
        fs::write(dir.path("source/index.json"), b"{}").unwrap();
        assert!(provider.load_resource("circuits/example.json").is_err());
        let (dir, provider) = fixture();
        fs::write(
            dir.path(&format!("source/{}.json", sha256(b"public resource"))),
            b"wrong",
        )
        .unwrap();
        assert!(provider.load_resource("circuits/example.json").is_err());
        assert!(!provider
            .object_path(&sha256(b"public resource"), "json")
            .exists());
    }
    #[test]
    fn concurrent_resources_share_verified_atomic_cache() {
        let (_dir, provider) = fixture();
        let provider = Arc::new(provider);
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let p = provider.clone();
                std::thread::spawn(move || p.load_resource("circuits/example.json").unwrap())
            })
            .collect();
        for thread in threads {
            assert_eq!(thread.join().unwrap(), b"public resource");
        }
        assert!(provider.load_resource("../example.json").is_err());
    }
    #[test]
    #[ignore = "requires Core release directory via INVISI_TEST_RESOURCE_SOURCE"]
    fn real_core_index_preserves_statement_and_provenance_identity() {
        let directory =
            std::env::var("INVISI_TEST_RESOURCE_SOURCE").expect("Core release directory required");
        let dir = PrivateDir::new().unwrap();
        let provider = ResourceProvider::new(ResourceOptions {
            source: directory,
            cache: dir.path("cache"),
            ..ResourceOptions::default()
        });
        let statement = statement("transact_user_slots1", "evm", vec![B256::ZERO; 20]).unwrap();
        let (artifact, key) = provider.load(&statement).unwrap();
        validate_assets(&statement, &artifact, &key).unwrap();
        let manifest = provider.load_resource("provenance/manifest.json").unwrap();
        let identity = crate::provenance::authenticate_manifest(
            &manifest,
            "6107789c5c0d24c4130bff05da6d389336feb5ccb247c4030eae5198ab05d762",
        )
        .unwrap();
        let raw: Value = serde_json::from_slice(&manifest).unwrap();
        let entry = &identity.manifest.circuits[0];
        let artifact = provider
            .load_resource(&format!(
                "provenance/{}",
                raw["circuits"][0]["artifact"].as_str().unwrap()
            ))
            .unwrap();
        let key = provider
            .load_resource(&format!(
                "provenance/{}",
                raw["circuits"][0]["vk"].as_str().unwrap()
            ))
            .unwrap();
        assert_eq!(sha256(&artifact), entry.artifact_sha256);
        assert_eq!(sha256(&key), entry.vk_sha256);
        let offline = ResourceProvider::new(ResourceOptions {
            source: "/missing".into(),
            offline: true,
            ..provider.options.clone()
        });
        assert!(offline.load(&statement).is_ok());
        assert_eq!(
            offline.load_resource("provenance/manifest.json").unwrap(),
            manifest
        );
    }
    #[test]
    fn http_misses_coalesce_and_corrupt_cache_is_repaired() {
        use std::io::{Read, Write};
        let (dir, mut provider) = fixture();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        provider.options.source = format!("http://{}", listener.local_addr().unwrap());
        let source = dir.path("source");
        let server = std::thread::spawn(move || {
            // Exactly index + object + repaired object. More requests cannot complete.
            for stream in listener.incoming().take(3) {
                let mut stream = stream.unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut request = [0; 4096];
                let n = stream.read(&mut request).unwrap();
                let request = std::str::from_utf8(&request[..n]).unwrap();
                assert!(request.starts_with("GET /"));
                let filename = request
                    .split_whitespace()
                    .nth(1)
                    .unwrap()
                    .trim_start_matches('/');
                let bytes = fs::read(source.join(filename)).unwrap();
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    bytes.len()
                )
                .unwrap();
                stream.write_all(&bytes).unwrap();
            }
        });
        let provider = Arc::new(provider);
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let p = provider.clone();
                std::thread::spawn(move || p.load_resource("circuits/example.json").unwrap())
            })
            .collect();
        for thread in threads {
            assert_eq!(thread.join().unwrap(), b"public resource");
        }
        fs::write(
            provider.object_path(&sha256(b"public resource"), "json"),
            b"bad",
        )
        .unwrap();
        assert_eq!(
            provider.load_resource("circuits/example.json").unwrap(),
            b"public resource"
        );
        server.join().unwrap();
    }
    #[test]
    fn cold_offline_does_not_read_source_and_invalid_indices_fail_closed() {
        let (_dir, mut provider) = fixture();
        provider.options.offline = true;
        assert!(provider.load_resource("circuits/example.json").is_err());
        for changed in [
            json!({"noirVersion":"2.0.0"}),
            json!({"bbVersion":"7.0.0"}),
            json!({"format":"other"}),
            json!({"files":{"../bad.json":{"size":1,"sha256":"a".repeat(64)}}}),
            json!({"files":{"circuits/example.json":{"size":536870913_u64,"sha256":"a".repeat(64)}}}),
            json!({"files":{"circuits/example.json":{"size":-1,"sha256":"a".repeat(64)}}}),
        ] {
            let (dir, mut provider) = fixture();
            let mut index: Value =
                serde_json::from_slice(&fs::read(dir.path("source/index.json")).unwrap()).unwrap();
            for (key, value) in changed.as_object().unwrap() {
                index[key] = value.clone();
            }
            let bytes = serde_json::to_vec(&index).unwrap();
            fs::write(dir.path("source/index.json"), &bytes).unwrap();
            provider.options.index_sha256 = sha256(&bytes);
            assert!(provider.load_resource("circuits/example.json").is_err());
        }
    }
    #[test]
    fn explicit_logical_directory_supports_offline_without_downloads() {
        let (dir, mut provider) = fixture();
        let logical = dir.path("logical");
        fs::create_dir_all(logical.join("circuits")).unwrap();
        fs::copy(dir.path("source/index.json"), logical.join("index.json")).unwrap();
        fs::write(logical.join("circuits/example.json"), b"public resource").unwrap();
        provider.options.directory = Some(logical.clone());
        provider.options.offline = true;
        assert_eq!(
            provider.load_resource("circuits/example.json").unwrap(),
            b"public resource"
        );
        fs::write(logical.join("circuits/example.json"), b"tampered").unwrap();
        assert!(provider.load_resource("circuits/example.json").is_err());
    }
    #[test]
    fn explicit_published_directory_supports_offline_without_downloads() {
        let (dir, mut provider) = fixture();
        provider.options.directory = Some(dir.path("source"));
        provider.options.offline = true;
        assert_eq!(
            provider.load_resource("circuits/example.json").unwrap(),
            b"public resource"
        );
        let object = dir
            .path("source")
            .join(format!("{}.json", sha256(b"public resource")));
        fs::write(object, b"tampered").unwrap();
        assert!(provider.load_resource("circuits/example.json").is_err());
    }
    #[test]
    fn shared_platform_cache_location() {
        let expected = if cfg!(target_os = "macos") {
            PathBuf::from(std::env::var_os("HOME").unwrap())
                .join("Library/Caches/invisi/prover-assets")
        } else if cfg!(target_os = "windows") {
            PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap()).join("invisi/prover-assets")
        } else {
            std::env::var_os("XDG_CACHE_HOME")
                .filter(|p| !p.is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(std::env::var_os("HOME").unwrap()).join(".cache"))
                .join("invisi/prover-assets")
        };
        assert_eq!(ResourceOptions::default().cache, expected);
    }
    #[test]
    fn default_release_source_uses_shared_assets_domain_and_pinned_set() {
        assert_eq!(resource_release_source("ca3ee827c620b1e25d87d1b880549f8cec4be4970f26ea0ab5993dc2db4c827c"), "https://assets.invisipay.fi/prover/sets/ca3ee827c620b1e25d87d1b880549f8cec4be4970f26ea0ab5993dc2db4c827c/");
    }
}

#[cfg(test)]
mod executable_artifact_tests {
    use super::*;
    #[test]
    fn official_executor_metadata_preserves_published_fields() {
        let original = json!({"noir_version":"1.0.0+275d3ab1a5c916c6ea73e8d6b943f685f574500c","abi":{"parameters":[]},"bytecode":"test-only"});
        let output: Value = serde_json::from_slice(
            &executable_artifact(&serde_json::to_vec(&original).unwrap()).unwrap(),
        )
        .unwrap();
        for (key, value) in original.as_object().unwrap() {
            assert_eq!(&output[key], value);
        }
        assert_eq!(output["hash"], json!(0));
        assert!(output["debug_symbols"].is_string());
        assert_eq!(output["file_map"], json!({}));
        let mut existing = original;
        existing["hash"] = json!(123);
        let output: Value = serde_json::from_slice(
            &executable_artifact(&serde_json::to_vec(&existing).unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!(output["hash"], json!(123));
    }
}
