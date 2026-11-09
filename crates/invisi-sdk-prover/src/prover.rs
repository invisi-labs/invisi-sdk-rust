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
    #[serde(rename = "artifactSha256")]
    artifact_sha256: String,
    keys: BTreeMap<String, String>,
    #[serde(rename = "publicInputCount")]
    count: usize,
    #[serde(rename = "public")]
    public_fields: Vec<PublicField>,
    private: Vec<String>,
}
#[derive(Deserialize)]
struct PublicField {
    name: String,
    count: usize,
    array: bool,
}
fn layouts() -> Result<BTreeMap<String, Layout>> {
    serde_json::from_str(MANIFEST).map_err(|_| "invalid bundled proving manifest".into())
}
pub fn sha256(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProofStatement {
    pub circuit_name: String,
    pub target: String,
    pub artifact_sha256: String,
    pub vk_sha256: String,
    pub expected_public_inputs: Vec<B256>,
}
pub fn statement(name: &str, target: &str, inputs: Vec<B256>) -> Result<ProofStatement> {
    for input in &inputs {
        crate::note::field(U256::from_be_slice(input.as_slice()), "public field")
            .map_err(|e| e.to_string())?;
    }
    let all = layouts()?;
    let layout = all.get(name).ok_or("unsupported circuit")?;
    let key = layout
        .keys
        .get(target)
        .ok_or("unsupported proving target")?;
    if inputs.len() != layout.count {
        return Err("public statement width mismatch".into());
    }
    Ok(ProofStatement {
        circuit_name: name.into(),
        target: target.into(),
        artifact_sha256: layout.artifact_sha256.clone(),
        vk_sha256: key.clone(),
        expected_public_inputs: inputs,
    })
}
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
    fn prove(&self, request: &ProvingRequest) -> Result<ProofBundle>;
    fn verify(&self, bundle: &ProofBundle, statement: &ProofStatement) -> Result<bool>;
}
// Asset paths are explicit host configuration; integrity comes from the bundled release manifest.
pub trait Assets: Send + Sync {
    fn load(&self, statement: &ProofStatement) -> Result<(Vec<u8>, Vec<u8>)>;
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
impl WitnessExecutor for NoirCli {
    fn execute(&self, artifact: &[u8], inputs: &LocalWitness) -> Result<Zeroizing<Vec<u8>>> {
        version(&self.binary, &["--version"], "1.0.0", self.timeout)?;
        let mut executable: Value =
            serde_json::from_slice(artifact).map_err(|_| "invalid artifact")?;
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
        let dir = PrivateDir::new()?;
        write_private(
            &dir.path("circuit.json"),
            &serde_json::to_vec(&executable).map_err(|_| "invalid artifact")?,
        )?;
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
