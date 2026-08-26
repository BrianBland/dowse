mod format;

use std::collections::HashSet;
use std::fs;
use std::io::BufWriter;
use std::path::PathBuf;

use alloy_primitives::{Address, B256};
use alloy_provider::{Provider, ProviderBuilder};
use clap::{Parser, Subcommand, ValueEnum};
use dowse_analyze::bytecode::{analyze_bytecode, analyzed_to_entries};
use dowse_analyze::trace::{TraceRecord, infer_from_traces};
use dowse_core::proxy;
use dowse_core::score::score_hints_batch;
use dowse_types::{HintTable, PrefetchItem, RecordedAccess};

use format::{read_binary, write_binary, write_human};

#[derive(Parser)]
#[command(name = "dowse", about = "EVM state prefetching hint table tool")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(ValueEnum, Clone, Default, Debug)]
enum OutputFormat {
    /// Human-readable with full addresses
    #[default]
    Human,
    /// Full JSON (serde)
    Json,
    /// Compact binary encoding
    Binary,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze bytecode and generate a hint table
    Generate {
        /// Contract address to fetch and analyze (requires --rpc-url)
        #[arg(long)]
        address: Option<String>,

        /// Hex-encoded bytecode or path to a file containing hex bytecode
        #[arg(long)]
        bytecode: Option<String>,

        /// RPC URL for fetching bytecode (env: RPC_URL or BASE_RPC_URL)
        #[arg(long, env = "RPC_URL")]
        rpc_url: Option<String>,

        /// Skip proxy detection when fetching from RPC
        #[arg(long)]
        no_proxy: bool,

        /// Follow Account targets and analyze their bytecode too
        #[arg(long)]
        recursive: bool,

        /// Max recursion depth for --recursive (default 2)
        #[arg(long, default_value = "2")]
        depth: usize,

        /// Output format
        #[arg(long, default_value = "human")]
        format: OutputFormat,

        /// Output file (stdout if not specified)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Infer a hint table from recorded execution traces
    Infer {
        /// Path to traces JSON file
        #[arg(long)]
        traces: PathBuf,

        /// Output format
        #[arg(long, default_value = "json")]
        format: OutputFormat,

        /// Output file (stdout if not specified)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Validate a hint table against recorded traces
    Validate {
        /// Path to hint table JSON file
        #[arg(long)]
        hints: PathBuf,

        /// Path to traces JSON file
        #[arg(long)]
        traces: PathBuf,
    },

    /// Pretty-print a hint table
    Inspect {
        /// Path to hint table JSON file
        #[arg(long)]
        hints: PathBuf,

        /// Output format
        #[arg(long, default_value = "human")]
        format: OutputFormat,
    },

    /// Merge multiple hint tables
    Merge {
        /// Hint table JSON files to merge
        files: Vec<PathBuf>,

        /// Output file (stdout if not specified)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Convert between hint table formats
    Convert {
        /// Input file
        #[arg(long)]
        input: PathBuf,

        /// Input format
        #[arg(long, default_value = "json")]
        from: OutputFormat,

        /// Output format
        #[arg(long, default_value = "human")]
        to: OutputFormat,

        /// Output file (stdout if not specified)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Generate {
            address,
            bytecode,
            rpc_url,
            no_proxy,
            recursive,
            depth,
            format,
            output,
        } => {
            cmd_generate(address, bytecode, rpc_url, no_proxy, recursive, depth, &format, output.as_deref()).await;
        }
        Commands::Infer { traces, format, output } => {
            cmd_infer(&traces, &format, output.as_deref())
        }
        Commands::Validate { hints, traces } => cmd_validate(&hints, &traces),
        Commands::Inspect { hints, format } => cmd_inspect(&hints, &format),
        Commands::Merge { files, output } => cmd_merge(&files, output.as_deref()),
        Commands::Convert {
            input,
            from,
            to,
            output,
        } => cmd_convert(&input, &from, &to, output.as_deref()),
    }
}

async fn cmd_generate(
    address: Option<String>,
    bytecode_input: Option<String>,
    rpc_url: Option<String>,
    no_proxy: bool,
    recursive: bool,
    depth: usize,
    fmt: &OutputFormat,
    output: Option<&std::path::Path>,
) {
    // Resolve RPC URL: --rpc-url flag > RPC_URL env > BASE_RPC_URL env
    let rpc_url = rpc_url.or_else(|| std::env::var("BASE_RPC_URL").ok());

    let fetch_result = match (&bytecode_input, &address, &rpc_url) {
        // Local bytecode provided
        (Some(input), addr, _) => {
            let hex_str = if std::path::Path::new(input).exists() {
                fs::read_to_string(input)
                    .expect("Failed to read bytecode file")
                    .trim()
                    .to_string()
            } else {
                input.to_string()
            };
            let hex_clean = hex_str.strip_prefix("0x").unwrap_or(&hex_str);
            let bytes = hex::decode(hex_clean).expect("Invalid hex bytecode");
            let addr: Address = addr
                .as_deref()
                .unwrap_or("0x0000000000000000000000000000000000000000")
                .parse()
                .expect("Invalid address");
            let code_hash = alloy_primitives::keccak256(&bytes);
            FetchResult { bytecode: bytes, proxy_bytecode: None, hint_address: addr, code_hash }
        }
        // Fetch from RPC
        (None, Some(addr_str), Some(url)) => {
            let addr: Address = addr_str.parse().expect("Invalid address");
            fetch_bytecode(addr, url, no_proxy).await
        }
        (None, Some(_), None) => {
            eprintln!("Error: --rpc-url is required when fetching by address (or set RPC_URL / BASE_RPC_URL env)");
            std::process::exit(1);
        }
        (None, None, _) => {
            eprintln!("Error: either --bytecode or --address (with --rpc-url) is required");
            std::process::exit(1);
        }
    };

    let hint_address = fetch_result.hint_address;
    let code_hash = fetch_result.code_hash;

    if recursive {
        let rpc_url = rpc_url.as_deref().expect("--recursive requires --rpc-url");
        let mut visited = HashSet::new();
        let mut analyzed_hashes = HashSet::new();
        let mut table = analyze_recursive(rpc_url, hint_address, code_hash, &fetch_result.bytecode, no_proxy, depth, &mut visited, &mut analyzed_hashes).await;
        // Also analyze proxy bytecode — captures proxy-level SLOADs and CALLs
        merge_proxy_analysis(&mut table, hint_address, code_hash, fetch_result.proxy_bytecode.as_deref());
        write_table(&table, fmt, output);
    } else {
        let analyzed = analyze_bytecode(&fetch_result.bytecode);
        let entries = analyzed_to_entries(&analyzed);

        let mut table = HintTable::new();
        table.metadata.source = "bytecode-analysis".into();
        table.metadata.description = format!("Generated from bytecode at {hint_address}");

        for (selector, items) in entries {
            table.insert(hint_address, code_hash, selector, items);
        }
        merge_proxy_analysis(&mut table, hint_address, code_hash, fetch_result.proxy_bytecode.as_deref());

        write_table(&table, fmt, output);
    }
}

/// Analyze proxy bytecode and merge its items into the hint table under the
/// implementation's code hash.
///
/// When a proxy is detected, both the implementation bytecode (main analysis) and
/// the proxy's own bytecode should be analyzed. The proxy bytecode typically SLOADs
/// the implementation address and may contain other operations invisible to the
/// implementation analysis alone.
fn merge_proxy_analysis(table: &mut HintTable, address: Address, code_hash: B256, proxy_bytecode: Option<&[u8]>) {
    if let Some(proxy_code) = proxy_bytecode {
        let proxy_analyzed = analyze_bytecode(proxy_code);
        let proxy_entries = analyzed_to_entries(&proxy_analyzed);
        for (selector, mut items) in proxy_entries {
            table.entries
                .entry(code_hash)
                .or_default()
                .entry(selector)
                .or_default()
                .append(&mut items);
        }
        table.register_code_hash(address, code_hash);
    }
}

/// Recursively analyze a contract and its Account targets.
///
/// Analyzes the bytecode at `address`, inserts entries into a HintTable,
/// then follows any `Account { address }` items to analyze those contracts too,
/// up to `remaining_depth` levels deep. Skips re-analyzing bytecode with the
/// same code hash (just registers the address→code_hash mapping).
async fn analyze_recursive(
    rpc_url: &str,
    address: Address,
    code_hash: B256,
    bytecode: &[u8],
    no_proxy: bool,
    remaining_depth: usize,
    visited: &mut HashSet<Address>,
    analyzed_hashes: &mut HashSet<B256>,
) -> HintTable {
    visited.insert(address);

    let mut table = HintTable::new();
    table.metadata.source = "bytecode-analysis".into();
    table.metadata.description = format!("Generated recursively from {address}");

    // If we've already analyzed this bytecode, just register the address mapping
    if analyzed_hashes.contains(&code_hash) {
        table.register_code_hash(address, code_hash);
        return table;
    }
    analyzed_hashes.insert(code_hash);

    let analyzed = analyze_bytecode(bytecode);
    let entries = analyzed_to_entries(&analyzed);

    // Collect Account targets before inserting
    let mut targets: Vec<Address> = Vec::new();
    for (_selector, items) in &entries {
        for item in items {
            if let PrefetchItem::Account { address: target, .. } = item {
                if !visited.contains(target) {
                    targets.push(*target);
                }
            }
        }
    }
    targets.sort();
    targets.dedup();

    for (selector, items) in entries {
        table.insert(address, code_hash, selector, items);
    }

    if remaining_depth > 0 {
        for target in targets {
            if visited.contains(&target) {
                continue;
            }
            eprintln!(
                "Following Account target {target} (depth remaining: {})",
                remaining_depth - 1,
            );

            // Fetch bytecode for the target — skip EOAs/empty contracts
            let fetch = match try_fetch_bytecode(target, rpc_url, no_proxy).await {
                Some(r) => r,
                None => {
                    eprintln!("Skipping {target}: no bytecode (EOA or empty)");
                    continue;
                }
            };

            let mut child_table = Box::pin(analyze_recursive(
                rpc_url,
                target,
                fetch.code_hash,
                &fetch.bytecode,
                no_proxy,
                remaining_depth - 1,
                visited,
                analyzed_hashes,
            ))
            .await;
            // Also analyze proxy bytecode for this child target
            merge_proxy_analysis(&mut child_table, target, fetch.code_hash, fetch.proxy_bytecode.as_deref());
            table.merge(child_table);
        }
    }

    table
}

/// Result of fetching bytecode, potentially through a proxy.
struct FetchResult {
    /// Bytecode to analyze (implementation bytecode for proxies, direct otherwise).
    bytecode: Vec<u8>,
    /// The proxy's own bytecode, if a proxy was detected. Should also be analyzed
    /// since it may contain SLOADs (e.g., loading the implementation address) and
    /// CALLs that the implementation bytecode alone doesn't reveal.
    proxy_bytecode: Option<Vec<u8>>,
    /// Address to key hints by (always the proxy/original address).
    hint_address: Address,
    /// Keccak256 hash of the bytecode being analyzed (implementation bytecode for proxies).
    code_hash: B256,
}

/// Fetch bytecode from an RPC endpoint, handling proxy detection.
///
/// Returns a `FetchResult` with the implementation bytecode, optional proxy bytecode,
/// and the hint address (always the original/proxy address, since callers target it).
async fn fetch_bytecode(address: Address, rpc_url: &str, no_proxy: bool) -> FetchResult {
    let provider = ProviderBuilder::new()
        .connect_http(rpc_url.parse().expect("Invalid RPC URL"));

    eprintln!("Fetching bytecode for {address} from {rpc_url} ...");

    let code = provider
        .get_code_at(address)
        .await
        .expect("Failed to fetch bytecode");

    if code.is_empty() {
        eprintln!("Error: no bytecode found at {address} (EOA or empty contract)");
        std::process::exit(1);
    }

    eprintln!("Got {} bytes of bytecode", code.len());

    if no_proxy {
        let code_hash = alloy_primitives::keccak256(&code);
        return FetchResult { bytecode: code.to_vec(), proxy_bytecode: None, hint_address: address, code_hash };
    }

    // Async proxy detection using the same slot constants from dowse_core::proxy
    eprintln!("Checking for proxy patterns...");

    let result = detect_proxy_async(&provider, address).await;

    match result {
        Some(proxy::ProxyResult::Implementation(impl_addr)) => {
            eprintln!("Detected proxy -> implementation at {impl_addr}");
            let (impl_code, hint_addr) = fetch_impl_bytecode(&provider, impl_addr, &code, address).await;
            let code_hash = alloy_primitives::keccak256(&impl_code);
            FetchResult { bytecode: impl_code, proxy_bytecode: Some(code.to_vec()), hint_address: hint_addr, code_hash }
        }
        Some(proxy::ProxyResult::Beacon {
            beacon,
            implementation,
        }) => {
            eprintln!("Detected beacon proxy -> beacon at {beacon} -> implementation at {implementation}");
            let (impl_code, hint_addr) = fetch_impl_bytecode(&provider, implementation, &code, address).await;
            let code_hash = alloy_primitives::keccak256(&impl_code);
            FetchResult { bytecode: impl_code, proxy_bytecode: Some(code.to_vec()), hint_address: hint_addr, code_hash }
        }
        None => {
            eprintln!("No proxy pattern detected, analyzing bytecode directly");
            let code_hash = alloy_primitives::keccak256(&code);
            FetchResult { bytecode: code.to_vec(), proxy_bytecode: None, hint_address: address, code_hash }
        }
    }
}

/// Like `fetch_bytecode` but returns `None` instead of exiting when no bytecode is found.
/// Used by recursive analysis to skip EOAs gracefully.
async fn try_fetch_bytecode(
    address: Address,
    rpc_url: &str,
    no_proxy: bool,
) -> Option<FetchResult> {
    let provider = ProviderBuilder::new()
        .connect_http(rpc_url.parse().expect("Invalid RPC URL"));

    eprintln!("Fetching bytecode for {address} ...");

    let code = provider
        .get_code_at(address)
        .await
        .expect("Failed to fetch bytecode");

    if code.is_empty() {
        return None;
    }

    eprintln!("Got {} bytes of bytecode", code.len());

    if no_proxy {
        let code_hash = alloy_primitives::keccak256(&code);
        return Some(FetchResult { bytecode: code.to_vec(), proxy_bytecode: None, hint_address: address, code_hash });
    }

    eprintln!("Checking for proxy patterns...");
    let result = detect_proxy_async(&provider, address).await;

    Some(match result {
        Some(proxy::ProxyResult::Implementation(impl_addr)) => {
            eprintln!("Detected proxy -> implementation at {impl_addr}");
            let (impl_code, hint_addr) = fetch_impl_bytecode(&provider, impl_addr, &code, address).await;
            let code_hash = alloy_primitives::keccak256(&impl_code);
            FetchResult { bytecode: impl_code, proxy_bytecode: Some(code.to_vec()), hint_address: hint_addr, code_hash }
        }
        Some(proxy::ProxyResult::Beacon {
            beacon,
            implementation,
        }) => {
            eprintln!("Detected beacon proxy -> beacon at {beacon} -> implementation at {implementation}");
            let (impl_code, hint_addr) = fetch_impl_bytecode(&provider, implementation, &code, address).await;
            let code_hash = alloy_primitives::keccak256(&impl_code);
            FetchResult { bytecode: impl_code, proxy_bytecode: Some(code.to_vec()), hint_address: hint_addr, code_hash }
        }
        None => {
            let code_hash = alloy_primitives::keccak256(&code);
            FetchResult { bytecode: code.to_vec(), proxy_bytecode: None, hint_address: address, code_hash }
        },
    })
}

/// Async proxy detection using the slot constants from dowse_core::proxy.
async fn detect_proxy_async(
    provider: &(impl Provider + Sync),
    address: Address,
) -> Option<proxy::ProxyResult> {
    use dowse_core::proxy::*;

    // Try direct implementation slots
    for slot in [EIP1967_IMPL_SLOT, OZ_LEGACY_IMPL_SLOT] {
        if let Ok(val) = provider.get_storage_at(address, slot).await {
            if let Some(addr) = addr_from_u256(val) {
                return Some(ProxyResult::Implementation(addr));
            }
        }
    }

    // Try beacon pattern
    if let Ok(val) = provider.get_storage_at(address, EIP1967_BEACON_SLOT).await {
        if let Some(beacon) = addr_from_u256(val) {
            if let Ok(impl_val) = provider.get_storage_at(beacon, EIP1967_IMPL_SLOT).await {
                if let Some(implementation) = addr_from_u256(impl_val) {
                    return Some(ProxyResult::Beacon {
                        beacon,
                        implementation,
                    });
                }
            }
        }
    }

    None
}

/// Extract a non-zero address from a U256 storage value.
fn addr_from_u256(val: alloy_primitives::U256) -> Option<Address> {
    use alloy_primitives::{B256, U256};
    if val == U256::ZERO {
        return None;
    }
    let bytes: B256 = val.into();
    let addr = Address::from_slice(&bytes.as_slice()[12..]);
    if addr == Address::ZERO {
        None
    } else {
        Some(addr)
    }
}

/// Fetch implementation bytecode, falling back to proxy bytecode if empty.
async fn fetch_impl_bytecode(
    provider: &(impl Provider + Sync),
    impl_addr: Address,
    proxy_code: &[u8],
    hint_address: Address,
) -> (Vec<u8>, Address) {
    let impl_code = provider
        .get_code_at(impl_addr)
        .await
        .expect("Failed to fetch implementation bytecode");
    if impl_code.is_empty() {
        eprintln!("Warning: no bytecode at implementation address, using proxy bytecode");
        (proxy_code.to_vec(), hint_address)
    } else {
        eprintln!("Got {} bytes of implementation bytecode", impl_code.len());
        (impl_code.to_vec(), hint_address)
    }
}

fn cmd_infer(
    traces_path: &std::path::Path,
    fmt: &OutputFormat,
    output: Option<&std::path::Path>,
) {
    let traces_json = fs::read_to_string(traces_path).expect("Failed to read traces file");
    let traces: Vec<TraceRecord> =
        serde_json::from_str(&traces_json).expect("Failed to parse traces JSON");
    let table = infer_from_traces(&traces);
    write_table(&table, fmt, output);
}

fn cmd_validate(hints_path: &std::path::Path, traces_path: &std::path::Path) {
    let hints_json = fs::read_to_string(hints_path).expect("Failed to read hints file");
    let hints: HintTable = serde_json::from_str(&hints_json).expect("Failed to parse hints JSON");

    let traces_json = fs::read_to_string(traces_path).expect("Failed to read traces file");
    let trace_records: Vec<TraceRecord> =
        serde_json::from_str(&traces_json).expect("Failed to parse traces JSON");

    let batch: Vec<_> = trace_records
        .iter()
        .map(|t| {
            let accesses: Vec<RecordedAccess> = t
                .storage_accesses
                .iter()
                .map(|(addr, slot)| RecordedAccess::Storage {
                    address: *addr,
                    slot: *slot,
                })
                .collect();
            (
                t.address,
                alloy_primitives::Address::ZERO,
                t.calldata.to_vec(),
                accesses,
            )
        })
        .collect();

    let score = score_hints_batch(&hints, &batch);

    println!("Validation Results:");
    println!("  Hits:      {}", score.hits);
    println!("  Misses:    {}", score.misses);
    println!("  Uncovered: {}", score.uncovered);
    println!("  Precision: {:.1}%", score.precision() * 100.0);
    println!("  Recall:    {:.1}%", score.recall() * 100.0);
}

fn cmd_inspect(hints_path: &std::path::Path, fmt: &OutputFormat) {
    let table = read_table(hints_path, &OutputFormat::Json);

    println!("Hint Table v{}", table.version);
    if !table.metadata.description.is_empty() {
        println!("  Description: {}", table.metadata.description);
    }
    if !table.metadata.source.is_empty() {
        println!("  Source: {}", table.metadata.source);
    }
    if let Some(name) = &table.metadata.contract_name {
        println!("  Contract: {name}");
    }
    println!(
        "{} code hashes, {} addresses, {} selectors, {} items\n",
        table.entries.len(),
        table.code_hashes.len(),
        table.selector_count(),
        table.item_count(),
    );

    write_table(&table, fmt, None);
}

fn cmd_merge(files: &[PathBuf], output: Option<&std::path::Path>) {
    if files.is_empty() {
        eprintln!("No files to merge");
        return;
    }

    let mut merged = HintTable::new();
    merged.metadata.source = "merged".into();

    for path in files {
        let json = fs::read_to_string(path).expect("Failed to read file");
        let table: HintTable = serde_json::from_str(&json).expect("Failed to parse JSON");
        merged.merge(table);
    }

    let json = serde_json::to_string_pretty(&merged).expect("Failed to serialize");

    match output {
        Some(path) => {
            fs::write(path, &json).expect("Failed to write output");
            eprintln!(
                "Merged {} files into {} ({} selectors)",
                files.len(),
                path.display(),
                merged.selector_count(),
            );
        }
        None => println!("{json}"),
    }
}

fn cmd_convert(
    input_path: &std::path::Path,
    from: &OutputFormat,
    to: &OutputFormat,
    output: Option<&std::path::Path>,
) {
    let table = read_table(input_path, from);
    write_table(&table, to, output);
}

/// Read a hint table from a file in the given format.
fn read_table(path: &std::path::Path, fmt: &OutputFormat) -> HintTable {
    match fmt {
        OutputFormat::Json | OutputFormat::Human => {
            let json = fs::read_to_string(path).expect("Failed to read file");
            serde_json::from_str(&json).expect("Failed to parse JSON")
        }
        OutputFormat::Binary => {
            let data = fs::read(path).expect("Failed to read binary file");
            read_binary(&mut data.as_slice()).expect("Failed to parse binary hint table")
        }
    }
}

/// Write a hint table to a file or stdout in the given format.
fn write_table(table: &HintTable, fmt: &OutputFormat, output: Option<&std::path::Path>) {
    match output {
        Some(path) => {
            let file = fs::File::create(path).expect("Failed to create output file");
            let mut w = BufWriter::new(file);
            write_table_to(table, fmt, &mut w);
            eprintln!("Wrote hint table to {}", path.display());
        }
        None => {
            let stdout = std::io::stdout();
            let mut w = BufWriter::new(stdout.lock());
            write_table_to(table, fmt, &mut w);
        }
    }
}

fn write_table_to(table: &HintTable, fmt: &OutputFormat, w: &mut impl std::io::Write) {
    match fmt {
        OutputFormat::Human => {
            write_human(table, w).expect("Failed to write human output");
        }
        OutputFormat::Json => {
            let json =
                serde_json::to_string_pretty(table).expect("Failed to serialize hint table");
            w.write_all(json.as_bytes())
                .expect("Failed to write JSON output");
            w.write_all(b"\n").ok();
        }
        OutputFormat::Binary => {
            write_binary(table, w).expect("Failed to write binary output");
        }
    }
}
