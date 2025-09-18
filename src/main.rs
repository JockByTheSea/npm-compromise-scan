use anyhow::{anyhow, Context, Result};
use clap::{ArgAction, Parser, ValueHint};
use serde_json::Value;
use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;
use std::process::Command;

#[derive(Parser, Debug)]
#[command(
    name = "npm-compromised-scan",
    version,
    about = "Compare npm dependency tree (npm ls --all --json) to a list of compromised packages."
)]
struct Cli {
    /// Path to compromised list file (default: compromised.txt)
    #[arg(short = 'l', long = "list", value_hint = ValueHint::FilePath, default_value = "compromised.txt")]
    list_file: PathBuf,

    /// Provide an existing npm ls JSON file path, or '-' to read from stdin. If omitted, runs `npm ls --all --json`.
    #[arg(long = "npm-json", value_hint = ValueHint::FilePath)]
    npm_json: Option<String>,

    /// Output format: text or json
    #[arg(short = 'f', long = "format", default_value = "text", value_parser = ["text", "json"])]
    format: String,

    /// Exit code to use when any matches are found
    #[arg(long = "fail-exit-code", default_value_t = 42)]
    fail_exit_code: i32,

    /// Suppress running npm (error if no JSON source is provided)
    #[arg(long = "no-run-npm", action = ArgAction::SetTrue)]
    no_run_npm: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Dep {
    name: String,
    version: String,
}

#[derive(Debug)]
struct Lists {
    exact: HashSet<(String, String)>, // (name, version)
    names: HashSet<String>,           // name only
}

#[derive(Debug, serde::Serialize)]
struct MatchRecord {
    match_type: String, // "exact" or "name"
    name: String,
    version: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let lists = parse_compromised_file(&cli.list_file)
        .context(format!("Failed to parse compromised list: {:?}", cli.list_file))?;

    let npm_json_value = load_npm_tree_json(&cli)?;
    let deps = collect_deps(&npm_json_value)?;

    let (matches, any) = find_matches(&deps, &lists);
    match cli.format.as_str() {
        "text" => {
            if any {
                for m in &matches {
                    match m.match_type.as_str() {
                        "exact" => println!("[EXACT MATCH] {}@{}", m.name, m.version),
                        "name" => println!("[NAME MATCH ] {}@{}", m.name, m.version),
                        _ => {}
                    }
                }
            } else {
                println!("No compromised dependencies found.");
            }
        }
        "json" => {
            #[derive(serde::Serialize)]
            struct Output<'a> {
                matches: &'a [MatchRecord],
                match_count: usize,
                compromised_names: Vec<String>,
                compromised_exact: Vec<String>,
            }
            let comp_names: BTreeSet<_> = lists.names.iter().cloned().collect();
            let comp_exact: BTreeSet<_> = lists
                .exact
                .iter()
                .map(|(n, v)| format!("{n}@{v}"))
                .collect();
            let out = Output {
                matches: &matches,
                match_count: matches.len(),
                compromised_names: comp_names.into_iter().collect(),
                compromised_exact: comp_exact.into_iter().collect(),
            };
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        _ => unreachable!(),
    }

    if any {
        std::process::exit(cli.fail_exit_code);
    }
    Ok(())
}

/// Parse the compromised list file.
///
/// Rules:
/// - Ignore blank lines and lines starting with '#'
/// - Distinguish name-only vs exact (name@version or @scope/name@version)
fn parse_compromised_file(path: &PathBuf) -> Result<Lists> {
    let content = fs::read_to_string(path)
        .context(format!("Unable to read compromised list file: {:?}", path))?;
    let mut exact = HashSet::new();
    let mut names = HashSet::new();

    for (lineno, raw_line) in content.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        match parse_compromised_entry(line) {
            CompEntry::Name(name) => {
                names.insert(name);
            }
            CompEntry::Exact { name, version } => {
                names.insert(name.clone());
                exact.insert((name, version));
            }
            CompEntry::Invalid(reason) => {
                return Err(anyhow!(
                    "Invalid entry at line {}: '{}' ({})",
                    lineno + 1,
                    line,
                    reason
                ));
            }
        }
    }

    Ok(Lists { exact, names })
}

enum CompEntry {
    Name(String),
    Exact { name: String, version: String },
    Invalid(String),
}

/// Determine if a line is name-only or exact.
/// Logic:
/// - Find last '@'
/// - If no '@' => name-only
/// - If line starts with '@':
///     - If total '@' count >= 2: candidate for exact (@scope/pkg@version)
/// - Else if unscoped and has one '@': candidate for exact
/// - Validate candidate version: must not contain '/', and starts with [0-9A-Za-z]
fn parse_compromised_entry(line: &str) -> CompEntry {
    if !line.contains('@') {
        return CompEntry::Name(line.to_string());
    }
    let at_count = line.matches('@').count();

    if line.starts_with('@') {
        if at_count < 2 {
            // e.g. @scope/name (no version)
            return CompEntry::Name(line.to_string());
        }
    } else {
        if at_count == 1 {
            // unscoped exact candidate
        } else if at_count > 1 {
            return CompEntry::Invalid("Too many @ characters for unscoped package".into());
        }
    }

    let last_at = line.rfind('@').unwrap();
    let name_part = &line[..last_at];
    let ver_part = &line[last_at + 1..];

    if name_part.is_empty() {
        return CompEntry::Invalid("Empty name part".into());
    }
    if ver_part.is_empty() {
        return CompEntry::Invalid("Empty version part".into());
    }
    if ver_part.contains('/') {
        return CompEntry::Invalid("Version contains '/'".into());
    }
    if !ver_part
        .chars()
        .next()
        .map(|c| c.is_ascii_alphanumeric())
        .unwrap_or(false)
    {
        return CompEntry::Invalid("Version does not start with alphanumeric".into());
    }

    CompEntry::Exact {
        name: name_part.to_string(),
        version: ver_part.to_string(),
    }
}

/// Load npm dependency tree JSON (Value).
fn load_npm_tree_json(cli: &Cli) -> Result<Value> {
    if let Some(src) = &cli.npm_json {
        if src == "-" {
            let mut buf = String::new();
            io::stdin()
                .read_to_string(&mut buf)
                .context("Failed to read stdin")?;
            let v: Value =
                serde_json::from_str(&buf).context("Failed to parse JSON from stdin (--npm-json -)")?;
            return Ok(v);
        } else {
            let data = fs::read_to_string(src)
                .context(format!("Failed to read npm JSON file: {}", src))?;
            let v: Value =
                serde_json::from_str(&data).context("Failed to parse provided npm JSON file")?;
            return Ok(v);
        }
    }

    if cli.no_run_npm {
        return Err(anyhow!(
            "no-run-npm specified but no --npm-json source provided"
        ));
    }

    let output = Command::new("npm")
        .args(["ls", "--all", "--json"])
        .output()
        .context("Failed to execute `npm ls --all --json`")?;

    if !output.status.success() {
        eprintln!(
            "Warning: npm ls exited with non-zero status ({:?}). Still attempting to parse output.",
            output.status.code()
        );
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: Value =
        serde_json::from_str(&stdout).context("Failed to parse JSON from `npm ls` output")?;
    Ok(v)
}

/// Collect dependencies from the npm JSON tree.
/// Returns unique list of (name, version).
fn collect_deps(root: &Value) -> Result<Vec<Dep>> {
    let mut acc = Vec::new();
    let mut seen = HashSet::new();

    if let Some(deps) = root.get("dependencies") {
        if let Some(obj) = deps.as_object() {
            for (name, node) in obj {
                traverse(name, node, &mut acc, &mut seen);
            }
        }
    }
    acc.sort();
    Ok(acc)
}

fn traverse(name: &str, node: &Value, acc: &mut Vec<Dep>, seen: &mut HashSet<(String, String)>) {
    if let Some(version) = node.get("version").and_then(|v| v.as_str()) {
        let key = (name.to_string(), version.to_string());
        if seen.insert(key.clone()) {
            acc.push(Dep {
                name: key.0.clone(),
                version: key.1.clone(),
            });
        }
    }
    if let Some(deps) = node.get("dependencies").and_then(|d| d.as_object()) {
        for (child_name, child_node) in deps {
            traverse(child_name, child_node, acc, seen);
        }
    }
}

fn find_matches(deps: &[Dep], lists: &Lists) -> (Vec<MatchRecord>, bool) {
    let mut matches = Vec::new();
    for d in deps {
        if lists.exact.contains(&(d.name.clone(), d.version.clone())) {
            matches.push(MatchRecord {
                match_type: "exact".to_string(),
                name: d.name.clone(),
                version: d.version.clone(),
            });
        } else if lists.names.contains(&d.name) {
            matches.push(MatchRecord {
                match_type: "name".to_string(),
                name: d.name.clone(),
                version: d.version.clone(),
            });
        }
    }
    let any = !matches.is_empty();
    (matches, any)
}
