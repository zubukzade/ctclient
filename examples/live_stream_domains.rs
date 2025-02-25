use chrono::{DateTime, Utc};
use ctclient::{certutils, CTClient, SthResult};
use openssl::x509::X509;
use serde_json::Value;
use std::collections::HashSet;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct LogInfo {
    url: String,
    public_key: Vec<u8>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let active_logs = Arc::new(Mutex::new(get_active_logs()?));
    println!("Initial active logs: {}", active_logs.lock().unwrap().len());

    let mut handles = vec![];

    for log in active_logs.lock().unwrap().iter().cloned() {
        let active_logs = Arc::clone(&active_logs);
        let handle = thread::spawn(move || {
            watch_log(log, active_logs);
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    Ok(())
}

fn get_active_logs() -> Result<HashSet<LogInfo>, Box<dyn std::error::Error>> {
    let json_url = "https://www.gstatic.com/ct/log_list/v2/all_logs_list.json";
    let json_text = reqwest::blocking::get(json_url)?.text()?;
    let json: Value = serde_json::from_str(&json_text)?;

    let mut active_logs = HashSet::new();

    if let Some(operators) = json["operators"].as_array() {
        for operator in operators {
            if let Some(logs) = operator["logs"].as_array() {
                for log in logs {
                    if is_log_active(log) {
                        if let (Some(url), Some(key)) = (log["url"].as_str(), log["key"].as_str()) {
                            let public_key = base64::decode(key)?;
                            active_logs.insert(LogInfo {
                                url: url.to_string(),
                                public_key,
                            });
                        }
                    }
                }
            }
        }
    }

    println!("Active logs:");
    for log in &active_logs {
        println!("URL: {}", log.url);
        println!("Public Key: {}", base64::encode(&log.public_key));
        println!();
    }

    Ok(active_logs)
}

fn is_log_active(log: &Value) -> bool {
    let now = Utc::now();

    if let Some(state) = log["state"].as_object() {
        if state.contains_key("retired") || state.contains_key("rejected") {
            return false;
        }
        if state.contains_key("usable") {
            return true;
        }
    }

    if let Some(temporal_interval) = log["temporal_interval"].as_object() {
        if let (Some(start), Some(end)) = (
            temporal_interval["start_inclusive"].as_str(),
            temporal_interval["end_exclusive"].as_str(),
        ) {
            let start_date = DateTime::parse_from_rfc3339(start)
                .ok()
                .map(|d| d.with_timezone(&Utc));
            let end_date = DateTime::parse_from_rfc3339(end)
                .ok()
                .map(|d| d.with_timezone(&Utc));

            return start_date.map_or(false, |s| s <= now) && end_date.map_or(true, |e| now < e);
        }
    }

    false
}

fn watch_log(log: LogInfo, active_logs: Arc<Mutex<HashSet<LogInfo>>>) {
    let mut client = match CTClient::new_from_latest_th(&log.url, &log.public_key) {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Error initializing client for log {}: {}", log.url, e);
            remove_log(&log, &active_logs);
            return;
        }
    };

    let mut backoff = Duration::from_secs(1);
    let max_backoff = Duration::from_secs(3600); // 1 hour

    let mut last_tree_head = [0u8; 32];
    loop {
        let update_result = client.update(Some(|certs: &[X509]| {
            let leaf = &certs[0];
            let ca = &certs[1];
            let canames = certutils::get_common_names(ca).unwrap();
            let caname = &canames[0];
            if let Ok(domains) = certutils::get_dns_names(leaf) {
                print!("{}: ", caname);
                let mut first = true;
                for d in domains.into_iter() {
                    if !first {
                        print!(", ");
                    }
                    print!("{}", d);
                    first = false;
                }
                println!();
            }
        }));

        match update_result {
            SthResult::Ok(head) => {
                if !head.root_hash.eq(&last_tree_head) {
                    last_tree_head = head.root_hash;
                    // println!("{}: {}", log.url, base64::encode(head.root_hash));
                }
                backoff = Duration::from_secs(1); // Reset backoff on success
            }
            SthResult::Err(e) => {
                eprintln!("Error in log {}: {}", log.url, e);

                if e.to_string().contains("429") {
                    println!(
                        "Rate limit hit for {}. Backing off for {:?}",
                        log.url, backoff
                    );
                    thread::sleep(backoff);
                    backoff = std::cmp::min(backoff * 2, max_backoff);
                } else {
                    remove_log(&log, &active_logs);
                    return;
                }
            }
            SthResult::ErrWithSth(_, _) => {
                backoff = Duration::from_secs(1); // Reset backoff on success
            }
        }

        std::io::stdout().flush().unwrap();
    }
}

fn remove_log(log: &LogInfo, active_logs: &Arc<Mutex<HashSet<LogInfo>>>) {
    let mut logs = active_logs.lock().unwrap();
    logs.remove(log);
    println!(
        "Removed log {}. Remaining active logs: {}",
        log.url,
        logs.len()
    );
}
