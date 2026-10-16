use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;
use serde::Deserialize;

use super::evaluator::{AlgorithmInput, EvaluatorFinding, EvaluatorReport, PolicyEvaluator};

/// Timeout for the Conforma validation request + response body.
const CONFORMA_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
/// Timeout used only for the readiness probe (fast fail).
const CONFORMA_READY_TIMEOUT: Duration = Duration::from_secs(5);

pub struct ConformaClient {
    base_url: String,
    client: reqwest::Client,
}

impl ConformaClient {
    pub fn new(base_url: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(CONFORMA_REQUEST_TIMEOUT)
            .build()
            .expect("failed to build Conforma HTTP client");
        Self { base_url, client }
    }

    async fn run(&self, input: serde_json::Value) -> Result<RawConformaReport, crate::Error> {
        self.wait_ready().await?;

        let response = self
            .client
            .post(format!("{}/v1/validate/input", self.base_url))
            .json(&input)
            .send()
            .await
            .context("failed to reach Conforma evaluation endpoint")?;

        let bytes = response
            .bytes()
            .await
            .context("failed to read Conforma response body")
            .map_err(|e| crate::Error::Internal(e.to_string()))?;

        tracing::debug!(
            body = %String::from_utf8_lossy(&bytes),
            "raw Conforma response"
        );

        serde_json::from_slice(&bytes)
            .context("failed to parse Conforma response")
            .map_err(|e| crate::Error::Internal(e.to_string()))
    }

    async fn wait_ready(&self) -> Result<(), crate::Error> {
        let client = reqwest::Client::builder()
            .timeout(CONFORMA_READY_TIMEOUT)
            .build()
            .context("failed to build HTTP client")?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);

        loop {
            if tokio::time::Instant::now() > deadline {
                return Err(crate::Error::Internal(
                    "Conforma server did not become ready within 30s".into(),
                ));
            }
            match client.get(format!("{}/ready", self.base_url)).send().await {
                Ok(r) if r.status().is_success() => return Ok(()),
                _ => tokio::time::sleep(Duration::from_millis(200)).await,
            }
        }
    }
}

#[async_trait]
impl PolicyEvaluator for ConformaClient {
    async fn evaluate(
        &self,
        algorithms: &[AlgorithmInput],
    ) -> Result<EvaluatorReport, crate::Error> {
        let input = serde_json::json!({
            "algorithms": algorithms.iter().map(|a| serde_json::json!({
                "node_id":    a.node_id,
                "sbom_id":   a.sbom_id,
                "name":      a.name,
                "oid":       a.oid,
                "properties": a.properties,
            })).collect::<Vec<_>>()
        });

        let raw = self.run(input).await?;
        let file = raw.filepaths.into_iter().next().unwrap_or_default();

        Ok(EvaluatorReport {
            violations: file.violations.into_iter().map(into_finding).collect(),
            warnings: file.warnings.into_iter().map(into_finding).collect(),
        })
    }
}

// Conforma strips custom fields from deny/warn results.
// node_id is embedded as "[node_id:<value>]" prefix in msg and parsed back here.
fn into_finding(r: RawResult) -> EvaluatorFinding {
    let node_id = r
        .msg
        .strip_prefix("[node_id:")
        .and_then(|s| s.find(']').map(|i| s[..i].to_string()));
    EvaluatorFinding { node_id, oid: None }
}

#[derive(Deserialize, Default)]
struct RawConformaReport {
    #[serde(default)]
    filepaths: Vec<RawFilePath>,
}

#[derive(Deserialize, Default)]
struct RawFilePath {
    #[serde(default)]
    violations: Vec<RawResult>,
    #[serde(default)]
    warnings: Vec<RawResult>,
}

#[derive(Deserialize)]
struct RawResult {
    msg: String,
    #[allow(dead_code)]
    #[serde(default)]
    metadata: Option<RawMetadata>,
}

#[derive(Deserialize)]
struct RawMetadata {
    #[allow(dead_code)]
    #[serde(default)]
    code: Option<String>,
}
