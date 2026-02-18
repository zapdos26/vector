use std::sync::Arc;

use azure_core::{
    credentials::{Secret, TokenCredential},
    error::Error as AzureCoreError,
};
use azure_identity::{
    ClientSecretCredential, DeveloperToolsCredential, ManagedIdentityCredential,
    ManagedIdentityCredentialOptions, UserAssignedId, WorkloadIdentityCredential,
};

use crate::sinks::azure_common::connection_string::{Auth, ParsedConnectionString};
use crate::sinks::azure_common::shared_key_policy::SharedKeyAuthorizationPolicy;
use azure_core::http::Url;
use azure_storage_blob::{BlobContainerClient, BlobContainerClientOptions};

use azure_core::http::StatusCode;
use bytes::Bytes;
use futures::FutureExt;
use snafu::Snafu;
use vector_lib::{
    configurable::configurable_component,
    json_size::JsonSize,
    request_metadata::{GroupedCountByteSize, MetaDescriptive, RequestMetadata},
    sensitive_string::SensitiveString,
    stream::DriverResponse,
};

use crate::{
    event::{EventFinalizers, EventStatus, Finalizable},
    sinks::{Healthcheck, util::retries::RetryLogic},
};

/// Authentication settings for Azure Blob Storage sinks.
#[configurable_component]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct AzureBlobAuthConfig {
    /// The Azure Blob Storage Account connection string.
    ///
    /// Authentication with an access key or shared access signature (SAS)
    /// are supported authentication methods. If using a non-account SAS,
    /// healthchecks will fail and will need to be disabled by setting
    /// `healthcheck.enabled` to `false` for this sink.
    ///
    /// When generating an account SAS, the following are the minimum required option
    /// settings for Vector to access blob storage and pass a health check.
    /// | Option                 | Value              |
    /// | ---------------------- | ------------------ |
    /// | Allowed services       | Blob               |
    /// | Allowed resource types | Container & Object |
    /// | Allowed permissions    | Read & Create      |
    #[configurable(metadata(
        docs::examples = "DefaultEndpointsProtocol=https;AccountName=mylogstorage;AccountKey=storageaccountkeybase64encoded;EndpointSuffix=core.windows.net"
    ))]
    #[configurable(metadata(
        docs::examples = "BlobEndpoint=https://mylogstorage.blob.core.windows.net/;SharedAccessSignature=generatedsastoken"
    ))]
    #[serde(default)]
    pub connection_string: SensitiveString,

    /// Use Microsoft Entra ID authentication for Blob Storage.
    ///
    /// When configured, Vector obtains a bearer token using either:
    /// - managed identity (default), optionally with a user-assigned client ID, or
    /// - service principal credentials when `tenant_id` and `client_secret` are supplied.
    #[serde(default)]
    pub entra_id: Option<AzureBlobEntraIdConfig>,
}

/// Microsoft Entra ID authentication options for Azure Blob Storage.
#[configurable_component]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct AzureBlobEntraIdConfig {
    /// The Blob service endpoint URL, e.g. `https://myaccount.blob.core.windows.net`.
    #[configurable(metadata(docs::examples = "https://myaccount.blob.core.windows.net"))]
    pub endpoint: String,

    /// The Entra tenant ID for service principal authentication.
    ///
    /// Must be provided together with `client_secret`.
    #[configurable(metadata(docs::examples = "11111111-1111-1111-1111-111111111111"))]
    pub tenant_id: Option<String>,

    /// The Entra application (client) ID.
    ///
    /// For managed identity auth this is optional and selects a user-assigned identity.
    #[configurable(metadata(docs::examples = "22222222-2222-2222-2222-222222222222"))]
    pub client_id: Option<String>,

    /// The Entra client secret for service principal authentication.
    ///
    /// Must be provided together with `tenant_id`.
    pub client_secret: Option<SensitiveString>,

    /// The Entra credential method to use.
    #[serde(default)]
    pub auth_method: AzureBlobEntraAuthMethod,
}

/// Credential method used for Entra authentication.
#[configurable_component]
#[derive(Clone, Copy, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum AzureBlobEntraAuthMethod {
    /// Use a default chain of credentials.
    ///
    /// `azure_identity` (including the currently available newer releases) does not expose
    /// a first-class `DefaultAzureCredential` type, so Vector models the default chain here.
    ///
    /// Vector tries, in order:
    /// 1. configured client secret (`tenant_id`, `client_id`, `client_secret`)
    /// 2. workload identity
    /// 3. managed identity
    /// 4. developer tools (Azure CLI / Azure Developer CLI)
    #[default]
    DefaultAzureCredential,
    /// Use managed identity (system-assigned or user-assigned if `client_id` is set).
    ManagedIdentity,
    /// Use service principal credentials from `tenant_id`, `client_id`, and `client_secret`.
    ClientSecret,
    /// Use workload identity.
    WorkloadIdentity,
    /// Use developer tools credentials (Azure CLI / Azure Developer CLI).
    DeveloperTools,
}

impl AzureBlobAuthConfig {
    fn client_secret_credential(
        entra_id: &AzureBlobEntraIdConfig,
    ) -> crate::Result<Arc<dyn TokenCredential>> {
        match (&entra_id.tenant_id, &entra_id.client_id, &entra_id.client_secret) {
            (Some(tenant_id), Some(client_id), Some(client_secret)) => ClientSecretCredential::new(
                tenant_id,
                client_id.clone(),
                Secret::new(client_secret.inner().to_owned()),
                None,
            )
            .map(|credential| credential as Arc<dyn TokenCredential>)
            .map_err(|e| format!("failed to create Entra client secret credential: {e}").into()),
            (Some(_), None, Some(_)) => Err(
                "`entra_id.client_id` is required when using tenant_id and client_secret".into(),
            ),
            (Some(_), _, None) | (None, _, Some(_)) => Err(
                "`entra_id.tenant_id` and `entra_id.client_secret` must be provided together"
                    .into(),
            ),
            _ => Err(
                "`entra_id.tenant_id`, `entra_id.client_id`, and `entra_id.client_secret` are required for client_secret auth".into(),
            ),
        }
    }

    fn managed_identity_credential(
        entra_id: &AzureBlobEntraIdConfig,
    ) -> crate::Result<Arc<dyn TokenCredential>> {
        let options = entra_id
            .client_id
            .clone()
            .map(|id| ManagedIdentityCredentialOptions {
                user_assigned_id: Some(UserAssignedId::ClientId(id)),
                ..Default::default()
            });
        ManagedIdentityCredential::new(options)
            .map(|credential| credential as Arc<dyn TokenCredential>)
            .map_err(|e| format!("failed to create managed identity credential: {e}").into())
    }

    fn token_credential(&self) -> crate::Result<Arc<dyn TokenCredential>> {
        let entra_id = self
            .entra_id
            .as_ref()
            .ok_or_else(|| "missing `entra_id` configuration".to_string())?;

        match entra_id.auth_method {
            AzureBlobEntraAuthMethod::ClientSecret => Self::client_secret_credential(entra_id),
            AzureBlobEntraAuthMethod::ManagedIdentity => {
                Self::managed_identity_credential(entra_id)
            }
            AzureBlobEntraAuthMethod::WorkloadIdentity => WorkloadIdentityCredential::new(None)
                .map(|credential| credential as Arc<dyn TokenCredential>)
                .map_err(|e| format!("failed to create workload identity credential: {e}").into()),
            AzureBlobEntraAuthMethod::DeveloperTools => DeveloperToolsCredential::new(None)
                .map(|credential| credential as Arc<dyn TokenCredential>)
                .map_err(|e| format!("failed to create developer tools credential: {e}").into()),
            AzureBlobEntraAuthMethod::DefaultAzureCredential => {
                let mut chain = Vec::new();
                if let Ok(credential) = Self::client_secret_credential(entra_id) {
                    chain.push(credential);
                }
                if let Ok(credential) = WorkloadIdentityCredential::new(None) {
                    chain.push(credential as Arc<dyn TokenCredential>);
                }
                if let Ok(credential) = Self::managed_identity_credential(entra_id) {
                    chain.push(credential);
                }
                if let Ok(credential) = DeveloperToolsCredential::new(None) {
                    chain.push(credential as Arc<dyn TokenCredential>);
                }

                if chain.is_empty() {
                    return Err(
                        "failed to create any default azure credential source for `entra_id`"
                            .into(),
                    );
                }

                Ok(Arc::new(AzureBlobDefaultCredentialChain { sources: chain }))
            }
        }
    }
}

#[derive(Debug)]
struct AzureBlobDefaultCredentialChain {
    sources: Vec<Arc<dyn TokenCredential>>,
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl TokenCredential for AzureBlobDefaultCredentialChain {
    async fn get_token(
        &self,
        scopes: &[&str],
        options: Option<azure_core::credentials::TokenRequestOptions<'_>>,
    ) -> azure_core::Result<azure_core::credentials::AccessToken> {
        let mut messages = Vec::new();
        let mut first_error = None;
        let mut current_options = options;
        for (idx, source) in self.sources.iter().enumerate() {
            // Reuse the original options on the final attempt to avoid an unnecessary clone.
            let request_options = if idx + 1 == self.sources.len() {
                current_options.take()
            } else {
                current_options.clone()
            };

            match source.get_token(scopes, request_options).await {
                Ok(token) => return Ok(token),
                Err(error) => {
                    messages.push(error.to_string());
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            }
        }

        let message = format!(
            "all default azure credential sources failed: {}",
            messages.join("; ")
        );

        let error = first_error.expect("at least one credential source should have been attempted");
        Err(azure_core::Error::with_error(
            azure_core::error::ErrorKind::Credential,
            error,
            message,
        ))
    }
}

#[derive(Debug, Clone)]
pub struct AzureBlobRequest {
    pub blob_data: Bytes,
    pub content_encoding: Option<&'static str>,
    pub content_type: &'static str,
    pub metadata: AzureBlobMetadata,
    pub request_metadata: RequestMetadata,
}

impl Finalizable for AzureBlobRequest {
    fn take_finalizers(&mut self) -> EventFinalizers {
        std::mem::take(&mut self.metadata.finalizers)
    }
}

impl MetaDescriptive for AzureBlobRequest {
    fn get_metadata(&self) -> &RequestMetadata {
        &self.request_metadata
    }

    fn metadata_mut(&mut self) -> &mut RequestMetadata {
        &mut self.request_metadata
    }
}

#[derive(Clone, Debug)]
pub struct AzureBlobMetadata {
    pub partition_key: String,
    pub count: usize,
    pub byte_size: JsonSize,
    pub finalizers: EventFinalizers,
}

#[derive(Debug, Clone)]
pub struct AzureBlobRetryLogic;

impl RetryLogic for AzureBlobRetryLogic {
    type Error = AzureCoreError;
    type Request = AzureBlobRequest;
    type Response = AzureBlobResponse;

    fn is_retriable_error(&self, error: &Self::Error) -> bool {
        match error.http_status() {
            Some(code) => code.is_server_error() || code == StatusCode::TooManyRequests,
            None => false,
        }
    }
}

#[derive(Debug)]
pub struct AzureBlobResponse {
    pub events_byte_size: GroupedCountByteSize,
    pub byte_size: usize,
}

impl DriverResponse for AzureBlobResponse {
    fn event_status(&self) -> EventStatus {
        EventStatus::Delivered
    }

    fn events_sent(&self) -> &GroupedCountByteSize {
        &self.events_byte_size
    }

    fn bytes_sent(&self) -> Option<usize> {
        Some(self.byte_size)
    }
}

#[derive(Debug, Snafu)]
pub enum HealthcheckError {
    #[snafu(display("Invalid connection string specified"))]
    InvalidCredentials,
    #[snafu(display("Container: {:?} not found", container))]
    UnknownContainer { container: String },
    #[snafu(display("Unknown status code: {}", status))]
    Unknown { status: StatusCode },
}

pub fn build_healthcheck(
    container_name: String,
    client: Arc<BlobContainerClient>,
) -> crate::Result<Healthcheck> {
    let healthcheck = async move {
        let resp: crate::Result<()> = match client.get_properties(None).await {
            Ok(_) => Ok(()),
            Err(error) => {
                let code = error.http_status();
                Err(match code {
                    Some(StatusCode::Forbidden) => Box::new(HealthcheckError::InvalidCredentials),
                    Some(StatusCode::NotFound) => Box::new(HealthcheckError::UnknownContainer {
                        container: container_name,
                    }),
                    Some(status) => Box::new(HealthcheckError::Unknown { status }),
                    None => "unknown status code".into(),
                })
            }
        };
        resp
    };

    Ok(healthcheck.boxed())
}

pub fn build_client(
    auth: &AzureBlobAuthConfig,
    container_name: String,
    proxy: &crate::config::ProxyConfig,
) -> crate::Result<Arc<BlobContainerClient>> {
    let mut options = BlobContainerClientOptions::default();
    let mut token_credential = None;
    let url = if !auth.connection_string.inner().is_empty() {
        // Parse connection string without legacy SDK
        let parsed = ParsedConnectionString::parse(auth.connection_string.inner())
            .map_err(|e| format!("Invalid connection string: {e}"))?;
        // Compose container URL (SAS appended if present)
        let container_url = parsed
            .container_url(&container_name)
            .map_err(|e| format!("Failed to build container URL: {e}"))?;
        let url = Url::parse(&container_url).map_err(|e| format!("Invalid container URL: {e}"))?;

        // Prepare options; attach Shared Key policy if needed
        match parsed.auth() {
            Auth::Sas { .. } | Auth::None => {
                // No extra policy; SAS is in the URL already (or anonymous)
            }
            Auth::SharedKey {
                account_name,
                account_key,
            } => {
                let policy = SharedKeyAuthorizationPolicy::new(
                    account_name,
                    account_key,
                    // Use an Azurite-supported storage service version
                    String::from("2025-11-05"),
                )
                .map_err(|e| format!("Failed to create SharedKey policy: {e}"))?;
                options
                    .client_options
                    .per_call_policies
                    .push(Arc::new(policy));
            }
        }
        url
    } else {
        let entra_id = auth.entra_id.as_ref().ok_or_else(|| {
            "either `connection_string` or `entra_id` must be configured".to_string()
        })?;
        token_credential = Some(auth.token_credential()?);
        Url::parse(&entra_id.endpoint).map_err(|e| format!("Invalid Entra endpoint URL: {e}"))?
    };

    // Use reqwest v0.12 since Azure SDK only implements HttpClient for reqwest::Client v0.12
    let mut reqwest_builder = reqwest_12::ClientBuilder::new();
    let bypass_proxy = {
        let host = url.host_str().unwrap_or("");
        let port = url.port();
        proxy.no_proxy.matches(host)
            || port
                .map(|p| proxy.no_proxy.matches(&format!("{}:{}", host, p)))
                .unwrap_or(false)
    };
    if bypass_proxy || !proxy.enabled {
        // Ensure no proxy (and disable any potential system proxy auto-detection)
        reqwest_builder = reqwest_builder.no_proxy();
    } else {
        if let Some(http) = &proxy.http {
            let p = reqwest_12::Proxy::http(http)
                .map_err(|e| format!("Invalid HTTP proxy URL: {e}"))?;
            // If credentials are embedded in the proxy URL, reqwest will handle them.
            reqwest_builder = reqwest_builder.proxy(p);
        }
        if let Some(https) = &proxy.https {
            let p = reqwest_12::Proxy::https(https)
                .map_err(|e| format!("Invalid HTTPS proxy URL: {e}"))?;
            // If credentials are embedded in the proxy URL, reqwest will handle them.
            reqwest_builder = reqwest_builder.proxy(p);
        }
    }
    options.client_options.transport = Some(azure_core::http::Transport::new(std::sync::Arc::new(
        reqwest_builder
            .build()
            .map_err(|e| format!("Failed to build reqwest client: {e}"))?,
    )));
    let client = if let Some(credential) = token_credential {
        BlobContainerClient::new(
            url.as_str(),
            &container_name,
            Some(credential),
            Some(options),
        )
        .map_err(|e| format!("{e}"))?
    } else {
        BlobContainerClient::from_url(url, None, Some(options)).map_err(|e| format!("{e}"))?
    };
    Ok(Arc::new(client))
}

#[cfg(test)]
mod tests {
    use super::{
        AzureBlobAuthConfig, AzureBlobEntraAuthMethod, AzureBlobEntraIdConfig, build_client,
    };

    #[test]
    fn build_client_requires_connection_string_or_entra() {
        let result = build_client(
            &AzureBlobAuthConfig {
                connection_string: String::new().into(),
                entra_id: None,
            },
            "logs".to_string(),
            &crate::config::ProxyConfig::default(),
        );

        match result {
            Ok(_) => panic!("expected missing auth configuration to fail"),
            Err(error) => assert!(
                error
                    .to_string()
                    .contains("either `connection_string` or `entra_id`")
            ),
        }
    }

    #[test]
    fn entra_client_secret_requires_client_id() {
        let result = build_client(
            &AzureBlobAuthConfig {
                connection_string: String::new().into(),
                entra_id: Some(AzureBlobEntraIdConfig {
                    endpoint: "https://example.blob.core.windows.net".to_string(),
                    tenant_id: Some("tenant".to_string()),
                    client_id: None,
                    client_secret: Some(String::from("secret").into()),
                    auth_method: AzureBlobEntraAuthMethod::ClientSecret,
                }),
            },
            "logs".to_string(),
            &crate::config::ProxyConfig::default(),
        );

        match result {
            Ok(_) => panic!("expected incomplete client secret auth config to fail"),
            Err(error) => assert!(
                error
                    .to_string()
                    .contains("`entra_id.client_id` is required")
            ),
        }
    }
}
