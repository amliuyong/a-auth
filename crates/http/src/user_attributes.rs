//! Exact attribute-size accounting shared by durable and development adapters.

use crate::ports::{FederatedAttributeOwner, NamespaceAttrs};
use std::collections::BTreeMap;

pub(crate) fn attributes_serialized_len(attrs: &BTreeMap<String, NamespaceAttrs>) -> usize {
    #[derive(serde::Serialize)]
    struct NamespaceView<'a> {
        kv: &'a BTreeMap<String, String>,
        federation_owners: &'a BTreeMap<String, FederatedAttributeOwner>,
    }
    let view: BTreeMap<&String, NamespaceView<'_>> = attrs
        .iter()
        .map(|(namespace, attributes)| {
            (
                namespace,
                NamespaceView {
                    kv: &attributes.kv,
                    federation_owners: &attributes.federation_owners,
                },
            )
        })
        .collect();
    serde_json::to_vec(&view)
        .map(|v| v.len())
        .unwrap_or(usize::MAX)
}
