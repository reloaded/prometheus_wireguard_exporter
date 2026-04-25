// wg-easy stores peer names in `wg0.json` rather than as
// `# friendly_name=` comments inside `wg0.conf`. The mindflavor
// upstream only knows about the conf-comment form, so on a wg-easy
// install every peer is labelled by raw public_key with no name.
//
// This module reads wg-easy's `wg0.json` and synthesises the same
// `friendly_name` label the upstream emits for conf-comment-named
// peers. No new label or schema change — just fills the existing
// one with data the operator can read.
//
// Merge order vs. wg0.conf parsing: wg0.conf is parsed first via
// `wireguard_config::peer_entry_hashmap_try_from`, then this module
// fills in `friendly_description = None` slots from wg0.json. So an
// explicit `# friendly_name=` in the conf wins over the json — useful
// if the operator hand-edits a name in the conf, or runs the exporter
// against a hybrid wg0.conf+wg0.json where some peers were created
// outside wg-easy.

use crate::wireguard_config::{PeerEntry, PeerEntryHashMap};
use crate::FriendlyDescription;
use log::debug;

/// Merges peer names from a parsed wg-easy `wg0.json` into an
/// existing `PeerEntryHashMap`. Only fills entries that don't
/// already carry a `friendly_description`.
///
/// Borrows `publicKey` / `name` directly from the input `Value`
/// — the caller must keep the `Value` alive for the lifetime of
/// the hashmap.
pub(crate) fn merge_into<'a>(
    pehm: &mut PeerEntryHashMap<'a>,
    wg_easy_json: &'a serde_json::Value,
) {
    let clients = match wg_easy_json.get("clients").and_then(|c| c.as_object()) {
        Some(c) => c,
        None => {
            debug!("wg_easy_config::merge_into: no `clients` object found, skipping");
            return;
        }
    };

    for (uuid, client) in clients {
        let public_key = match client.get("publicKey").and_then(|v| v.as_str()) {
            Some(pk) if !pk.is_empty() => pk,
            _ => {
                debug!(
                    "wg_easy_config::merge_into: client {} has no publicKey, skipping",
                    uuid
                );
                continue;
            }
        };
        let name = match client.get("name").and_then(|v| v.as_str()) {
            Some(n) if !n.is_empty() => n,
            _ => {
                debug!(
                    "wg_easy_config::merge_into: client {} has no name, skipping",
                    uuid
                );
                continue;
            }
        };

        let entry = pehm.entry(public_key).or_insert_with(|| PeerEntry {
            public_key,
            allowed_ips: "",
            friendly_description: None,
        });

        if entry.friendly_description.is_none() {
            // Same quote-escape policy as the
            // `friendly_description::TryFrom` impl for
            // `("friendly_name", value)` — keeps Prometheus label
            // values valid when the wg-easy UI lets a user enter
            // something like `My "test" device`.
            let escaped = name.replace('\"', "\\\"");
            entry.friendly_description = Some(FriendlyDescription::Name(escaped.into()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WG_EASY_JSON_BASIC: &str = r#"{
        "server": {
            "privateKey": "redacted",
            "publicKey": "ServerPubKey=",
            "address": "10.0.10.1"
        },
        "clients": {
            "11111111-1111-1111-1111-111111111111": {
                "name": "phone-full",
                "address": "10.0.10.2",
                "privateKey": "redacted",
                "publicKey": "PhoneFullPubKey0123456789abcdefghijklmno=",
                "preSharedKey": "redacted",
                "createdAt": "2026-01-01T00:00:00.000Z",
                "updatedAt": "2026-01-01T00:00:00.000Z",
                "enabled": true
            },
            "22222222-2222-2222-2222-222222222222": {
                "name": "laptop split",
                "address": "10.0.10.3",
                "privateKey": "redacted",
                "publicKey": "LaptopSplitPubKey0123456789abcdefghijklm=",
                "preSharedKey": "redacted",
                "createdAt": "2026-01-01T00:00:00.000Z",
                "updatedAt": "2026-01-01T00:00:00.000Z",
                "enabled": true
            }
        }
    }"#;

    const WG_EASY_JSON_WITH_QUOTES: &str = r#"{
        "clients": {
            "33333333-3333-3333-3333-333333333333": {
                "name": "Jason's \"test\" device",
                "publicKey": "QuotedNameKey0123456789abcdefghijklmnopq="
            }
        }
    }"#;

    const WG_EASY_JSON_NO_CLIENTS: &str = r#"{ "server": {} }"#;

    const WG_EASY_JSON_PARTIAL_CLIENT: &str = r#"{
        "clients": {
            "44444444-4444-4444-4444-444444444444": {
                "name": "no-pubkey-client"
            },
            "55555555-5555-5555-5555-555555555555": {
                "publicKey": "no-name-key"
            },
            "66666666-6666-6666-6666-666666666666": {
                "name": "good-client",
                "publicKey": "GoodClientPubKey0123456789abcdefghijklm="
            }
        }
    }"#;

    fn parse(s: &str) -> serde_json::Value {
        serde_json::from_str(s).expect("test fixture json must parse")
    }

    #[test]
    fn merges_into_empty_hashmap() {
        let v = parse(WG_EASY_JSON_BASIC);
        let mut pehm = PeerEntryHashMap::new();
        merge_into(&mut pehm, &v);
        assert_eq!(pehm.len(), 2);

        let phone = pehm
            .get("PhoneFullPubKey0123456789abcdefghijklmno=")
            .expect("phone pubkey should be present");
        assert_eq!(
            phone.friendly_description,
            Some(FriendlyDescription::Name("phone-full".into()))
        );

        let laptop = pehm
            .get("LaptopSplitPubKey0123456789abcdefghijklm=")
            .expect("laptop pubkey should be present");
        assert_eq!(
            laptop.friendly_description,
            Some(FriendlyDescription::Name("laptop split".into()))
        );
    }

    #[test]
    fn does_not_overwrite_existing_friendly_name() {
        // Mirrors the real-world case: an operator hand-edits
        // `# friendly_name=` into wg0.conf for a peer that's also
        // in wg0.json. The conf-side name should win.
        let v = parse(WG_EASY_JSON_BASIC);
        let mut pehm = PeerEntryHashMap::new();
        pehm.insert(
            "PhoneFullPubKey0123456789abcdefghijklmno=",
            PeerEntry {
                public_key: "PhoneFullPubKey0123456789abcdefghijklmno=",
                allowed_ips: "10.0.10.2/32",
                friendly_description: Some(FriendlyDescription::Name("phone (conf override)".into())),
            },
        );

        merge_into(&mut pehm, &v);

        let phone = pehm
            .get("PhoneFullPubKey0123456789abcdefghijklmno=")
            .expect("phone pubkey should be present");
        assert_eq!(
            phone.friendly_description,
            Some(FriendlyDescription::Name("phone (conf override)".into()))
        );
    }

    #[test]
    fn escapes_double_quotes_in_name() {
        let v = parse(WG_EASY_JSON_WITH_QUOTES);
        let mut pehm = PeerEntryHashMap::new();
        merge_into(&mut pehm, &v);

        let entry = pehm
            .get("QuotedNameKey0123456789abcdefghijklmnopq=")
            .expect("quoted-name client should be present");
        assert_eq!(
            entry.friendly_description,
            Some(FriendlyDescription::Name(
                r#"Jason's \"test\" device"#.into()
            ))
        );
    }

    #[test]
    fn ignores_missing_clients_key() {
        let v = parse(WG_EASY_JSON_NO_CLIENTS);
        let mut pehm = PeerEntryHashMap::new();
        merge_into(&mut pehm, &v);
        assert!(pehm.is_empty());
    }

    #[test]
    fn skips_clients_missing_pubkey_or_name() {
        let v = parse(WG_EASY_JSON_PARTIAL_CLIENT);
        let mut pehm = PeerEntryHashMap::new();
        merge_into(&mut pehm, &v);

        // only the well-formed entry should make it through
        assert_eq!(pehm.len(), 1);
        let good = pehm
            .get("GoodClientPubKey0123456789abcdefghijklm=")
            .expect("good-client should be present");
        assert_eq!(
            good.friendly_description,
            Some(FriendlyDescription::Name("good-client".into()))
        );
    }

    #[test]
    fn merges_alongside_conf_parsed_entries() {
        // wg0.conf-parsed entries (by allowed_ips field, which
        // wg0.json synthesised entries leave empty) coexist with
        // wg0.json-synthesised entries: the conf-parsed entry
        // already had a public_key, so wg0.json's pass through
        // `entry.or_insert_with` is a no-op for pubkey,
        // friendly_description fills in.
        const CONF: &str = "
[Peer]
PublicKey = PhoneFullPubKey0123456789abcdefghijklmno=
AllowedIPs = 10.0.10.2/32

[Peer]
PublicKey = StrayPubKeyOnlyInConf0123456789abcdefghi=
AllowedIPs = 10.0.10.99/32
";

        let mut pehm = crate::wireguard_config::peer_entry_hashmap_try_from(CONF)
            .expect("conf parses cleanly");
        let v = parse(WG_EASY_JSON_BASIC);
        merge_into(&mut pehm, &v);

        // conf-side pubkey now has a name from wg0.json
        let phone = pehm
            .get("PhoneFullPubKey0123456789abcdefghijklmno=")
            .expect("phone pubkey should be present");
        assert_eq!(
            phone.friendly_description,
            Some(FriendlyDescription::Name("phone-full".into()))
        );
        // conf-side allowed_ips is preserved (wg0.json doesn't
        // touch it)
        assert_eq!(phone.allowed_ips, "10.0.10.2/32");

        // conf-only stray peer is unaffected
        let stray = pehm
            .get("StrayPubKeyOnlyInConf0123456789abcdefghi=")
            .expect("stray conf-only pubkey should still be there");
        assert_eq!(stray.friendly_description, None);

        // wg0.json-only entry showed up
        let laptop = pehm
            .get("LaptopSplitPubKey0123456789abcdefghijklm=")
            .expect("laptop should be present from wg0.json");
        assert_eq!(
            laptop.friendly_description,
            Some(FriendlyDescription::Name("laptop split".into()))
        );
    }

}
