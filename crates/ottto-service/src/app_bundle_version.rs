//! On-disk version evidence for the Ottto app bundle, for local diagnostics.
//!
//! The service's own compiled version says nothing about the app: Homebrew and
//! the app can be installed side by side at different versions, and Sparkle
//! replaces the app independently of a Homebrew-owned service. The only
//! evidence used here is an `Info.plist` whose `CFBundleIdentifier` is the
//! Ottto app's. Anything less qualified reports no version.

use serde::Deserialize;
use std::io::Read;
use std::path::{Path, PathBuf};

const COMPANION_BUNDLE_IDENTIFIER: &str = "net.ottto.Companion";
const APP_BUNDLE_NAME: &str = "Ottto.app";
// A packaged Ottto Info.plist is a few KiB and a few collections deep.
const MAX_INFO_PLIST_BYTES: u64 = 64 * 1024;
const MAX_INFO_PLIST_DEPTH: usize = 16;
const MAX_VERSION_LEN: usize = 64;

/// What one candidate bundle location proved.
#[derive(Debug, PartialEq, Eq)]
enum BundleEvidence {
    /// No bundle at this location.
    Absent,
    /// A bundle exists but belongs to another app.
    Foreign,
    /// An Ottto bundle whose version cannot be read or validated.
    Unqualified,
    Version(String),
}

/// `app_version` for the local diagnostics bundle: the proven installed app
/// version, or `unknown`. Unit tests never read the host's app bundles.
pub(crate) fn diagnostics_app_version(current_exe: Option<&Path>, home: Option<&Path>) -> String {
    let version = if cfg!(test) {
        None
    } else {
        installed_app_version(current_exe, home, Path::new("/Applications"))
    };
    version.unwrap_or_else(|| "unknown".to_string())
}

/// The installed Ottto app version, or `None` when it is not proven.
///
/// When this service runs from inside an app bundle
/// (`<bundle>.app/Contents/Helpers/<service>`), only that enclosing bundle
/// counts: it is the bundle the service ships in. Otherwise the service is a
/// Homebrew, installer or development binary, and an app may coexist at
/// `~/Applications` or `system_applications`; its version is reported only
/// when every Ottto bundle found there agrees on one valid version.
pub(crate) fn installed_app_version(
    current_exe: Option<&Path>,
    home: Option<&Path>,
    system_applications: &Path,
) -> Option<String> {
    if let Some(bundle) = current_exe.and_then(enclosing_app_bundle) {
        return match bundle_evidence(&bundle) {
            BundleEvidence::Version(version) => Some(version),
            _ => None,
        };
    }

    let mut candidates = Vec::new();
    if let Some(home) = home {
        candidates.push(home.join("Applications").join(APP_BUNDLE_NAME));
    }
    candidates.push(system_applications.join(APP_BUNDLE_NAME));

    let mut found: Option<String> = None;
    for candidate in candidates {
        match bundle_evidence(&candidate) {
            BundleEvidence::Absent | BundleEvidence::Foreign => {}
            BundleEvidence::Unqualified => return None,
            BundleEvidence::Version(version) => match &found {
                Some(existing) if *existing != version => return None,
                Some(_) => {}
                None => found = Some(version),
            },
        }
    }
    found
}

/// `<bundle>.app` when `exe` is `<bundle>.app/Contents/Helpers/<name>`.
fn enclosing_app_bundle(exe: &Path) -> Option<PathBuf> {
    let helpers = exe.parent()?;
    let contents = helpers.parent()?;
    let bundle = contents.parent()?;
    let is_layout = helpers.file_name()? == "Helpers"
        && contents.file_name()? == "Contents"
        && bundle.extension()? == "app";
    is_layout.then(|| bundle.to_path_buf())
}

fn bundle_evidence(bundle: &Path) -> BundleEvidence {
    if !bundle.is_dir() {
        return BundleEvidence::Absent;
    }
    let Some(info) = read_info_keys(&bundle.join("Contents").join("Info.plist")) else {
        return BundleEvidence::Unqualified;
    };
    match info.identifier.as_deref() {
        Some(COMPANION_BUNDLE_IDENTIFIER) => {}
        Some(_) => return BundleEvidence::Foreign,
        None => return BundleEvidence::Unqualified,
    }
    match info.short_version.filter(|version| valid_version(version)) {
        Some(version) => BundleEvidence::Version(version),
        None => BundleEvidence::Unqualified,
    }
}

#[derive(Deserialize)]
struct InfoKeys {
    #[serde(rename = "CFBundleIdentifier")]
    identifier: Option<String>,
    #[serde(rename = "CFBundleShortVersionString")]
    short_version: Option<String>,
}

/// Reads the two top-level string keys from an XML `Info.plist`.
///
/// Binary plists are refused: their shared object references can expand far
/// beyond the file size, and packaged Ottto bundles write XML. The XML must
/// also pass [`plain_plist_xml_within`] before parsing, because skipping
/// unknown values recurses once per nesting level. A duplicate or non-string
/// value for either key fails the read.
fn read_info_keys(path: &Path) -> Option<InfoKeys> {
    let file = std::fs::File::open(path).ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(MAX_INFO_PLIST_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > MAX_INFO_PLIST_BYTES
        || !plain_plist_xml_within(&bytes, MAX_INFO_PLIST_DEPTH)
    {
        return None;
    }
    plist::from_reader_xml(bytes.as_slice()).ok()
}

/// Accepts only the plain plist vocabulary a packaged Info.plist uses, with
/// collection nesting at most `max_depth`.
///
/// Every markup token must be the standard XML declaration, the Apple plist
/// DOCTYPE, `<plist version="1.0">`, or a bare plist element tag with no
/// attributes. Anything the parser could read differently from this count is
/// rejected: comments, CDATA, processing instructions, namespaces,
/// attributes, other DOCTYPEs, and binary plists (no leading `<`).
fn plain_plist_xml_within(bytes: &[u8], max_depth: usize) -> bool {
    const FIXED_TAGS: [&[u8]; 4] = [
        br#"?xml version="1.0" encoding="UTF-8"?"#,
        br#"!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd""#,
        br#"plist version="1.0""#,
        b"/plist",
    ];
    const ELEMENTS: [&[u8]; 10] = [
        b"dict", b"array", b"key", b"string", b"true", b"false", b"integer", b"real", b"date",
        b"data",
    ];

    if !bytes.trim_ascii_start().starts_with(b"<") {
        return false;
    }
    let mut depth = 0_usize;
    let mut rest = bytes;
    while let Some(start) = rest.iter().position(|byte| *byte == b'<') {
        rest = &rest[start + 1..];
        let Some(end) = rest.iter().position(|byte| *byte == b'>') else {
            return false;
        };
        let tag = &rest[..end];
        rest = &rest[end + 1..];
        if FIXED_TAGS.contains(&tag) {
            continue;
        }
        let (closing, name) = match tag.strip_prefix(b"/") {
            Some(name) => (true, name),
            None => (false, tag),
        };
        let (empty, name) = match name.strip_suffix(b"/") {
            Some(name) if !closing => (true, name),
            Some(_) => return false,
            None => (false, name),
        };
        if !ELEMENTS.contains(&name) {
            return false;
        }
        if empty || !(name == b"dict" || name == b"array") {
            continue;
        }
        if closing {
            let Some(outer) = depth.checked_sub(1) else {
                return false;
            };
            depth = outer;
        } else {
            depth += 1;
            if depth > max_depth {
                return false;
            }
        }
    }
    true
}

fn valid_version(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= MAX_VERSION_LEN
        && version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+' | b'_'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_scratch;

    struct Scratch(PathBuf);

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn scratch() -> Scratch {
        Scratch(test_scratch::private_dir("ottto-app-bundle-version"))
    }

    fn write_bundle(bundle: &Path, info_plist: &str) {
        std::fs::create_dir_all(bundle.join("Contents").join("Helpers")).unwrap();
        std::fs::write(bundle.join("Contents").join("Info.plist"), info_plist).unwrap();
    }

    fn info_plist(identifier: &str, version: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key>
  <string>{identifier}</string>
  <key>CFBundleShortVersionString</key>
  <string>{version}</string>
  <key>CFBundleVersion</key>
  <string>{version}</string>
</dict>
</plist>
"#
        )
    }

    fn helper_in(bundle: &Path) -> PathBuf {
        bundle
            .join("Contents")
            .join("Helpers")
            .join("ottto-service")
    }

    #[test]
    fn app_owned_service_reports_its_enclosing_bundle_version() {
        let root = scratch();
        let bundle = root.0.join("Elsewhere").join("Ottto.app");
        write_bundle(&bundle, &info_plist(COMPANION_BUNDLE_IDENTIFIER, "0.1.162"));
        // A different installed copy must not override the bundle the
        // service actually runs from.
        let system = root.0.join("Applications");
        write_bundle(
            &system.join(APP_BUNDLE_NAME),
            &info_plist(COMPANION_BUNDLE_IDENTIFIER, "0.1.150"),
        );

        assert_eq!(
            installed_app_version(Some(&helper_in(&bundle)), None, &system),
            Some("0.1.162".to_string())
        );
    }

    #[test]
    fn app_owned_service_with_unreadable_bundle_stays_unknown() {
        let root = scratch();
        let bundle = root.0.join("Ottto.app");
        write_bundle(&bundle, "not a plist");
        let system = root.0.join("Applications");
        write_bundle(
            &system.join(APP_BUNDLE_NAME),
            &info_plist(COMPANION_BUNDLE_IDENTIFIER, "0.1.162"),
        );

        // Never substitute another copy for the enclosing bundle.
        assert_eq!(
            installed_app_version(Some(&helper_in(&bundle)), None, &system),
            None
        );
    }

    #[test]
    fn homebrew_service_reports_coexisting_app_version_not_its_own() {
        let root = scratch();
        let system = root.0.join("Applications");
        write_bundle(
            &system.join(APP_BUNDLE_NAME),
            &info_plist(COMPANION_BUNDLE_IDENTIFIER, "0.1.161"),
        );
        let homebrew_exe = root
            .0
            .join("opt/homebrew/Cellar/ottto/0.1.162/bin/ottto-service");

        assert_eq!(
            installed_app_version(Some(&homebrew_exe), Some(&root.0.join("home")), &system),
            Some("0.1.161".to_string())
        );
    }

    #[test]
    fn homebrew_service_without_an_app_stays_unknown() {
        let root = scratch();
        let homebrew_exe = root
            .0
            .join("opt/homebrew/Cellar/ottto/0.1.162/bin/ottto-service");

        assert_eq!(
            installed_app_version(
                Some(&homebrew_exe),
                Some(&root.0.join("home")),
                &root.0.join("Applications")
            ),
            None
        );
    }

    #[test]
    fn conflicting_installed_copies_stay_unknown() {
        let root = scratch();
        let home = root.0.join("home");
        let system = root.0.join("Applications");
        write_bundle(
            &home.join("Applications").join(APP_BUNDLE_NAME),
            &info_plist(COMPANION_BUNDLE_IDENTIFIER, "0.1.160"),
        );
        write_bundle(
            &system.join(APP_BUNDLE_NAME),
            &info_plist(COMPANION_BUNDLE_IDENTIFIER, "0.1.162"),
        );

        assert_eq!(installed_app_version(None, Some(&home), &system), None);
    }

    #[test]
    fn missing_or_malformed_plists_stay_unknown() {
        let root = scratch();
        let system = root.0.join("Applications");
        let bundle = system.join(APP_BUNDLE_NAME);

        std::fs::create_dir_all(bundle.join("Contents")).unwrap();
        assert_eq!(installed_app_version(None, None, &system), None);

        std::fs::write(bundle.join("Contents").join("Info.plist"), "<plist>").unwrap();
        assert_eq!(installed_app_version(None, None, &system), None);

        write_bundle(&bundle, &info_plist(COMPANION_BUNDLE_IDENTIFIER, ""));
        assert_eq!(installed_app_version(None, None, &system), None);

        write_bundle(
            &bundle,
            &info_plist(COMPANION_BUNDLE_IDENTIFIER, "0.1.162 <script>"),
        );
        assert_eq!(installed_app_version(None, None, &system), None);
    }

    fn plist_with_body(body: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
{body}
</plist>
"#
        )
    }

    fn system_version_for(info_plist: &str) -> Option<String> {
        let root = scratch();
        let system = root.0.join("Applications");
        write_bundle(&system.join(APP_BUNDLE_NAME), info_plist);
        installed_app_version(None, None, &system)
    }

    #[test]
    fn packaged_shape_with_nested_keys_reports_top_level_version() {
        // Nested dictionaries (URL types) may repeat key names; only the
        // top-level values count.
        let body = format!(
            r#"<dict>
  <key>CFBundleIdentifier</key>
  <string>{COMPANION_BUNDLE_IDENTIFIER}</string>
  <key>CFBundleShortVersionString</key>
  <string>0.1.162</string>
  <key>CFBundleURLTypes</key>
  <array>
    <dict>
      <key>CFBundleIdentifier</key>
      <string>com.example.Other</string>
      <key>CFBundleShortVersionString</key>
      <string>9.9.9</string>
    </dict>
  </array>
  <key>LSMinimumSystemVersion</key>
  <string>14.0</string>
  <key>NSHighResolutionCapable</key>
  <true/>
</dict>"#
        );
        assert_eq!(
            system_version_for(&plist_with_body(&body)),
            Some("0.1.162".to_string())
        );
    }

    #[test]
    fn binary_plists_are_refused_without_expanding_them() {
        let mut info = plist::Dictionary::new();
        info.insert(
            "CFBundleIdentifier".to_string(),
            plist::Value::String(COMPANION_BUNDLE_IDENTIFIER.to_string()),
        );
        info.insert(
            "CFBundleShortVersionString".to_string(),
            plist::Value::String("0.1.162".to_string()),
        );
        let mut binary = Vec::new();
        plist::Value::Dictionary(info)
            .to_writer_binary(&mut binary)
            .unwrap();
        assert!(binary.starts_with(b"bplist"));

        let root = scratch();
        let system = root.0.join("Applications");
        let bundle = system.join(APP_BUNDLE_NAME);
        std::fs::create_dir_all(bundle.join("Contents")).unwrap();
        std::fs::write(bundle.join("Contents").join("Info.plist"), binary).unwrap();
        assert_eq!(installed_app_version(None, None, &system), None);
    }

    #[test]
    fn hostile_xml_shapes_stay_unknown() {
        let identifier =
            format!("<key>CFBundleIdentifier</key><string>{COMPANION_BUNDLE_IDENTIFIER}</string>");
        let version = "<key>CFBundleShortVersionString</key><string>0.1.162</string>";

        let deep = format!(
            "<dict>{identifier}{version}<key>Deep</key>{}{}</dict>",
            "<array>".repeat(MAX_INFO_PLIST_DEPTH + 1),
            "</array>".repeat(MAX_INFO_PLIST_DEPTH + 1)
        );
        let duplicate = format!(
            "<dict>{identifier}{version}<key>CFBundleShortVersionString</key><string>0.1.1</string></dict>"
        );
        let non_string = format!(
            "<dict>{identifier}<key>CFBundleShortVersionString</key><integer>162</integer></dict>"
        );
        let collection_value = format!(
            "<dict>{identifier}<key>CFBundleShortVersionString</key><array><string>0.1.162</string></array></dict>"
        );
        let array_root = format!("<array><dict>{identifier}{version}</dict></array>");
        let hidden_close = format!(
            "<dict>{identifier}{version}<key>Note</key><string><![CDATA[</dict>]]></string></dict>"
        );
        let comment = format!("<dict><!-- note -->{identifier}{version}</dict>");
        // Each of these would hide collection depth from a looser scan.
        let namespaced = format!(
            "<dict xmlns:x=\"urn:x\">{identifier}{version}<key>Deep</key>{}{}</dict>",
            "<x:array>".repeat(MAX_INFO_PLIST_DEPTH + 1),
            "</x:array>".repeat(MAX_INFO_PLIST_DEPTH + 1)
        );
        let instruction = format!(
            "<dict>{identifier}{version}<key>Deep</key>{}{}</dict>",
            "<array><?p > </array>?>".repeat(MAX_INFO_PLIST_DEPTH + 1),
            "</array>".repeat(MAX_INFO_PLIST_DEPTH + 1)
        );
        let attribute = format!(
            "<dict>{identifier}{version}<key>Deep</key><array note=\"></array>\"></array></dict>"
        );
        let internal_subset =
            format!("<!DOCTYPE plist [<!ENTITY e \"x\">]><plist version=\"1.0\"><dict>{identifier}{version}</dict></plist>");
        for body in [
            deep,
            duplicate,
            non_string,
            collection_value,
            array_root,
            hidden_close,
            comment,
            namespaced,
            instruction,
            attribute,
        ] {
            assert_eq!(
                system_version_for(&plist_with_body(&body)),
                None,
                "{body:.80}"
            );
        }

        assert_eq!(system_version_for(&internal_subset), None);

        let oversized = format!(
            "<dict>{identifier}{version}<key>Padding</key><string>{}</string></dict>",
            "x".repeat(MAX_INFO_PLIST_BYTES as usize)
        );
        assert_eq!(system_version_for(&plist_with_body(&oversized)), None);
    }

    #[test]
    fn foreign_bundle_named_ottto_is_ignored() {
        let root = scratch();
        let home = root.0.join("home");
        let system = root.0.join("Applications");
        write_bundle(
            &home.join("Applications").join(APP_BUNDLE_NAME),
            &info_plist("com.example.Other", "9.9.9"),
        );
        write_bundle(
            &system.join(APP_BUNDLE_NAME),
            &info_plist(COMPANION_BUNDLE_IDENTIFIER, "0.1.162"),
        );

        assert_eq!(
            installed_app_version(None, Some(&home), &system),
            Some("0.1.162".to_string())
        );
    }
}
