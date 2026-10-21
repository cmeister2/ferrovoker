//! Immutable certificate identifiers indexed from browser revocation feeds.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use x509_parser::{parse_x509_certificate, prelude::X509Certificate};

use crate::{CrlSet, CrlSetHeader, Error, OneCrl, Result};

/// The feed identifier that matched a certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevocationReason {
    /// Mozilla listed the certificate's DER issuer name and serial number.
    OneCrlIssuerSerial,
    /// Mozilla listed its DER subject name and SubjectPublicKeyInfo hash.
    OneCrlSubjectPublicKey,
    /// Chrome listed its SubjectPublicKeyInfo hash as blocked.
    CrlSetBlockedSpki,
    /// Chrome restricted its subject to a different set of public keys.
    CrlSetLimitedSubject,
    /// Chrome listed its serial number under a supplied issuer's SPKI hash.
    CrlSetSerial,
}

/// A certificate matched a revocation identifier in one of the supplied feeds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RevocationMatch {
    /// Position of the matching certificate in the supplied leaf-first chain.
    pub certificate_index: usize,
    /// The matching identifier's feed and form.
    pub reason: RevocationReason,
}

/// All matching feed identifiers for one unique certificate in the input chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateRevocations {
    /// First position of this exact DER certificate in the supplied chain.
    pub certificate_index: usize,
    /// Distinct matching identifier forms, in a stable feed and reason order.
    pub reasons: Vec<RevocationReason>,
}

/// Supplemental issuer identifiers, such as those available in a TLS trust store.
///
/// These identifiers enable CRLSet issuer/serial lookups when an issuer's full
/// certificate is absent from the supplied chain. They do not establish that
/// the identified key signed a certificate or belongs to its verified path.
/// Provide identifiers from a trusted source and retain normal TLS validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuerIdentity {
    /// Issuer's complete DER-encoded subject name, including its SEQUENCE header.
    pub subject_der: Vec<u8>,
    /// SHA-256 of its complete DER SubjectPublicKeyInfo, including its SEQUENCE header.
    pub spki_sha256: [u8; 32],
}

/// Whether the supplied certificates matched the loaded revocation feeds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevocationStatus {
    /// No identifier matched; this does not establish that certificates are good.
    ///
    /// Browser feeds cover only part of the revoked certificate population.
    NotListed,
    /// At least one certificate matched a revocation identifier.
    Revoked(RevocationMatch),
}

/// Immutable revocation identifiers suitable for sharing between TLS clients.
///
/// This checks the supplied feed data, including enabled OneCRL records and
/// CRLSet SPKI, limited-subject, and issuer/serial entries. It does not build or
/// authenticate certificate paths, check certificate signatures or names, or
/// verify feed signatures. Keep normal TLS validation enabled. Browser feeds
/// are partial and do not include every browser-specific trust policy.
#[derive(Debug)]
pub struct RevocationSet {
    /// DER issuer names mapped to Mozilla's unmodified serial-number bytes.
    onecrl_issuer_serials: HashMap<Vec<u8>, HashSet<Vec<u8>>>,
    /// DER subject names mapped to hashes of complete DER SubjectPublicKeyInfo values.
    onecrl_subject_keys: HashMap<Vec<u8>, HashSet<[u8; 32]>>,
    /// Chrome's optional full snapshot, indexed independently of OneCRL.
    crlset: Option<CrlSetIndex>,
}

/// Chrome's binary and header revocation identifiers.
#[derive(Debug)]
struct CrlSetIndex {
    /// Hashes of complete DER SubjectPublicKeyInfo values that must be blocked.
    blocked_spkis: HashSet<[u8; 32]>,
    /// Subject DER hashes mapped to the SPKI hashes still allowed for that name.
    limited_subjects: HashMap<[u8; 32], HashSet<[u8; 32]>>,
    /// Issuer SPKI hashes mapped to unsigned serial-number bytes without padding.
    issuer_serials: HashMap<[u8; 32], HashSet<Vec<u8>>>,
    /// Last usable Unix second, or zero when the feed specifies no expiration.
    not_after: u64,
}

impl RevocationSet {
    /// Index one or both complete feed snapshots for certificate checks.
    ///
    /// Disabled OneCRL records do not block certificates. CRLSet bytes are
    /// authoritative; the separately exposed parsed header is not consulted.
    /// Full snapshots are required; CRLSet deltas cannot be applied here.
    /// Neither feed's publisher signature is verified by this operation.
    ///
    /// # Errors
    ///
    /// Returns an error if neither feed is supplied, a OneCRL record has an
    /// invalid identifier combination, an enabled identifier has invalid base64
    /// or hash length, or a CRLSet header or body is malformed, truncated,
    /// unsupported, or describes a delta rather than a full snapshot.
    pub fn from_snapshots(onecrl: Option<&OneCrl>, crlset: Option<&CrlSet>) -> Result<Self> {
        if onecrl.is_none() && crlset.is_none() {
            return Err(Error::InvalidFormat(
                "at least one revocation feed is required",
            ));
        }
        let mut set = Self {
            onecrl_issuer_serials: HashMap::new(),
            onecrl_subject_keys: HashMap::new(),
            crlset: crlset.map(CrlSetIndex::from_snapshot).transpose()?,
        };
        if let Some(snapshot) = onecrl {
            for record in &snapshot.changes {
                record.validate()?;
                if !record.enabled {
                    continue;
                }
                match (
                    &record.issuer_name,
                    &record.serial_number,
                    &record.subject,
                    &record.public_key_hash,
                ) {
                    (Some(issuer), Some(serial), None, None) => {
                        set.onecrl_issuer_serials
                            .entry(decode_identifier(issuer)?)
                            .or_default()
                            .insert(decode_identifier(serial)?);
                    }
                    (None, None, Some(subject), Some(key_hash)) => {
                        set.onecrl_subject_keys
                            .entry(decode_identifier(subject)?)
                            .or_default()
                            .insert(decode_hash(key_hash)?);
                    }
                    _ => return Err(Error::InvalidFormat("invalid OneCRL revocation record")),
                }
            }
        }
        Ok(set)
    }

    /// Check DER, PEM, or base64 certificates and return the first match.
    ///
    /// Supply the leaf first, followed by available issuer candidates in any
    /// order. Chrome serial entries use every supplied certificate whose subject
    /// DER matches a certificate's issuer DER. Any matching blocked pair rejects
    /// the certificate. A certificate without a supplied issuer cannot be checked
    /// against those serial entries. Other identifiers check every certificate.
    /// Use [`Self::check_chain_with_issuers`] when issuer identifiers are
    /// available separately, for example from a TLS trust store.
    /// Each entry must contain exactly one complete DER certificate, one PEM
    /// `CERTIFICATE` block, or standard base64-encoded DER. Text encodings may
    /// contain ASCII whitespace. Formats may be mixed within a chain; returned
    /// indexes always refer to the original entries.
    ///
    /// `unix_time` is the current number of seconds since the Unix epoch and is
    /// used to reject an expired CRLSet. OneCRL has no equivalent expiry field;
    /// callers must enforce their own refresh policy for their cached snapshots.
    ///
    /// This does not validate certificate signatures, certificate validity dates,
    /// trust, hostnames, or feed signatures. A [`RevocationStatus::NotListed`]
    /// result establishes only that the supplied feeds contain no matching entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidCertificate`] for an empty chain or entry,
    /// malformed encoding or certificate, PEM bundles or a different PEM label,
    /// or extra data surrounding a certificate.
    /// Returns [`Error::ExpiredCrlSet`] when its nonzero `NotAfter` is earlier
    /// than `unix_time`.
    pub fn check_chain(&self, chain: &[&[u8]], unix_time: u64) -> Result<RevocationStatus> {
        self.check_chain_with_issuers(chain, &[], unix_time)
    }

    /// Check certificates with additional issuer identifiers and return the first match.
    ///
    /// Supplemental `issuers` participate only in CRLSet issuer/serial lookups
    /// for certificates in `chain`; they are not themselves checked against
    /// revocation entries. Their complete subject DER must equal the checked
    /// certificate's issuer DER. Any matching blocked pair rejects that
    /// certificate without establishing which issuer signed it.
    ///
    /// Other behavior and validation limitations match [`Self::check_chain`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidCertificate`] for an empty chain or entry,
    /// malformed DER/PEM/base64, certificate bundles, or extra data, and
    /// [`Error::ExpiredCrlSet`] for an expired CRLSet.
    pub fn check_chain_with_issuers(
        &self,
        chain: &[&[u8]],
        issuers: &[IssuerIdentity],
        unix_time: u64,
    ) -> Result<RevocationStatus> {
        let matches = self.check_chain_all_with_issuers(chain, issuers, unix_time)?;
        Ok(matches
            .into_iter()
            .find_map(|matched| {
                matched.reasons.into_iter().next().map(|reason| {
                    RevocationStatus::Revoked(RevocationMatch {
                        certificate_index: matched.certificate_index,
                        reason,
                    })
                })
            })
            .unwrap_or(RevocationStatus::NotListed))
    }

    /// Collect every matching reason once for each unique DER certificate.
    ///
    /// A certificate appearing repeatedly in `chain`, including in different
    /// supported encodings, is reported only once at its first position.
    /// Identical rules within each feed are indexed once;
    /// different OneCRL and CRLSet identifier forms remain distinct reasons.
    /// Certificates with no match are omitted. An empty result has the same
    /// limited meaning as [`RevocationStatus::NotListed`].
    ///
    /// Issuer-candidate handling, feed expiry, validation limitations, and the
    /// meaning of `unix_time` are the same as for [`Self::check_chain`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidCertificate`] for an empty chain or entry,
    /// malformed DER/PEM/base64, certificate bundles, or extra data, and
    /// [`Error::ExpiredCrlSet`] for an expired CRLSet.
    pub fn check_chain_all(
        &self,
        chain: &[&[u8]],
        unix_time: u64,
    ) -> Result<Vec<CertificateRevocations>> {
        self.check_chain_all_with_issuers(chain, &[], unix_time)
    }

    /// Collect distinct matches per certificate with supplemental issuer identifiers.
    ///
    /// Deduplication and validation behavior match [`Self::check_chain_all`].
    /// Supplemental identifiers participate only in issuer/serial lookups as
    /// described by [`Self::check_chain_with_issuers`]; they cannot add reported
    /// certificates beyond those present in `chain`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidCertificate`] for an empty chain or entry,
    /// malformed DER/PEM/base64, certificate bundles, or extra data, and
    /// [`Error::ExpiredCrlSet`] for an expired CRLSet.
    pub fn check_chain_all_with_issuers(
        &self,
        chain: &[&[u8]],
        issuers: &[IssuerIdentity],
        unix_time: u64,
    ) -> Result<Vec<CertificateRevocations>> {
        if let Some(crlset) = &self.crlset
            && crlset.not_after != 0
            && unix_time > crlset.not_after
        {
            return Err(Error::ExpiredCrlSet);
        }
        if chain.is_empty() {
            return Err(Error::InvalidCertificate);
        }
        let normalized = chain
            .iter()
            .map(|bytes| normalize_certificate(bytes))
            .collect::<Result<Vec<_>>>()?;
        let certificates = normalized
            .iter()
            .map(|der| {
                let (remainder, certificate) =
                    parse_x509_certificate(der.as_ref()).map_err(|_| Error::InvalidCertificate)?;
                if !remainder.is_empty()
                    || certificate.public_key().subject_public_key.unused_bits != 0
                {
                    return Err(Error::InvalidCertificate);
                }
                Ok(certificate)
            })
            .collect::<Result<Vec<_>>>()?;
        let mut matches = Vec::new();
        let mut seen = HashSet::new();
        for (index, certificate) in certificates.iter().enumerate() {
            if !seen.insert(certificate.as_raw()) {
                continue;
            }
            let reasons = self.check_certificate(certificate, &certificates, issuers);
            if !reasons.is_empty() {
                matches.push(CertificateRevocations {
                    certificate_index: index,
                    reasons,
                });
            }
        }
        Ok(matches)
    }

    /// Collect distinct matching identifier forms using every supplied issuer candidate.
    fn check_certificate(
        &self,
        certificate: &X509Certificate<'_>,
        candidates: &[X509Certificate<'_>],
        issuers: &[IssuerIdentity],
    ) -> Vec<RevocationReason> {
        let mut reasons = Vec::new();
        if self
            .onecrl_issuer_serials
            .get(certificate.issuer().as_raw())
            .is_some_and(|serials| serials.contains(certificate.raw_serial()))
        {
            reasons.push(RevocationReason::OneCrlIssuerSerial);
        }
        if self
            .onecrl_subject_keys
            .get(certificate.subject().as_raw())
            .is_some_and(|keys| keys.contains(&sha256(certificate.public_key().raw)))
        {
            reasons.push(RevocationReason::OneCrlSubjectPublicKey);
        }
        let Some(crlset) = &self.crlset else {
            return reasons;
        };
        let spki_hash = sha256(certificate.public_key().raw);
        if crlset.blocked_spkis.contains(&spki_hash) {
            reasons.push(RevocationReason::CrlSetBlockedSpki);
        }
        if crlset
            .limited_subjects
            .get(&sha256(certificate.subject().as_raw()))
            .is_some_and(|allowed| !allowed.contains(&spki_hash))
        {
            reasons.push(RevocationReason::CrlSetLimitedSubject);
        }
        if let Some(serial) = chrome_serial(certificate.raw_serial())
            && (candidates.iter().any(|issuer| {
                issuer.subject().as_raw() == certificate.issuer().as_raw()
                    && crlset
                        .issuer_serials
                        .get(&sha256(issuer.public_key().raw))
                        .is_some_and(|serials| serials.contains(serial))
            }) || issuers.iter().any(|issuer| {
                issuer.subject_der == certificate.issuer().as_raw()
                    && crlset
                        .issuer_serials
                        .get(&issuer.spki_sha256)
                        .is_some_and(|serials| serials.contains(serial))
            }))
        {
            reasons.push(RevocationReason::CrlSetSerial);
        }
        reasons
    }
}

/// Borrows DER directly or decodes one PEM/base64 text value.
///
/// Complete X.509 parsing happens after every chain entry has been normalized,
/// retaining ownership of decoded buffers throughout issuer lookup and deduplication.
///
/// # Errors
///
/// Returns an invalid-certificate error for empty input, malformed text/base64,
/// incorrect PEM boundaries or labels, or a PEM bundle containing extra blocks.
fn normalize_certificate(bytes: &[u8]) -> Result<Cow<'_, [u8]>> {
    if bytes.first() == Some(&0x30) {
        return Ok(Cow::Borrowed(bytes));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| Error::InvalidCertificate)?
        .trim_matches(|character: char| character.is_ascii_whitespace() || character == '\u{000b}');
    let encoded = if let Some(body) = text.strip_prefix("-----BEGIN CERTIFICATE-----") {
        body.strip_suffix("-----END CERTIFICATE-----")
            .ok_or(Error::InvalidCertificate)?
    } else {
        text
    };
    let compact: Vec<u8> = encoded
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace() && *byte != 0x0b)
        .collect();
    if compact.is_empty() {
        return Err(Error::InvalidCertificate);
    }
    STANDARD
        .decode(compact)
        .map(Cow::Owned)
        .map_err(|_| Error::InvalidCertificate)
}

impl CrlSetIndex {
    /// Decode and validate all identifiers and framing from a complete CRLSet.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed JSON, unsupported formats, deltas, invalid
    /// hashes or header field types, truncated binary entries, or count mismatch.
    fn from_snapshot(snapshot: &CrlSet) -> Result<Self> {
        let prefix: [u8; 2] = take_prefix(&snapshot.bytes, 2)?
            .try_into()
            .map_err(|_| Error::InvalidFormat("invalid CRLSet header length"))?;
        let header_end = 2 + usize::from(u16::from_le_bytes(prefix));
        let mut bytes = snapshot
            .bytes
            .get(2..)
            .ok_or(Error::InvalidFormat("truncated CRLSet header"))?;
        let header: CrlSetHeader = serde_json::from_slice(take_bytes(&mut bytes, header_end - 2)?)?;
        if header.content_type != "CRLSet" || header.version != 0 {
            return Err(Error::InvalidFormat(
                "unsupported CRLSet content type or version",
            ));
        }
        if header_u64(&header.extra, "DeltaFrom")?.is_some_and(|value| value != 0) {
            return Err(Error::InvalidFormat("CRLSet deltas are unsupported"));
        }
        let not_after = header_u64(&header.extra, "NotAfter")?.unwrap_or(0);
        let mut blocked_spkis = header_hashes(&header.extra, "BlockedSPKIs")?;
        blocked_spkis.extend(header_hashes(&header.extra, "BlockedInterceptionSPKIs")?);
        // Known interception keys are informational, not revocation entries.
        let _ = header_hashes(&header.extra, "KnownInterceptionSPKIs")?;
        let limited_subjects = limited_subjects(&header.extra)?;
        let expected_parents = header_u64(&header.extra, "NumParents")?;
        let mut issuer_serials: HashMap<[u8; 32], HashSet<Vec<u8>>> = HashMap::new();
        let mut parent_count = 0_u64;
        while !bytes.is_empty() {
            let issuer_hash: [u8; 32] = take_bytes(&mut bytes, 32)?
                .try_into()
                .map_err(|_| Error::InvalidFormat("invalid CRLSet issuer hash"))?;
            let serial_count = u32::from_le_bytes(
                take_bytes(&mut bytes, 4)?
                    .try_into()
                    .map_err(|_| Error::InvalidFormat("invalid CRLSet serial count"))?,
            );
            // Every serial needs at least its one-byte length; never allocate
            // based on an unchecked attacker-supplied entry count.
            if u64::from(serial_count) > bytes.len() as u64 {
                return Err(Error::InvalidFormat("truncated CRLSet serial entries"));
            }
            let serials = issuer_serials.entry(issuer_hash).or_default();
            for _ in 0..serial_count {
                let length = usize::from(take_bytes(&mut bytes, 1)?[0]);
                serials.insert(take_bytes(&mut bytes, length)?.to_vec());
            }
            parent_count += 1;
        }
        if expected_parents.is_some_and(|expected| expected != parent_count) {
            return Err(Error::InvalidFormat(
                "CRLSet parent count does not match body",
            ));
        }
        Ok(Self {
            blocked_spkis,
            limited_subjects,
            issuer_serials,
            not_after,
        })
    }
}

/// Read a nonnegative integer header field while rejecting a wrong JSON type.
///
/// # Errors
///
/// Returns an error when the named field exists but is not an unsigned integer.
fn header_u64(header: &Map<String, Value>, field: &str) -> Result<Option<u64>> {
    header
        .get(field)
        .map(|value| {
            value
                .as_u64()
                .ok_or(Error::InvalidFormat("invalid CRLSet numeric header field"))
        })
        .transpose()
}

/// Decode an optional header array containing SHA-256 values.
///
/// # Errors
///
/// Returns an error for a wrong JSON type, malformed base64, or non-SHA-256 size.
fn header_hashes(header: &Map<String, Value>, field: &str) -> Result<HashSet<[u8; 32]>> {
    match header.get(field) {
        None | Some(Value::Null) => Ok(HashSet::new()),
        Some(Value::Array(values)) => decode_hash_values(values),
        Some(_) => Err(Error::InvalidFormat("invalid CRLSet hash list")),
    }
}

/// Decode a JSON array containing base64-encoded SHA-256 values.
///
/// # Errors
///
/// Returns an error for a non-string member, malformed base64, or wrong hash size.
fn decode_hash_values(values: &[Value]) -> Result<HashSet<[u8; 32]>> {
    values
        .iter()
        .map(|value| {
            decode_hash(
                value
                    .as_str()
                    .ok_or(Error::InvalidFormat("invalid CRLSet hash value"))?,
            )
        })
        .collect()
}

/// Decode Chrome's map of subject DER hashes to permitted SPKI hashes.
///
/// # Errors
///
/// Returns an error for malformed map/list types, base64, or hash sizes.
fn limited_subjects(header: &Map<String, Value>) -> Result<HashMap<[u8; 32], HashSet<[u8; 32]>>> {
    let Some(value) = header
        .get("LimitedSubjects")
        .filter(|value| !value.is_null())
    else {
        return Ok(HashMap::new());
    };
    let map = value
        .as_object()
        .ok_or(Error::InvalidFormat("invalid CRLSet limited subjects"))?;
    map.iter()
        .map(|(subject, values)| {
            Ok((
                decode_hash(subject)?,
                decode_hash_values(
                    values
                        .as_array()
                        .ok_or(Error::InvalidFormat("invalid CRLSet allowed SPKI list"))?,
                )?,
            ))
        })
        .collect()
}

/// Decode a nonempty base64 revocation identifier.
///
/// # Errors
///
/// Returns an error for malformed base64 or an empty identifier.
fn decode_identifier(value: &str) -> Result<Vec<u8>> {
    let bytes = STANDARD
        .decode(value)
        .map_err(|_| Error::InvalidFormat("invalid base64 revocation identifier"))?;
    if bytes.is_empty() {
        return Err(Error::InvalidFormat("empty revocation identifier"));
    }
    Ok(bytes)
}

/// Decode a base64 SHA-256 digest and require exactly 32 bytes.
///
/// # Errors
///
/// Returns an error for malformed base64 or a digest of a different size.
fn decode_hash(value: &str) -> Result<[u8; 32]> {
    decode_identifier(value)?
        .try_into()
        .map_err(|_| Error::InvalidFormat("revocation hash must contain 32 bytes"))
}

/// Hash complete bytes using SHA-256 without retaining the input.
fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Normalize Chrome serial lookups, excluding negative ASN.1 INTEGER values.
fn chrome_serial(mut serial: &[u8]) -> Option<&[u8]> {
    if serial.first().is_some_and(|first| first & 0x80 != 0) {
        return None;
    }
    while serial.len() > 1 && serial[0] == 0 {
        serial = &serial[1..];
    }
    Some(serial)
}

/// Borrow a bounded prefix while returning a format error for truncated data.
///
/// # Errors
///
/// Returns an error when fewer than `length` bytes remain.
fn take_prefix(bytes: &[u8], length: usize) -> Result<&[u8]> {
    bytes
        .get(..length)
        .ok_or(Error::InvalidFormat("truncated CRLSet payload"))
}

/// Consume a bounded prefix without arithmetic on untrusted offsets.
///
/// # Errors
///
/// Returns an error when fewer than `length` bytes remain.
fn take_bytes<'a>(bytes: &mut &'a [u8], length: usize) -> Result<&'a [u8]> {
    let prefix = take_prefix(bytes, length)?;
    *bytes = &bytes[length..];
    Ok(prefix)
}

#[cfg(test)]
#[path = "../tests/unit/revocation.rs"]
mod tests;
