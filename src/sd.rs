//! "User cannot change password", which Active Directory keeps not as an
//! account flag but in the user's security descriptor: two entries that deny
//! the Change Password right to Everyone and to the user itself (SELF).
//!
//! Written from Microsoft's published formats ([MS-DTYP] 2.4.6
//! SECURITY_DESCRIPTOR, 2.4.5 ACL, 2.4.4.4 ACCESS_DENIED_OBJECT_ACE) and the
//! "Modifying User Cannot Change Password" documentation. Only the DACL is
//! read and written (the SD flags control asks for just that), and every
//! entry other than the four this is about is kept byte for byte.

/// The SD flags control (LDAP_SERVER_SD_FLAGS_OID): read and write only the
/// DACL, which an account may change without the right to change owners or
/// auditing.
pub const SD_FLAGS_OID: &str = "1.2.840.113556.1.4.801";
/// BER for SEQUENCE { INTEGER 4 } — DACL_SECURITY_INFORMATION.
pub const SD_FLAGS_DACL: [u8; 5] = [0x30, 0x03, 0x02, 0x01, 0x04];

const ACCESS_ALLOWED_OBJECT_ACE: u8 = 0x05;
const ACCESS_DENIED_OBJECT_ACE: u8 = 0x06;
const INHERITED_ACE: u8 = 0x10;
const ACE_OBJECT_TYPE_PRESENT: u32 = 0x1;
const ACE_INHERITED_OBJECT_TYPE_PRESENT: u32 = 0x2;
/// ADS_RIGHT_DS_CONTROL_ACCESS: an extended right, named by the GUID.
const CONTROL_ACCESS: u32 = 0x100;
const SE_DACL_PRESENT: u16 = 0x0004;
const SE_SELF_RELATIVE: u16 = 0x8000;
/// ACL_REVISION_DS: needed for object entries.
const ACL_REVISION_DS: u8 = 4;

/// The User-Change-Password extended right,
/// ab721a53-1e2f-11d0-9819-00aa0040529b, as stored (the first three fields
/// little-endian).
const CHANGE_PASSWORD: [u8; 16] = [
    0x53, 0x1a, 0x72, 0xab, 0x2f, 0x1e, 0xd0, 0x11, 0x98, 0x19, 0x00, 0xaa, 0x00, 0x40, 0x52, 0x9b,
];
/// S-1-1-0, Everyone.
const EVERYONE: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
/// S-1-5-10, SELF: the account itself.
const SELF: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 10, 0, 0, 0];

type SdResult<T> = Result<T, String>;

fn u16_at(b: &[u8], at: usize) -> SdResult<u16> {
    b.get(at..at + 2).map(|s| u16::from_le_bytes([s[0], s[1]])).ok_or_else(too_short)
}

fn u32_at(b: &[u8], at: usize) -> SdResult<u32> {
    b.get(at..at + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]])).ok_or_else(too_short)
}

fn too_short() -> String {
    "the security descriptor the DC sent is cut short".to_string()
}

/// One ACE, as found: its bytes, and what this module needs to know about it.
struct Ace {
    bytes: Vec<u8>,
}

impl Ace {
    fn kind(&self) -> u8 {
        self.bytes[0]
    }

    fn inherited(&self) -> bool {
        self.bytes[1] & INHERITED_ACE != 0
    }

    /// For an allow or deny object entry: the right's GUID and the trustee's SID.
    fn object_right(&self) -> Option<(&[u8], &[u8])> {
        if self.kind() != ACCESS_ALLOWED_OBJECT_ACE && self.kind() != ACCESS_DENIED_OBJECT_ACE {
            return None;
        }
        let flags = u32_at(&self.bytes, 8).ok()?;
        if flags & ACE_OBJECT_TYPE_PRESENT == 0 {
            return None;
        }
        let guid = self.bytes.get(12..28)?;
        let sid_at = if flags & ACE_INHERITED_OBJECT_TYPE_PRESENT != 0 { 44 } else { 28 };
        Some((guid, self.bytes.get(sid_at..)?))
    }

    /// An entry about changing the password, for Everyone or SELF.
    fn is_change_password(&self) -> bool {
        self.object_right().is_some_and(|(guid, sid)| {
            guid == CHANGE_PASSWORD && (sid.starts_with(&EVERYONE) || sid.starts_with(&SELF))
        })
    }

    fn denies_change_password(&self) -> bool {
        self.kind() == ACCESS_DENIED_OBJECT_ACE && self.is_change_password()
    }

    /// An explicit entry that allows or denies changing the password: the
    /// ones this module replaces.
    fn ours(&self) -> bool {
        !self.inherited() && self.is_change_password()
    }

    fn new(kind: u8, sid: &[u8; 12]) -> Ace {
        let mut b = Vec::with_capacity(40);
        b.extend([kind, 0]);
        b.extend(40u16.to_le_bytes());
        b.extend(CONTROL_ACCESS.to_le_bytes());
        b.extend(ACE_OBJECT_TYPE_PRESENT.to_le_bytes());
        b.extend(CHANGE_PASSWORD);
        b.extend(sid);
        Ace { bytes: b }
    }
}

/// A self-relative security descriptor, split into its parts.
pub struct Descriptor {
    control: u16,
    owner: Option<Vec<u8>>,
    group: Option<Vec<u8>>,
    sacl: Option<Vec<u8>>,
    acl_revision: u8,
    dacl: Vec<Ace>,
}

/// The SID at `at` in `b`: 8 bytes of header and 4 per sub-authority.
fn sid_at(b: &[u8], at: usize) -> SdResult<Vec<u8>> {
    let count = usize::from(*b.get(at + 1).ok_or_else(too_short)?);
    b.get(at..at + 8 + 4 * count).map(<[u8]>::to_vec).ok_or_else(too_short)
}

fn acl_at(b: &[u8], at: usize) -> SdResult<&[u8]> {
    let size = usize::from(u16_at(b, at + 2)?);
    b.get(at..at + size).ok_or_else(too_short)
}

impl Descriptor {
    pub fn parse(b: &[u8]) -> SdResult<Descriptor> {
        if b.len() < 20 || b[0] != 1 {
            return Err("the DC sent a security descriptor in a form EasyDC does not know".to_string());
        }
        let control = u16_at(b, 2)?;
        if control & SE_SELF_RELATIVE == 0 {
            return Err("the DC sent a security descriptor in a form EasyDC does not know".to_string());
        }
        let offset = |i: usize| u32_at(b, 4 + 4 * i).map(|o| o as usize);
        let (owner, group, sacl, dacl) = (offset(0)?, offset(1)?, offset(2)?, offset(3)?);
        if dacl == 0 || control & SE_DACL_PRESENT == 0 {
            return Err("the user has no access list to change".to_string());
        }
        let acl = acl_at(b, dacl)?;
        let count = usize::from(u16_at(acl, 4)?);
        let mut aces = Vec::with_capacity(count);
        let mut at = 8;
        for _ in 0..count {
            let size = usize::from(u16_at(acl, at + 2)?);
            if size < 8 {
                return Err("the DC sent an access list EasyDC cannot read".to_string());
            }
            aces.push(Ace { bytes: acl.get(at..at + size).ok_or_else(too_short)?.to_vec() });
            at += size;
        }
        Ok(Descriptor {
            control,
            owner: if owner == 0 { None } else { Some(sid_at(b, owner)?) },
            group: if group == 0 { None } else { Some(sid_at(b, group)?) },
            sacl: if sacl == 0 { None } else { Some(acl_at(b, sacl)?.to_vec()) },
            acl_revision: acl[0],
            dacl: aces,
        })
    }

    /// Whether changing the password is denied to the user, by any entry.
    pub fn cannot_change_password(&self) -> bool {
        self.dacl.iter().any(Ace::denies_change_password)
    }

    /// Deny changing the password to Everyone and SELF, or allow it again as
    /// a new user's defaults do. The explicit entries about it are replaced;
    /// a deny goes first and an allow after the other explicit entries, the
    /// order Windows keeps an access list in.
    pub fn set_cannot_change_password(&mut self, cannot: bool) {
        self.dacl.retain(|a| !a.ours());
        if cannot {
            self.dacl.insert(0, Ace::new(ACCESS_DENIED_OBJECT_ACE, &SELF));
            self.dacl.insert(0, Ace::new(ACCESS_DENIED_OBJECT_ACE, &EVERYONE));
        } else {
            let at = self.dacl.iter().position(Ace::inherited).unwrap_or(self.dacl.len());
            self.dacl.insert(at, Ace::new(ACCESS_ALLOWED_OBJECT_ACE, &SELF));
            self.dacl.insert(at, Ace::new(ACCESS_ALLOWED_OBJECT_ACE, &EVERYONE));
        }
        self.acl_revision = self.acl_revision.max(ACL_REVISION_DS);
    }

    /// Back to the self-relative form, for writing with the SD flags control.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut acl = vec![self.acl_revision, 0, 0, 0];
        acl.extend((self.dacl.len() as u16).to_le_bytes());
        acl.extend([0, 0]);
        for ace in &self.dacl {
            acl.extend(&ace.bytes);
        }
        let size = (acl.len() as u16).to_le_bytes();
        acl[2..4].copy_from_slice(&size);

        let mut out = vec![1, 0];
        out.extend(self.control.to_le_bytes());
        out.extend([0u8; 16]);
        let place = |out: &mut Vec<u8>, slot: usize, part: Option<&[u8]>| {
            if let Some(part) = part {
                let at = out.len() as u32;
                out[4 + 4 * slot..8 + 4 * slot].copy_from_slice(&at.to_le_bytes());
                out.extend(part);
            }
        };
        place(&mut out, 2, self.sacl.as_deref());
        place(&mut out, 3, Some(&acl));
        place(&mut out, 0, self.owner.as_deref());
        place(&mut out, 1, self.group.as_deref());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An explicit generic ACE (ACCESS_ALLOWED, mask GenericRead) for `sid`.
    fn plain(sid: &[u8], flags: u8) -> Vec<u8> {
        let size = (8 + sid.len()) as u16;
        let mut b = vec![0x00, flags];
        b.extend(size.to_le_bytes());
        b.extend(0x8000_0000u32.to_le_bytes());
        b.extend(sid);
        b
    }

    /// Domain Admins in some domain, to stand for any other trustee.
    fn admins() -> Vec<u8> {
        let mut s = vec![1, 5, 0, 0, 0, 0, 0, 5];
        for sub in [21u32, 1, 2, 3, 512] {
            s.extend(sub.to_le_bytes());
        }
        s
    }

    /// A descriptor as the DC sends it with the SD flags control: a DACL only.
    fn descriptor(aces: &[Vec<u8>]) -> Vec<u8> {
        let mut acl = vec![ACL_REVISION_DS, 0, 0, 0];
        acl.extend((aces.len() as u16).to_le_bytes());
        acl.extend([0, 0]);
        for a in aces {
            acl.extend(a);
        }
        let size = (acl.len() as u16).to_le_bytes();
        acl[2..4].copy_from_slice(&size);
        let mut b = vec![1, 0];
        b.extend((SE_SELF_RELATIVE | SE_DACL_PRESENT).to_le_bytes());
        b.extend([0u8; 12]);
        b.extend(20u32.to_le_bytes());
        b.extend(acl);
        b
    }

    fn kinds(d: &Descriptor) -> Vec<(u8, bool)> {
        d.dacl.iter().map(|a| (a.kind(), a.is_change_password())).collect()
    }

    #[test]
    fn the_change_password_right_is_written_as_microsoft_documents_it() {
        // ab721a53-1e2f-11d0-9819-00aa0040529b
        assert_eq!(&CHANGE_PASSWORD[..4], &0xab721a53u32.to_le_bytes());
        assert_eq!(&CHANGE_PASSWORD[4..6], &0x1e2fu16.to_le_bytes());
        assert_eq!(&CHANGE_PASSWORD[6..8], &0x11d0u16.to_le_bytes());
        assert_eq!(CHANGE_PASSWORD[8..], [0x98, 0x19, 0x00, 0xaa, 0x00, 0x40, 0x52, 0x9b]);
        assert_eq!(Ace::new(ACCESS_DENIED_OBJECT_ACE, &SELF).bytes.len(), 40);
    }

    #[test]
    fn a_new_user_may_change_the_password() {
        // As a new user's defaults have it: allowed to Everyone and SELF.
        let raw = descriptor(&[
            plain(&admins(), 0),
            Ace::new(ACCESS_ALLOWED_OBJECT_ACE, &EVERYONE).bytes,
            Ace::new(ACCESS_ALLOWED_OBJECT_ACE, &SELF).bytes,
            plain(&admins(), INHERITED_ACE),
        ]);
        let d = Descriptor::parse(&raw).unwrap();
        assert!(!d.cannot_change_password());
        assert_eq!(d.to_bytes(), raw, "read and written back unchanged");
    }

    #[test]
    fn denying_puts_two_entries_first_and_keeps_the_rest() {
        let raw = descriptor(&[
            plain(&admins(), 0),
            Ace::new(ACCESS_ALLOWED_OBJECT_ACE, &EVERYONE).bytes,
            Ace::new(ACCESS_ALLOWED_OBJECT_ACE, &SELF).bytes,
            plain(&admins(), INHERITED_ACE),
        ]);
        let mut d = Descriptor::parse(&raw).unwrap();
        d.set_cannot_change_password(true);
        assert!(d.cannot_change_password());
        assert_eq!(
            kinds(&d),
            [(ACCESS_DENIED_OBJECT_ACE, true), (ACCESS_DENIED_OBJECT_ACE, true), (0, false), (0, false)]
        );
        let again = Descriptor::parse(&d.to_bytes()).unwrap();
        assert!(again.cannot_change_password());
        assert_eq!(again.dacl.len(), 4);
        assert!(again.dacl[3].inherited(), "the inherited entry stays last");

        // And allowing again restores the defaults, before inherited entries.
        let mut d = again;
        d.set_cannot_change_password(false);
        assert!(!d.cannot_change_password());
        assert_eq!(d.to_bytes(), raw);
    }

    #[test]
    fn setting_twice_does_not_add_entries_twice() {
        let mut d = Descriptor::parse(&descriptor(&[plain(&admins(), 0)])).unwrap();
        d.set_cannot_change_password(true);
        d.set_cannot_change_password(true);
        assert_eq!(d.dacl.len(), 3);
        d.set_cannot_change_password(false);
        d.set_cannot_change_password(false);
        assert_eq!(d.dacl.len(), 3);
        assert!(!d.cannot_change_password());
    }

    /// A deny another tool wrote for SELF alone still means the user cannot
    /// change it; an inherited deny is not removed, since it is not the user's own.
    #[test]
    fn any_deny_counts_and_inherited_ones_stay() {
        let mut inherited = Ace::new(ACCESS_DENIED_OBJECT_ACE, &SELF).bytes;
        inherited[1] = INHERITED_ACE;
        let mut d = Descriptor::parse(&descriptor(&[inherited])).unwrap();
        assert!(d.cannot_change_password());
        d.set_cannot_change_password(false);
        assert!(d.cannot_change_password(), "an inherited deny is set on the OU, not the user");
        assert_eq!(d.dacl.len(), 3);
    }

    #[test]
    fn owner_group_and_sacl_are_kept() {
        let mut raw = descriptor(&[plain(&admins(), 0)]);
        let owner_at = raw.len() as u32;
        raw.extend(admins());
        raw[4..8].copy_from_slice(&owner_at.to_le_bytes());
        let d = Descriptor::parse(&raw).unwrap();
        let back = Descriptor::parse(&d.to_bytes()).unwrap();
        assert_eq!(back.owner, Some(admins()));
        assert_eq!(back.dacl.len(), 1);
    }

    #[test]
    fn a_broken_descriptor_is_refused_not_guessed_at() {
        assert!(Descriptor::parse(&[]).is_err());
        let raw = descriptor(&[plain(&admins(), 0)]);
        assert!(Descriptor::parse(&raw[..raw.len() - 3]).is_err());
        let mut no_dacl = raw.clone();
        no_dacl[16..20].copy_from_slice(&0u32.to_le_bytes());
        assert!(Descriptor::parse(&no_dacl).is_err());
    }
}
