//! Access lists on directory objects. First for "User cannot change
//! password", which Active Directory keeps not as an
//! account flag but in the user's security descriptor: two entries that deny
//! the Change Password right to Everyone and to the user itself (SELF).
//!
//! Written from Microsoft's published formats ([MS-DTYP] 2.4.6
//! SECURITY_DESCRIPTOR, 2.4.5 ACL, 2.4.4.4 ACCESS_DENIED_OBJECT_ACE) and the
//! "Modifying User Cannot Change Password" documentation. Only the DACL is
//! read and written (the SD flags control asks for just that), and every
//! entry other than the ones being changed is kept byte for byte. Also read
//! and written by the delegation page (`delegation.rs`).

/// The SD flags control (LDAP_SERVER_SD_FLAGS_OID): read and write only the
/// DACL, which an account may change without the right to change owners or
/// auditing.
pub const SD_FLAGS_OID: &str = "1.2.840.113556.1.4.801";
/// BER for SEQUENCE { INTEGER 4 } — DACL_SECURITY_INFORMATION.
pub const SD_FLAGS_DACL: [u8; 5] = [0x30, 0x03, 0x02, 0x01, 0x04];
/// BER for SEQUENCE { INTEGER 7 } — owner, group and DACL.
pub const SD_FLAGS_OWNER_GROUP_DACL: [u8; 5] = [0x30, 0x03, 0x02, 0x01, 0x07];

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
/// S-1-3-0, CREATOR OWNER.
const CREATOR_OWNER: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0];
/// S-1-5-32-554, Pre-Windows 2000 Compatible Access.
const PRE_WINDOWS_2000: [u8; 16] = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x2a, 2, 0, 0];
const OBJECT_INHERIT: u8 = 0x01;
/// ACL_REVISION: an access list with no object entries.
const ACL_REVISION: u8 = 2;
/// The SACL's bits in the control word: a file's descriptor has no SACL.
const SE_SACL_BITS: u16 = 0x0010 | 0x0020 | 0x0200 | 0x0800 | 0x2000;
/// "The owner / group was set by default": not true of what is written here.
const SE_DEFAULTED_BITS: u16 = 0x0001 | 0x0002;

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

    /// The entry, for an allow or deny one (plain or object); None for the
    /// kinds this does not read (callback and audit entries).
    fn entry(&self) -> Option<Entry> {
        let b = &self.bytes;
        let deny = match self.kind() {
            0x00 | ACCESS_ALLOWED_OBJECT_ACE => false,
            0x01 | ACCESS_DENIED_OBJECT_ACE => true,
            _ => return None,
        };
        let mask = u32_at(b, 4).ok()?;
        let guid = |at: usize| b.get(at..at + 16).and_then(|g| <[u8; 16]>::try_from(g).ok());
        let (object, applies_to, sid_at) = if self.kind() == 0x00 || self.kind() == 0x01 {
            (None, None, 8)
        } else {
            let present = u32_at(b, 8).ok()?;
            let mut at = 12;
            let mut take = |flag: u32| {
                if present & flag == 0 {
                    return Some(None);
                }
                let g = guid(at)?;
                at += 16;
                Some(Some(g))
            };
            let object = take(ACE_OBJECT_TYPE_PRESENT)?;
            let applies_to = take(ACE_INHERITED_OBJECT_TYPE_PRESENT)?;
            (object, applies_to, at)
        };
        Some(Entry {
            deny,
            flags: b[1] & !INHERITED_ACE,
            inherited: self.inherited(),
            mask,
            object,
            applies_to,
            sid: sid_at_or_none(b, sid_at)?,
        })
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

/// An access entry, read: what the delegation page shows and compares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub deny: bool,
    /// The inheritance flags (container inherit, inherit only, …) without
    /// INHERITED, which `inherited` says.
    pub flags: u8,
    pub inherited: bool,
    pub mask: u32,
    /// The right, class or attribute it is about, as stored.
    pub object: Option<[u8; 16]>,
    /// The class of the objects below that it applies to, as stored.
    pub applies_to: Option<[u8; 16]>,
    pub sid: Vec<u8>,
}

pub const CONTAINER_INHERIT: u8 = 0x02;
pub const INHERIT_ONLY: u8 = 0x08;

impl Entry {
    /// An allow entry, set here (not inherited).
    pub fn allow(mask: u32, flags: u8, object: Option<[u8; 16]>, applies_to: Option<[u8; 16]>, sid: &[u8]) -> Entry {
        Entry { deny: false, flags, inherited: false, mask, object, applies_to, sid: sid.to_vec() }
    }

    /// The same grant, wherever it was set.
    pub fn same_grant(&self, other: &Entry) -> bool {
        self.deny == other.deny
            && self.flags == other.flags
            && self.mask == other.mask
            && self.object == other.object
            && self.applies_to == other.applies_to
            && self.sid == other.sid
    }

    fn to_ace(&self) -> Ace {
        let object = self.object.is_some() || self.applies_to.is_some();
        let kind = match (object, self.deny) {
            (false, false) => 0x00,
            (false, true) => 0x01,
            (true, false) => ACCESS_ALLOWED_OBJECT_ACE,
            (true, true) => ACCESS_DENIED_OBJECT_ACE,
        };
        let mut b = vec![kind, self.flags | if self.inherited { INHERITED_ACE } else { 0 }, 0, 0];
        b.extend(self.mask.to_le_bytes());
        if object {
            let mut present = 0u32;
            if self.object.is_some() {
                present |= ACE_OBJECT_TYPE_PRESENT;
            }
            if self.applies_to.is_some() {
                present |= ACE_INHERITED_OBJECT_TYPE_PRESENT;
            }
            b.extend(present.to_le_bytes());
            for g in [self.object, self.applies_to].into_iter().flatten() {
                b.extend(g);
            }
        }
        b.extend(&self.sid);
        let size = (b.len() as u16).to_le_bytes();
        b[2..4].copy_from_slice(&size);
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

fn sid_at_or_none(b: &[u8], at: usize) -> Option<Vec<u8>> {
    sid_at(b, at).ok()
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

    /// The allow and deny entries, in order.
    pub fn entries(&self) -> Vec<Entry> {
        self.dacl.iter().filter_map(Ace::entry).collect()
    }

    /// Add an allow entry set here, after the other entries set here and
    /// before the inherited ones, unless it is there already. Returns whether
    /// it was added.
    pub fn add(&mut self, e: &Entry) -> bool {
        if self.dacl.iter().filter_map(Ace::entry).any(|x| !x.inherited && x.same_grant(e)) {
            return false;
        }
        let at = self.dacl.iter().position(Ace::inherited).unwrap_or(self.dacl.len());
        self.dacl.insert(at, e.to_ace());
        self.acl_revision = self.acl_revision.max(ACL_REVISION_DS);
        true
    }

    /// Take out the entries set here that `drop` picks. Returns how many went.
    pub fn remove(&mut self, drop: impl Fn(&Entry) -> bool) -> usize {
        let before = self.dacl.len();
        self.dacl.retain(|a| a.inherited() || !a.entry().is_some_and(|e| drop(&e)));
        before - self.dacl.len()
    }

    /// The same permissions for a GPO's folder in SYSVOL, so that the folder
    /// and the directory object agree. Each directory right is mapped to the
    /// file rights it stands for, and every entry is inherited by what the
    /// folder holds.
    pub fn for_gpo_folder(&self) -> Descriptor {
        let dacl = self
            .dacl
            .iter()
            .filter(|a| a.kind() <= 1 && !a.bytes[8..].starts_with(&PRE_WINDOWS_2000))
            .filter_map(|a| {
                let mut bytes = a.bytes.clone();
                bytes[1] |= OBJECT_INHERIT | CONTAINER_INHERIT;
                if bytes[8..] == CREATOR_OWNER {
                    bytes[1] |= INHERIT_ONLY;
                }
                let mask = directory_rights_to_file_rights(u32_at(&a.bytes, 4).ok()?);
                bytes[4..8].copy_from_slice(&mask.to_le_bytes());
                Some(Ace { bytes })
            })
            .collect();
        Descriptor {
            control: self.control & !(SE_SACL_BITS | SE_DEFAULTED_BITS),
            owner: self.owner.clone(),
            group: self.group.clone(),
            sacl: None,
            acl_revision: ACL_REVISION,
            dacl,
        }
    }

    /// The same owner, group and entries, in any order.
    pub fn same_access(&self, other: &Descriptor) -> bool {
        let sorted = |d: &Descriptor| {
            let mut v: Vec<_> = d.dacl.iter().map(|a| a.bytes.clone()).collect();
            v.sort();
            v
        };
        self.owner == other.owner && self.group == other.group && sorted(self) == sorted(other)
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

/// What a right on a directory object means on a file or folder.
fn directory_rights_to_file_rights(ds: u32) -> u32 {
    const DS_CREATE_CHILD: u32 = 0x01;
    const DS_DELETE_CHILD: u32 = 0x02;
    const DS_LIST_CONTENTS: u32 = 0x04;
    const DS_READ_PROPERTY: u32 = 0x10;
    const DS_WRITE_PROPERTY: u32 = 0x20;
    const STANDARD_RIGHTS: u32 = 0x001f_0000;
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const LIST_OR_READ: u32 = 0x0001;
    const ADD_FILE_OR_WRITE: u32 = 0x0002;
    const ADD_FOLDER_OR_APPEND: u32 = 0x0004;
    const READ_EA: u32 = 0x0008;
    const WRITE_EA: u32 = 0x0010;
    const TRAVERSE_OR_EXECUTE: u32 = 0x0020;
    const DELETE_CHILD: u32 = 0x0040;
    const READ_ATTRIBUTES: u32 = 0x0080;
    const WRITE_ATTRIBUTES: u32 = 0x0100;

    let mut file = ds & STANDARD_RIGHTS;
    if ds & DS_READ_PROPERTY != 0 && ds & DS_LIST_CONTENTS != 0 {
        file |= SYNCHRONIZE | LIST_OR_READ | READ_ATTRIBUTES | READ_EA | TRAVERSE_OR_EXECUTE;
    }
    if ds & DS_WRITE_PROPERTY != 0 {
        file |= SYNCHRONIZE | ADD_FILE_OR_WRITE | ADD_FOLDER_OR_APPEND | WRITE_EA | WRITE_ATTRIBUTES;
    }
    if ds & DS_CREATE_CHILD != 0 {
        file |= ADD_FILE_OR_WRITE | ADD_FOLDER_OR_APPEND;
    }
    if ds & DS_DELETE_CHILD != 0 {
        file |= DELETE_CHILD;
    }
    file
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

    #[test]
    fn a_gpo_folder_gets_the_file_rights_of_the_object() {
        let ace = |kind: u8, flags: u8, mask: u32, sid: &[u8]| {
            let mut b = vec![kind, flags];
            b.extend(((8 + sid.len()) as u16).to_le_bytes());
            b.extend(mask.to_le_bytes());
            b.extend(sid);
            b
        };
        let mut object_ace = vec![ACCESS_ALLOWED_OBJECT_ACE, 0x02];
        object_ace.extend(40u16.to_le_bytes());
        object_ace.extend(CONTROL_ACCESS.to_le_bytes());
        object_ace.extend(ACE_OBJECT_TYPE_PRESENT.to_le_bytes());
        object_ace.extend([7u8; 16]);
        object_ace.extend(EVERYONE);
        let raw = descriptor(&[
            ace(0x00, 0x00, 0x000f_01ff, &admins()),
            ace(0x00, 0x02, 0x0002_0094, &[1, 1, 0, 0, 0, 0, 0, 5, 11, 0, 0, 0]),
            ace(0x00, 0x00, 0x0002_0094, &CREATOR_OWNER),
            ace(0x00, 0x00, 0x0002_0094, &PRE_WINDOWS_2000),
            ace(0x01, 0x00, 0x0000_0020, &SELF),
            object_ace,
        ]);
        let folder = Descriptor::parse(&raw).unwrap().for_gpo_folder();
        let e = folder.entries();
        assert_eq!(e.len(), 4, "no object entries, and no Pre-Windows 2000 entry");
        assert_eq!((e[0].flags, e[0].mask), (0x03, 0x001f_01ff), "full control");
        assert_eq!((e[1].flags, e[1].mask), (0x03, 0x0012_00a9), "read and list");
        assert_eq!(e[2].flags, 0x0b, "CREATOR OWNER applies only to what is inside");
        assert!(e[3].deny);
        assert_eq!(e[3].mask, 0x0010_0116, "write");
        assert_eq!(folder.acl_revision, ACL_REVISION);
        assert!(folder.same_access(&Descriptor::parse(&folder.to_bytes()).unwrap()));
    }

    #[test]
    fn rights_map_only_when_they_mean_the_same() {
        assert_eq!(directory_rights_to_file_rights(0x10), 0, "reading needs listing too");
        assert_eq!(directory_rights_to_file_rights(0x04), 0);
        assert_eq!(directory_rights_to_file_rights(0x100), 0, "an extended right is not a file right");
        assert_eq!(directory_rights_to_file_rights(0x01), 0x06);
        assert_eq!(directory_rights_to_file_rights(0x02), 0x40);
        assert_eq!(directory_rights_to_file_rights(0x000f_0000), 0x000f_0000);
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
    fn entries_read_back_as_written() {
        let user = [7u8; 16];
        let right = [9u8; 16];
        let full = Entry::allow(0xF01FF, CONTAINER_INHERIT | INHERIT_ONLY, None, Some(user), &admins());
        let reset = Entry::allow(0x100, CONTAINER_INHERIT | INHERIT_ONLY, Some(right), Some(user), &admins());
        let plain_one = Entry::allow(0x20094, 0, None, None, &admins());
        let mut inherited = plain(&admins(), INHERITED_ACE);
        inherited[4..8].copy_from_slice(&0x10u32.to_le_bytes());
        let mut d = Descriptor::parse(&descriptor(&[inherited])).unwrap();
        assert!(d.add(&full) && d.add(&reset) && d.add(&plain_one));
        assert!(!d.add(&full), "not added twice");
        let d = Descriptor::parse(&d.to_bytes()).unwrap();
        let e = d.entries();
        assert_eq!(e.len(), 4);
        assert_eq!(e[0], full);
        assert_eq!(e[1], reset);
        assert_eq!(e[2], plain_one);
        assert!(e[3].inherited && e[3].mask == 0x10, "new entries go before inherited ones");
        assert_eq!(full.to_ace().bytes.len(), 4 + 4 + 4 + 16 + admins().len());
    }

    #[test]
    fn only_entries_set_here_are_removed() {
        let mut inherited = plain(&admins(), INHERITED_ACE);
        inherited[4..8].copy_from_slice(&0x10u32.to_le_bytes());
        let mut d = Descriptor::parse(&descriptor(&[plain(&admins(), 0), inherited])).unwrap();
        assert_eq!(d.remove(|e| e.sid == admins()), 1);
        let e = d.entries();
        assert_eq!(e.len(), 1);
        assert!(e[0].inherited);
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
