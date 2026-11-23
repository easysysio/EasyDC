//! A GPO's folder in SYSVOL, written over SMB.
//!
//! A GPO is two things: an object in the directory and a folder,
//! `\\<dc>\sysvol\<realm>\Policies\{GUID}`, holding `GPT.INI` and the `Machine`
//! and `User` folders. Clients read both, so a GPO with no folder fails when
//! it is applied. The folder's permissions must match the object's, or GPMC
//! reports the GPO as inconsistent.
//!
//! Samba does not replicate SYSVOL. The folder goes on the PDC emulator, which
//! is where GPMC edits GPOs by default, and reaching the other DCs is left to
//! whatever already syncs SYSVOL there.

use smb2::{
    msg::{
        create::{CreateDisposition, CreateRequest, CreateResponse, ImpersonationLevel, ShareAccess},
        query_info::{InfoType, QueryInfoRequest, QueryInfoResponse},
        set_info::SetInfoRequest,
    },
    pack::{ReadCursor, Unpack},
    types::{flags::FileAccessMask, status::NtStatus, Command, FileId, OplockLevel},
    ClientConfig, SmbClient, Tree,
};

use crate::{
    fsmo::{self, Role},
    ldap::{self, ldap_err, LdapResult},
    models::Server,
    sd::Descriptor,
};

const GPT_INI: &[u8] = b"[General]\r\nVersion=0\r\n";
const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
const READ_CONTROL: u32 = 0x0002_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;
/// Owner, group and DACL.
const OWNER_GROUP_DACL: u32 = 0x07;
/// The DACL stands alone, and takes nothing from the Policies folder.
const PROTECTED_DACL: u32 = 0x8000_0000;
const DEFAULT_GPOS: [&str; 2] = ["31B2F340-016D-11D2-945F-00C04FB984F9", "6AC1786C-016F-11D2-945F-00C04FB984F9"];

/// `XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX`. A GUID names the folder that a
/// delete removes, so nothing else may pass.
pub fn is_guid(guid: &str) -> bool {
    let b = guid.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_hexdigit(),
        })
}

fn is_default_gpo(guid: &str) -> bool {
    DEFAULT_GPOS.iter().any(|d| d.eq_ignore_ascii_case(guid))
}

fn gpo_folder(realm: &str, guid: &str) -> String {
    format!("{realm}/Policies/{{{guid}}}")
}

/// `u:LAB\Administrator`, as the DC names the account EasyDC binds with.
fn parse_whoami(authzid: &str) -> Option<(String, String)> {
    let (domain, user) = authzid.strip_prefix("u:")?.split_once('\\')?;
    (!domain.is_empty() && !user.is_empty()).then(|| (domain.to_string(), user.to_string()))
}

async fn who_am_i(conn: &mut ldap3::Ldap) -> LdapResult<(String, String)> {
    use ldap3::exop::{WhoAmI, WhoAmIResp};
    let (exop, _) = conn
        .with_timeout(ldap::OP_TIMEOUT)
        .extended(WhoAmI)
        .await
        .map_err(ldap_err)?
        .success()
        .map_err(ldap_err)?;
    let who: WhoAmIResp = exop.parse();
    parse_whoami(&who.authzid).ok_or_else(|| "The DC did not say which account EasyDC signs in with.".to_string())
}

struct Share {
    client: SmbClient,
    tree: Tree,
}

impl Share {
    async fn connect(server: &Server, host: &str, domain: &str, user: &str) -> LdapResult<Share> {
        let config = ClientConfig {
            addr: format!("{host}:445"),
            timeout: std::time::Duration::from_secs(10),
            username: user.to_string(),
            password: server.bind_password.clone(),
            domain: domain.to_string(),
            auto_reconnect: false,
            compression: false,
            dfs_enabled: false,
            ..Default::default()
        };
        let mut client = SmbClient::connect(config)
            .await
            .map_err(|e| format!("EasyDC could not sign in to {host} over SMB (TCP port 445): {e}"))?;
        let tree = client
            .connect_share("sysvol")
            .await
            .map_err(|e| format!("EasyDC could not open the sysvol share on {host}: {e}"))?;
        Ok(Share { client, tree })
    }

    async fn open_folder(&mut self, path: &str, access: u32) -> LdapResult<FileId> {
        self.open_with(path, access, FILE_DIRECTORY_FILE).await
    }

    /// `create_options` 0 opens a file or a folder.
    async fn open_with(&mut self, path: &str, access: u32, create_options: u32) -> LdapResult<FileId> {
        let req = CreateRequest {
            requested_oplock_level: OplockLevel::None,
            impersonation_level: ImpersonationLevel::Impersonation,
            desired_access: FileAccessMask::new(access),
            file_attributes: 0,
            share_access: ShareAccess(ShareAccess::FILE_SHARE_READ | ShareAccess::FILE_SHARE_WRITE | ShareAccess::FILE_SHARE_DELETE),
            create_disposition: CreateDisposition::FileOpen,
            create_options,
            // As the library's own calls send it: `/` is the separator.
            name: smb2::encode_path(path),
            create_contexts: vec![],
        };
        let tree_id = self.tree.tree_id;
        let frame = self.client.connection_mut().execute(Command::Create, &req, Some(tree_id)).await.map_err(|e| e.to_string())?;
        if frame.header.status != NtStatus::SUCCESS {
            return Err(format!("Could not open {path}: {:?}", frame.header.status));
        }
        let mut cursor = ReadCursor::new(&frame.body);
        Ok(CreateResponse::unpack(&mut cursor).map_err(|e| e.to_string())?.file_id)
    }

    async fn is_folder(&mut self, path: &str) -> bool {
        match self.open_folder(path, READ_CONTROL).await {
            Ok(id) => {
                let _ = self.tree.close_handle(self.client.connection_mut(), id).await;
                true
            }
            Err(_) => false,
        }
    }

    async fn read_descriptor(&mut self, path: &str) -> LdapResult<Descriptor> {
        let file_id = self.open_with(path, READ_CONTROL, 0).await?;
        let req = QueryInfoRequest {
            info_type: InfoType::Security,
            file_info_class: 0,
            output_buffer_length: 65_536,
            additional_information: OWNER_GROUP_DACL,
            flags: 0,
            file_id,
            input_buffer: vec![],
        };
        let tree_id = self.tree.tree_id;
        let frame = self.client.connection_mut().execute(Command::QueryInfo, &req, Some(tree_id)).await.map_err(|e| e.to_string());
        let _ = self.tree.close_handle(self.client.connection_mut(), file_id).await;
        let frame = frame?;
        if frame.header.status != NtStatus::SUCCESS {
            return Err(format!("Could not read the permissions of {path}: {:?}", frame.header.status));
        }
        let mut cursor = ReadCursor::new(&frame.body);
        Descriptor::parse(&QueryInfoResponse::unpack(&mut cursor).map_err(|e| e.to_string())?.output_buffer)
    }

    async fn set_descriptor(&mut self, path: &str, descriptor: &Descriptor) -> LdapResult<()> {
        let file_id = self.open_with(path, READ_CONTROL | WRITE_DAC | WRITE_OWNER, 0).await?;
        let req = SetInfoRequest {
            info_type: InfoType::Security,
            file_info_class: 0,
            additional_information: OWNER_GROUP_DACL | PROTECTED_DACL,
            file_id,
            buffer: descriptor.to_bytes(),
        };
        let tree_id = self.tree.tree_id;
        let frame = self.client.connection_mut().execute(Command::SetInfo, &req, Some(tree_id)).await.map_err(|e| e.to_string());
        let _ = self.tree.close_handle(self.client.connection_mut(), file_id).await;
        let status = frame?.header.status;
        if status != NtStatus::SUCCESS {
            return Err(format!("Could not set the permissions of {path}: {status:?}"));
        }
        Ok(())
    }

    /// Delete a folder and all it holds. A link is removed, never followed.
    async fn remove_tree(&mut self, path: &str) -> LdapResult<()> {
        let mut pending = vec![(path.to_string(), false)];
        while let Some((dir, emptied)) = pending.pop() {
            if emptied {
                self.client.delete_directory(&self.tree, &dir).await.map_err(|e| format!("{dir}: {e}"))?;
                continue;
            }
            pending.push((dir.clone(), true));
            let entries = self.client.list_directory(&mut self.tree, &dir).await.map_err(|e| format!("{dir}: {e}"))?;
            for e in entries {
                if e.name == "." || e.name == ".." {
                    continue;
                }
                if e.name.contains(['\\', '/']) {
                    return Err(format!("{dir} holds a name EasyDC will not touch: {}", e.name));
                }
                let child = format!("{dir}/{}", e.name);
                if e.is_link() {
                    self.client.delete_link(&self.tree, &child).await.map_err(|err| format!("{child}: {err}"))?;
                } else if e.is_directory {
                    pending.push((child, false));
                } else {
                    self.client.delete_file(&self.tree, &child).await.map_err(|err| format!("{child}: {err}"))?;
                }
            }
        }
        Ok(())
    }

    async fn close(mut self) {
        let _ = self.tree.disconnect(self.client.connection_mut()).await;
    }
}

/// The PDC emulator, over LDAP and SMB.
struct OnPdc {
    ldap: ldap3::Ldap,
    share: Share,
    dc: String,
    realm: String,
}

async fn open_pdc(server: &Server, conn: &mut ldap3::Ldap, base_dn: &str) -> LdapResult<OnPdc> {
    let (o, infos, _) = fsmo::overview(conn, base_dn).await?;
    let holder = o.roles.iter().find(|h| h.role == Role::Pdc).ok_or("EasyDC could not find the PDC emulator.")?;
    if holder.missing || holder.dc.is_empty() || holder.gone {
        return Err("The GPO's folder goes on the PDC emulator, and no running DC holds that role. Take the role on a DC first.".to_string());
    }
    let dc = infos
        .iter()
        .find(|d| d.name.eq_ignore_ascii_case(&holder.dc))
        .ok_or_else(|| format!("{} is not in the list of DCs.", holder.dc))?;
    let mut ldap = fsmo::connect_to(server, dc).await?;
    let (domain, user) = who_am_i(&mut ldap).await?;
    let mut share = Share::connect(server, &dc.dns_host_name, &domain, &user).await?;
    let realm = ldap::base_dn_to_domain(base_dn).to_lowercase();
    if !share.is_folder(&format!("{realm}/Policies")).await {
        return Err(format!("{} has no {realm}/Policies folder in its sysvol share.", dc.name));
    }
    Ok(OnPdc { ldap, share, dc: dc.name.clone(), realm })
}

async fn fill_folder(t: &mut OnPdc, gpo_dn: &str, folder: &str) -> LdapResult<()> {
    let wanted = ldap::gpo_descriptor(&mut t.ldap, gpo_dn).await?.for_gpo_folder();
    t.share.set_descriptor(folder, &wanted).await?;
    for sub in ["Machine", "User"] {
        let path = format!("{folder}/{sub}");
        t.share.client.create_directory(&t.share.tree, &path).await.map_err(|e| format!("{path}: {e}"))?;
    }
    let ini = format!("{folder}/GPT.INI");
    t.share.client.write_file(&t.share.tree, &ini, GPT_INI).await.map_err(|e| format!("{ini}: {e}"))?;
    // `samba-tool ntacl sysvolcheck` wants the same entries on everything inside.
    for path in [format!("{folder}/Machine"), format!("{folder}/User"), ini] {
        t.share.set_descriptor(&path, &wanted).await?;
    }
    for path in [folder.to_string(), format!("{folder}/Machine"), format!("{folder}/User"), format!("{folder}/GPT.INI")] {
        if !t.share.read_descriptor(&path).await?.same_access(&wanted) {
            return Err(format!("{} did not keep the permissions set on {path}.", t.dc));
        }
    }
    Ok(())
}

/// Create a complete GPO, or nothing: what a failed attempt made is removed.
pub async fn create_gpo(server: &Server, conn: &mut ldap3::Ldap, base_dn: &str, display_name: &str) -> LdapResult<()> {
    let mut t = open_pdc(server, conn, base_dn).await.map_err(|e| format!("{display_name} was not created. {e}"))?;
    let guid = ldap::add_gpo_object(&mut t.ldap, base_dn, display_name).await?;
    let gpo_dn = format!("CN={{{guid}}},CN=Policies,CN=System,{base_dn}");
    let folder = gpo_folder(&t.realm, &guid);

    let made = t.share.client.create_directory(&t.share.tree, &folder).await.map_err(|e| format!("{folder}: {e}"));
    let result = match made {
        Err(e) => Err(e),
        Ok(()) => {
            let filled = fill_folder(&mut t, &gpo_dn, &folder).await;
            if filled.is_err()
                && let Err(left) = t.share.remove_tree(&folder).await
            {
                let e = filled.err().unwrap_or_default();
                let _ = ldap::delete_gpo_tree(&mut t.ldap, &gpo_dn).await;
                let _ = t.ldap.unbind().await;
                t.share.close().await;
                return Err(format!("{display_name} was not created: {e} Its unfinished folder is still in SYSVOL: {left}"));
            }
            filled
        }
    };
    if let Err(e) = result {
        let undone = ldap::delete_gpo_tree(&mut t.ldap, &gpo_dn).await;
        let _ = t.ldap.unbind().await;
        t.share.close().await;
        return Err(match undone {
            Ok(()) => format!("{display_name} was not created: {e}"),
            Err(left) => format!("{display_name} was not created: {e} Its directory object {guid} is still there: {left}"),
        });
    }
    let _ = t.ldap.unbind().await;
    t.share.close().await;
    Ok(())
}

/// The GUID in capitals, if a GPO with it may be deleted at all.
fn deletable(guid: &str) -> LdapResult<String> {
    let guid = guid.to_uppercase();
    if !is_guid(&guid) {
        return Err("That is not a GPO's ID.".to_string());
    }
    if is_default_gpo(&guid) {
        return Err("The Default Domain Policy and Default Domain Controllers Policy cannot be deleted: the domain relies on them.".to_string());
    }
    Ok(guid)
}

/// Delete a GPO and its folder. The object goes first: a folder left behind
/// does no harm, while an object whose folder is gone fails on every client.
pub async fn delete_gpo(server: &Server, conn: &mut ldap3::Ldap, base_dn: &str, guid: &str) -> LdapResult<()> {
    let guid = deletable(guid)?;
    let gpo_dn = format!("CN={{{guid}}},CN=Policies,CN=System,{base_dn}");
    let links = ldap::list_gpo_links(conn, base_dn, &gpo_dn).await?;
    if !links.is_empty() {
        let names: Vec<&str> = links.iter().map(|l| l.ou_name.as_str()).collect();
        return Err(format!("The GPO was not deleted: it is still linked to {}. Unlink it first.", names.join(", ")));
    }
    match open_pdc(server, conn, base_dn).await {
        Ok(mut t) => {
            let result = async {
                ldap::delete_gpo_tree(&mut t.ldap, &gpo_dn).await?;
                let folder = gpo_folder(&t.realm, &guid);
                if t.share.is_folder(&folder).await {
                    t.share
                        .remove_tree(&folder)
                        .await
                        .map_err(|e| format!("The GPO was deleted, but part of its folder is still in SYSVOL on {}: {e}", t.dc))?;
                }
                Ok(())
            }
            .await;
            let _ = t.ldap.unbind().await;
            t.share.close().await;
            result
        }
        // A GPO from an older EasyDC is a bare object with no folder to remove.
        Err(e) => {
            if ldap::gpo_has_children(conn, &gpo_dn).await? {
                return Err(format!("The GPO was not deleted, because its folder in SYSVOL cannot be removed. {e}"));
            }
            ldap::delete_gpo_tree(conn, &gpo_dn).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_real_guid_names_a_folder() {
        assert!(is_guid("31B2F340-016D-11D2-945F-00C04FB984F9"));
        assert!(is_guid("31b2f340-016d-11d2-945f-00c04fb984f9"));
        for bad in [
            "",
            "..",
            "..\\..\\etc",
            "31B2F340-016D-11D2-945F-00C04FB984F",
            "31B2F340-016D-11D2-945F-00C04FB984F99",
            "31B2F340x016D-11D2-945F-00C04FB984F9",
            "{1B2F340-016D-11D2-945F-00C04FB984F9",
            "31B2F340-016D-11D2-945F-00C04FB98/F9",
            "31B2F340-016D-11D2-945F-00C04FB98\\F9",
            "G1B2F340-016D-11D2-945F-00C04FB984F9",
        ] {
            assert!(!is_guid(bad), "{bad}");
        }
    }

    #[test]
    fn the_default_gpos_are_known_in_any_case() {
        assert!(is_default_gpo("31b2f340-016d-11d2-945f-00c04fb984f9"));
        assert!(is_default_gpo("6AC1786C-016F-11D2-945F-00C04fB984F9"));
        assert!(!is_default_gpo("11111111-016D-11D2-945F-00C04FB984F9"));
    }

    #[test]
    fn the_default_gpos_and_odd_ids_are_never_deleted() {
        assert!(deletable("31b2f340-016d-11d2-945f-00c04fb984f9").unwrap_err().contains("Default Domain Policy"));
        assert!(deletable("6AC1786C-016F-11D2-945F-00C04FB984F9").is_err());
        assert!(deletable("../../easydc").is_err());
        assert_eq!(deletable("43bba07e-2e3b-4d2a-a627-6968dc431dd8").unwrap(), "43BBA07E-2E3B-4D2A-A627-6968DC431DD8");
    }

    #[test]
    fn the_folder_is_under_policies() {
        assert_eq!(gpo_folder("lab.test", "ABC"), "lab.test/Policies/{ABC}");
    }

    #[test]
    fn the_bind_account_is_read_from_the_dc() {
        assert_eq!(parse_whoami("u:LAB\\Administrator"), Some(("LAB".into(), "Administrator".into())));
        for bad in ["", "u:", "u:LAB", "dn:CN=Administrator", "u:\\x", "u:LAB\\"] {
            assert_eq!(parse_whoami(bad), None, "{bad}");
        }
    }
}
