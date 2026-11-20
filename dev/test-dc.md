# A test domain controller for EasyDC

A small Samba AD domain on a VM, separate from any real domain, so EasyDC can be tested
freely: bulk actions, deleting things, roles, thousands of users.

The test domain is called `lab.test` (NetBIOS name `LAB`), and the DC `labdc1`. The
`.test` ending is reserved for testing, so it can never clash with a real domain.

Replace these placeholders below:

| Placeholder | Meaning | Example |
|---|---|---|
| `<IP>` | the VM's fixed IP address | `192.168.1.50` |
| `<GATEWAY_DNS>` | the DNS server the VM should ask for outside names (your router) | `192.168.1.1` |
| `<ADMIN_PASSWORD>` | the test domain's Administrator password: 8+ characters, with upper case, lower case and a digit | |

## 1. The VM

- Ubuntu Server 24.04 LTS or Debian 12, freshly installed.
- 2 CPUs, 2 GB RAM, 20 GB disk.
- A **fixed IP address** (`<IP>`), set during install or in the router's DHCP reservations.
- On the same network as the machine running EasyDC.

Take a VM snapshot at the end of step 6: you can then reset the whole domain in seconds
after a test that broke it.

## 2. Name the machine

```bash
sudo hostnamectl set-hostname labdc1
```

Edit `/etc/hosts` so the name points to the real IP, not `127.0.1.1`. Replace any
`127.0.1.1 labdc1` line with:

```
<IP>  labdc1.lab.test  labdc1
```

## 3. Install Samba

```bash
sudo apt update
sudo apt install -y samba samba-ad-dc krb5-user winbind smbclient ldb-tools dnsutils
```

If asked for a Kerberos realm, enter `LAB.TEST`; for the servers, `labdc1.lab.test`.

## 4. Clear the way for the DC

Samba as a DC replaces the ordinary file-server services and needs DNS port 53:

```bash
sudo systemctl disable --now smbd nmbd winbind
sudo mv /etc/samba/smb.conf /etc/samba/smb.conf.orig
```

On **Ubuntu** only, turn off the local DNS stub, which holds port 53:

```bash
sudo systemctl disable --now systemd-resolved
sudo rm /etc/resolv.conf
echo "nameserver <GATEWAY_DNS>" | sudo tee /etc/resolv.conf
```

## 5. Create the domain

```bash
sudo samba-tool domain provision \
  --realm=LAB.TEST --domain=LAB \
  --server-role=dc --dns-backend=SAMBA_INTERNAL \
  --use-rfc2307 \
  --option="dns forwarder = <GATEWAY_DNS>" \
  --adminpass='<ADMIN_PASSWORD>'
```

Then use the Kerberos settings it wrote, and make the DC its own DNS server:

```bash
sudo cp /var/lib/samba/private/krb5.conf /etc/krb5.conf
printf 'nameserver 127.0.0.1\nsearch lab.test\n' | sudo tee /etc/resolv.conf
```

## 6. Start it and check

```bash
sudo systemctl unmask samba-ad-dc
sudo systemctl enable --now samba-ad-dc
```

Each of these should answer:

```bash
host -t SRV _ldap._tcp.lab.test
host labdc1.lab.test
kinit administrator
klist
samba-tool domain level show
```

LDAPS (port 636) works out of the box with a self-signed certificate:

```bash
openssl s_client -connect labdc1.lab.test:636 </dev/null 2>/dev/null | head -5
```

**Take the VM snapshot now.**

## 7. Add it to EasyDC

On the machine running EasyDC, let it find the DC by name. Add this line to `/etc/hosts`
(on a Mac: `sudo nano /etc/hosts`):

```
<IP>  labdc1.lab.test  labdc1
```

Then on the EasyDC dashboard, **Add server**:

| Field | Value |
|---|---|
| Name | `LAB` |
| LDAP URL | `ldaps://labdc1.lab.test` |
| Bind DN | `CN=Administrator,CN=Users,DC=lab,DC=test` |
| Password | `<ADMIN_PASSWORD>` |
| Skip TLS verification | on (the certificate is self-signed) |

Open the server and run the **Health check**. Expect a warning about having a single DC;
anything marked as failing needs a look before testing.

## 8. Test data (optional)

OUs, and users spread over them. `samba-tool` creates about one user a second, so 2,000
users take around half an hour; run it on the DC:

```bash
for ou in Sales Support Engineering; do
  sudo samba-tool ou add "OU=$ou,DC=lab,DC=test"
done
sudo samba-tool ou add "OU=Europe,OU=Sales,DC=lab,DC=test"

ous=("OU=Sales" "OU=Europe,OU=Sales" "OU=Support" "OU=Engineering")
for i in $(seq -w 1 2000); do
  sudo samba-tool user add "test$i" 'Lab-Pass-2026' \
    --given-name=Test --surname="User $i" \
    --userou="${ous[$((10#$i % 4))]}" >/dev/null
done
```

## 9. A second DC (optional)

For the Replication page and the multi-DC health checks. On a second VM, `labdc2`, do
steps 1 to 4, but point `/etc/resolv.conf` at labdc1 (`nameserver <IP of labdc1>`), then:

```bash
sudo samba-tool domain join lab.test DC -U administrator --dns-backend=SAMBA_INTERNAL
sudo cp /var/lib/samba/private/krb5.conf /etc/krb5.conf
sudo systemctl unmask samba-ad-dc
sudo systemctl enable --now samba-ad-dc
```

Give labdc2 a line in EasyDC's `/etc/hosts` too. After a few minutes, the Replication page
should show both DCs replicating.

## Resetting

Restore the VM snapshot from step 6. Without one, on the DC:

```bash
sudo systemctl stop samba-ad-dc
sudo rm -rf /var/lib/samba/private/* /var/lib/samba/sysvol/* /etc/samba/smb.conf
```

and run step 5 again.
