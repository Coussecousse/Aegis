# Volume Encryption — PostgreSQL Data-at-Rest Protection

## Recommended Approach: LUKS Full-Disk Encryption

**Setup:** Encrypt `/var/lib/docker/volumes` (or dedicated partition) via LUKS AES-256.

```bash
cryptsetup luksFormat /dev/sdX
cryptsetup luksOpen /dev/sdX aegis_encrypted
mkfs.ext4 /dev/mapper/aegis_encrypted
mount /dev/mapper/aegis_encrypted /var/lib/docker/volumes
```

**Key management:** Store passphrase in HashiCorp Vault. Auto-unlock via `/etc/crypttab`.

**References:** NIST SP 800-111, ANSSI-BP-028.
