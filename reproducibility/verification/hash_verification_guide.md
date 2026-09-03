# Hash Verification Guide

To verify local artifact integrity against frozen research hashes:

## Linux / macOS
```bash
sha256sum -c manifests/hashes/reproducibility_hashes.csv
```

## Windows PowerShell
```powershell
Get-FileHash -Algorithm SHA256 <path_to_artifact>
```
