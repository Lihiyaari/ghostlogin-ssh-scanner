# GhostLogin
GhostLogin is a Bash-based cybersecurity tool that automates SSH exposure testing using Nmap, Hydra and sshpass.

## Features 
- Detects hosts with open SSH using Nmap
- Tests credentials using Hydra
- Automatically verifies access with SSH 
- Generates logs and reports

## Technologies 
- Bash
- Nmap
- Hydra
- SSH / sshpass
  
## Usage
Run the script:
```bash
chmod +x ghostlogin.sh
./ghostlogin.sh
```

## Screenshots

- Input Validation
The script validates the target input and prevents invalid IP formats or ranges.

![Input Validation](screenshots/input-validation.png)

- Built-in Credentials
GhostLogin can use a built-in credentials list to test SSH authentication.

![Built-in Credentials](screenshots/built-in-credentials.png)

- Custom Credentials File
Users can provide a custom credentials file for authentication testing.

![Custom Credentials](screenshots/custom-credentials.png)

- Proof File Verification
Successful access is verified by creating a proof file on the target machine.

![Proof File](screenshots/proof-file-choice1.png)

## Disclaimer
This tool was created for educational purposes only and must be used only in authorized environments.
