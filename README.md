# App-Uninstall
A Powershell script that uninstalls Win10 applications installed at the HKLM registry level, regardless if they're `.msi` or `.exe`.

## Installation
Requires an administration account to run this code in a powershell terminal; however a seperate `.bat` file can be created, without the need for an admin account, to execute the following code:
```batch
powershell.exe -ExecutionPolicy UnRestricted -File %~dp0file-name.ps1
pause
```

## Usage
Script can be used in a Endpoint Configuration Manager to batch uninstall legacy or unwanted applications in a large enterprise environment that manages many computers or if a domain-joined user needs to remove a locally installed application on their computer.

### Uninstall Features
Script performs the following at the Windows registry's (HKLM) Local Machine level:
- Tests if an application is installed, outputting the uninstall string and its location through the `-Search` switch.
- Will uninstall multiple versions of the same application, even if an application's `AppData` is found on different user profiles through the `-Credential` switch.
- Will re-read the machine's registry to ensure there are no false positives with an application's removal.
- If a `.msi`'s uninstall switch is set to `/i`, the script will replace with the appropriate `/x` switch.

## Etcetera
Please make use of the "helper" code built-in to the script to learn more about syntax and view examples.
- Use the following command: 
```powershell
Get-Help C:\file-dir\file-name.ps1 -full
```
