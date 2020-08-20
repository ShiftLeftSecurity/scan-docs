## Visual Studio Code Extension

Scan is full integrated with Visual Studio Code IDE via its own native [extension](https://marketplace.visualstudio.com/items?itemName=shiftleftsecurity.shiftleft-scan). Use this extension to perform security scans and visualize the scan results without leaving your IDE. You can also navigate to the source code and remediate the results by interacting with the scan results.

## Features

- One-click security scanning (SAST based scanning)
- Navigation to the source location of the result
- Scan Results shows details about the result:
  - Result info
  - Run info
  - Code flow steps
  - Attachments
  - Fixes
- macOS touch bar support

### Results Viewer

- Automatically launches after performing a scan or when the workspace contains .sarif files in reports directory
- Updates the Result Details Panel with the currently selected result in the Results List, Problems Panel, or in source code
- Manually open it by typing "Scan: View Results" in the Command Palette(Ctrl+P or ⌘+P) or using the hotkey (Ctrl+L then Ctrl+E)


![Extension in Action](https://raw.githubusercontent.com/ShiftLeftSecurity/scan-action/master/docs/readmeImages/vscode.gif?raw=true)


## Install

1. Install or upgrade [Visual Studio Code](https://code.visualstudio.com/). Requires version 1.41.0 or higher.
2. Open up the extensions tab (Ctrl + Shift + X) and search for "Scan". Click "Install"
3. Alternatively, Quick Open (Ctrl + P)m paste the follwing command `ext install shiftleftsecurity.shiftleft-scan` and press enter.
4. Reload VS Code
5. Install Docker Desktop for performing Scan

## Use

1. Perform a Scan by using the `Perform Security Scan` option in the results window. Or in the Command Palette (Ctrl+Shift+p or ⌘+⇧+p) type "Scan: Security Scan" or use the hotkey (Ctrl+l then Ctrl+p)
2. Results will show up on the **Scan Findings** panel
3. Click the result you're investigating. The editor will navigate to the location

### Monorepo support

While working with large monorepo based repositories, configure the application root to limit the scanning to specific application directories. To do this, go to Preferences and search for "Scan". Specify the `App Root` as shown below:

![AppRoot Preference](https://raw.githubusercontent.com/ShiftLeftSecurity/scan-action/master/docs/readmeImages/vscode-pref.png?raw=true)

!!! note
    This configuration can be specified for either the user or for the workspace. To set it for a particular workspace, choose the `Workspace` tab in the above settings screen.

## Troubleshooting

- VS Code version should be 1.41.0 or higher for the extension to install and work
- The user should be part of the `docker` group on Linux and Mac. Please refer to the [post install](https://docs.docker.com/install/linux/linux-postinstall/) steps for your platform. Example below for linux.

  ```bash
  sudo groupadd docker
  sudo usermod -aG docker $USER
  ```

!!! warning
    Internet connectivity is required while loading the results for the first time. You might see the below error otherwise.
    ```
    Unable to load schema from 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json': getaddrinfo ENOTFOUND raw.githubusercontent.com.
    ```
