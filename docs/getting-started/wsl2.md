# Scan on Windows 10 with WSL 2 and podman

[WSL 2](https://docs.microsoft.com/en-us/windows/wsl/wsl2-index) in available on Windows 10, version 2004, Build 19041 or higher. [Podman](https://podman.io/) is a daemonless container engine for developing and running OCI containers. It is possible to run scan on Windows 10 with WSL2 and podman without the need for installing docker desktop. Without a running docker daemon, more CPU and RAM are available for your development needs.

## Installing WSL2

Follow the instructions [here](https://docs.microsoft.com/en-us/windows/wsl/install-win10) to either install or update to WSL2.

## Install Ubuntu 20.04 LTS

Ubuntu 20.04 LTS is one of the supported distro for both WSL2 and podman. If you are planning to use an existing Ubuntu WSL 1 installation, please ensure it is upgraded to WSL 2.

```powershell
wsl --list --verbose
wsl --set-version <distribution name> <versionNumber>
```

## Installing podman and dependencies

Install podman using the below the commands as mentioned [here](https://podman.io/getting-started/installation)

```bash
. /etc/os-release
sudo sh -c "echo 'deb https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/testing/xUbuntu_${VERSION_ID}/ /' > /etc/apt/sources.list.d/devel:kubic:libcontainers:testing.list"
curl -L https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/testing/xUbuntu_${VERSION_ID}/Release.key | sudo apt-key add -
sudo apt-get update -qq
sudo apt-get -qq -y install podman build-essential
```

### Configuring podman

We need to make couple of changes to podman configuration. Edit the file `/etc/containers/containers.conf` and change:

- cgroup_manager to "cgroupfs" 
- events_logger to "file"

```
cgroup_manager = "cgroupfs"
events_logger = "file"
```

### Set alias for docker

Add the below alias to your ~/.bashrc or ~/.zshrc

```bash
alias docker=podman
```

Restart the shell for the alias to take effect.

## Running scan

Run scan using the same docker commands as mentioned in the [getting-started](README.md)

```bash
docker run --rm -e "WORKSPACE=${PWD}" -v "$PWD:/app:cached" shiftleft/sast-scan scan
```

If you do not prefer alias `docker` then use `podman` in the above command.

```bash
podman run --rm -e "WORKSPACE=${PWD}" -v "$PWD:/app:cached" shiftleft/sast-scan scan
```
