# Introduction

`prov` is a Python script that enables Terraform-like declarative Cobbler server
configurations by synchronizing the data in one or more YAML-based configuration
files with the Cobbler server via Cobbler's
[XMLRPC API](https://github.com/cobbler/cobbler/wiki/Cobbler-XMLRPC-API).

## System Requirements

* Python 3
* [PyYAML](https://pyyaml.org/)

## Installation

Simply invoke `prov.py` as an executable script in your system's shell, assuming
your system meets all of the requirements listed above.

## Known Bugs & Potential Issues

* There is an annoying discrepancy between the key names presented to the script
  from the Cobbler server when fetching existing information, and the names the
  server expects when attempting to add or modify information. The worst
  offender in this regard is with the interface specifications of Cobbler system
  items. The script will do what it can to reduce this discrepancy.
  
* The Cobbler server will not complain when presented with a key-value pair it
  doesn't know how to interpret. If after running the script you run the script
  again with the `--dry-run` flag but see that it still has pending changes, it
  probably means that the key names don't match up correctly (in relation to the
  first bullet point).

----
# Usage

## Basic Example

`prov` is invoked by specifying the location of a declarative configuration file
to load (see `CONFIGURATION.md`). If a directory is supplied instead of a full
path, `prov` will select a file within that directory called `prov.yaml` or
select the `.yaml` file that most closely matches the hostname of the executing
machine. Consider the following invocation with respect to a relative directory
called `example`:

```bash
$ prov example -s cobbler.example.com
```

where `cobbler.example.com` corresponds to the FQDN of a cobbler server. 

Below is an example of how to export the existing configuration of a Cobbler
server to a compatible declarative configuration file:

``` bash
$ prov -s cobbler.example.com --dump existing.yaml
```

## CLI Arguments

The following table describes the various command-line arguments.

| Argument(s)             | Description                                                                                                                                                                   |
|-------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `-a`, `--api-path`      | Specifies the API path endpoint to make XMLRPC requests to.                                                                                                                   |
| `-b`, `--base-dir`      | Specifies the base directory from which files will be searched for (as an alternative to the directory containing the specified configuration file).                          |
| `--delete`              | Specifies that the script should delete any specifications on the server which are not present in the target configuration.                                                   |
| `-d`, `--dry-run`       | Specifies that the script should only execute a dry-run, preventing any changes from occurring to the specified cobbler server.                                               |
| `-D`, `--dump`          | Specifies that the script should save the active configuration of the specified Cobbler server to the specified configuration file (instead of the script's usual operation). |
| `-h`, `--help`          | Displays help and usage information.                                                                                                                                          |
| `-f`, `--log-file`      | Specifies a log file to write events to in addition to STDOUT/STDERR.                                                                                                         |
| `-l`, `--log-level`     | Specifies the log level of the script, being either `info` or `debug`.                                                                                                        |
| `-m`, `--log-mode`      | Specifies whether to `append` or `overwrite` the specified log file.                                                                                                          |
| `--no-color`            | Disables color output to STDOUT/STDERR.                                                                                                                                       |
| `-p`, `--password`      | Specifies the password to use when connecting to the specified cobbler server.                                                                                                |
| `-P`, `--port`          | Specifies the port on the specified cobbler server to connect to.                                                                                                             |
| `-s`, `--server`        | Specifies the FQDN or IP address of the cobbler server to connect to.                                                                                                         |
| `-S`, `--snippets-dir`  | Specifies the directory relative to the specified base directory within which autoinstallation snippets should be found.                                                      |
| `--ssl`                 | Specifies that the script should connect to the Cobbler API via `https`.                                                                                                      |
| `-t`, `--templates-dir` | Specifies the directory relative to the specified base directory within which autoinstallation templates (kickstarts) should be found.                                        |
| `-u`, `--username`      | Specifies the username to use when connecting to the specified cobbler server.                                                                                                |

The following table expands upon the one above to list the value types, default
values, and associated environment variables for applicable arguments:

| Argument(s)             | Value Type / Possible Values | Default Value | Associated Environment Variable |
|-------------------------|------------------------------|---------------|---------------------------------|
| `-a`, `--api-path`      | API Path                     | `cobbler_api` | `PROV_API_PATH`                 |
| `-b`, `--base-dir`      | Directory Path               |               | `PROV_BASE_DIR`                 |
| `-f`, `--log-file`      | File Path                    |               | `PROV_LOG_FILE`                 |
| `-l`, `--log-level`     | `info` or `debug`            | `info`        | `PROV_LOG_LEVEL`                |
| `-m`, `--log-mode`      | `append` or `overwrite`      | `append`      | `PROV_LOG_MODE`                 |
| `-p`, `--password`      | String                       | `cobbler`     | `PROV_PASSWORD`                 |
| `-P`, `--port`          | Positive Integer             | `80`          | `PROV_PORT`                     |
| `-s`, `--server`        | FQDN or IP Address           | `127.0.0.1`   | `PROV_SERVER`                   |
| `-S`, `--snippets-dir`  | Directory Path               | `snippets`    | `PROV_SNIPPETS_DIR`             |
| `-t`, `--templates-dir` | Directory Path               | `templates`   | `PROV_TEMPLATES_DIR`            |
| `-u`, `--username`      | String                       | `cobbler`     | `PROV_USERNAME`                 |

## Exit Codes

`prov` may produce one of the following exit codes:

| Exit Code | Description                                                                                |
|-----------|--------------------------------------------------------------------------------------------|
| `0`       | Script exited successfully, although perhaps with warnings.                                |
| `1`       | Script encountered a general error prior to performing its main task.                      |
| `2`       | Indicates an issue during the parsing of command-line arguments or environment validation. |
| `3`       | Indicates an issue reading/parsing the specified configuration file(s).                    |
| `4`       | Indicates an invalid Cobbler configuration.                                                |
| `5`       | Indicates an issue connecting to the specified Cobbler server.                             |
| `6`       | Indicates an issue updating Cobbler repositories.                                          |
| `7`       | Indicates an issue updating Cobbler images.                                                |
| `8`       | Indicates an issue updating Cobbler distributions.                                         |
| `9`       | Indicates an issue updating Cobbler management classes.                                    |
| `10`      | Indicates an issue updating Cobbler profiles.                                              |
| `11`      | Indicates an issue updating Cobbler systems.                                               |
| `12`      | Indicates an issue synchronizing changes.                                                  |
| `13`      | Indicates an issue while disconnecting from the specified Cobbler server.                  |
| `15`      | Indicates an issue while dumping existing Cobbler configuration.                           |
| `16`      | Indicates an issue while synchronizing disk images.                                        |
| `17`      | Indicates an issue updating Cobbler autoinstallation snippet files.                        |
| `18`      | Indicates an issue updating Cobbler autoinstallation template (kickstart) files.           |
| `100`     | Indicates the script received a CTRL-C or CTRL-D.                                          |
