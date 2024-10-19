# Password Dictionary Creator Project

## Overview

This project is designed to serve as a comprehensive toolkit for penetration testing, with a focus on password dictionary creation. It includes various command-line modules that enhance password dictionary creation and support additional functionalities like network scanning and IP tracing.

## Table of Contents

1. [PasswordDictionaryCreator](#passworddictionarycreator)
2. [PentestTool](#pentesttool)
3. [NmapModule](#nmapmodule)
4. [IPTraceModule](#iptracemodule)
5. [Installation](#installation)
6. [Usage](#usage)
7. [Contributing](#contributing)
8. [License](#license)

## PasswordDictionaryCreator

`PasswordDictionaryCreator` is a command-line module designed to create advanced password dictionaries with enhanced patterns and combinations.

### Features

- Generates complex password dictionaries with substitutions and case-sensitivity permutations.
- Supports appending and prepending special characters and numbers.
- Allows combinations of multiple base words.

### Usage

Start the `PasswordDictionaryCreator` module:

```sh
python PasswordDictionaryCreator.py
```

#### Commands

- `generate <base_word_list> <output_file_path>`: Generates a complex password dictionary.
- `quit`: Exits the PasswordDictionaryCreator module.

## PentestTool

`PentestTool` is the main command interpreter for the pentesting toolkit.

### Features

- Provides a unified command-line interface for different pentesting modules.
- Modules supported: Nmap, IP Trace, Password Dictionary Creator, etc.

### Usage

Launch the `PentestTool`:

```sh
python PentestTool.py
```

#### Commands

- `exit`: Exits the PentestTool.
- `nmap`: Switches to the Nmap module.
- `iptrace`: Switches to the IP Trace module.
- `dictionary_creator`: Switches to the Password Dictionary Creator module.
- `help`: Lists available commands.

## NmapModule

`NmapModule` provides advanced network scanning functionalities using Nmap.

### Features

- Supports various Nmap scans like TCP SYN scan, UDP scan, OS fingerprinting, etc.

### Usage

Switch to the `NmapModule` from the `PentestTool`:

```sh
nmap
```

#### Commands

- `quit`: Returns to the main menu and exits the Nmap module.
- `tcp_syn_scan <target_ip>`: Perform a TCP SYN port scan.
- `tcp_connect_scan <target_ip>`: Perform a TCP connect() scan.
- `udp_scan <target_ip>`: Perform a UDP scan.
- `tcp_ack_scan <target_ip>`: Perform a TCP ACK scan.
- `ping_sweep <target_ip_range>`: Perform a ping sweep.
- `xmas_scan <target_ip>`: Perform an XMAS scan.
- `null_scan <target_ip>`: Perform a NULL scan.
- `fin_scan <target_ip>`: Perform a FIN scan.
- `os_fingerprinting <target_ip>`: Perform OS fingerprinting.
- `version_detection <target_ip>`: Perform version detection.

## IPTraceModule

`IPTraceModule` provides functionalities for IP tracing.

### Features

- Allows querying of IP information.
- Prints detailed IP information.

### Usage

Switch to the `IPTraceModule` from the `PentestTool`:

```sh
iptrace
```

#### Commands

- `trace <ip>`: Traces the provided IP.
- `quit`: Returns to the main menu and exits the IP Trace module.

## Installation

To install the project, make sure you have Python installed. Install the required dependencies using `pip`:

```sh
pip install -r requirements.txt
```

## Usage

1. Clone the repository.
2. Navigate to the project directory.
3. Start the `PentestTool`:

```sh
python PentestTool.py
```

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.