# swift-airsniffer

![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/lovetodream/SwiftAirsniffer) ![Platform macOS](https://img.shields.io/badge/platform-macOS-blue) ![Platform linux](https://img.shields.io/badge/platform-linux-blue) ![swift-tools-version 5.5](https://img.shields.io/badge/swift--tools-5.5-orange) ![GitHub](https://img.shields.io/github/license/lovetodream/SwiftAirsniffer)

A command line utility to send data from an [AirSniffer](https://www.stall.biz/project/der-airsniffer-schlechte-luft-kann-man-messen) to a Postgres database.

You can download the binary attached to each release. You can get the latest binary [here](https://github.com/lovetodream/SwiftAirsniffer/releases/latest).

## Usage

```sh
OVERVIEW: A utility for performing actions with data provided by the AirSniffer.

USAGE: airsniffer <subcommand>

OPTIONS:
  -h, --help              Show help information.

SUBCOMMANDS:
  lametric
  store (default)

  See 'airsniffer help <subcommand>' for detailed help.
```

### store (default)

```sh
USAGE: airsniffer store [<url>] [--host <host>] [--port <port>] [--ssl] [--database <database>] [--username <username>] [--password <password>]

ARGUMENTS:
  <url>                   The url of the airsniffer without /?json. (default: http://airsniffer.local)

OPTIONS:
  --host <host>           The hostname or IP address of the Postgres server. (default: localhost)
  --port <port>           The port number of the Postgres server. (default: 5432)
  -s, --ssl               Whether to use SSL/TLS to connect to the Postgres server.
  -d, --database <database>
                          The Postgres database. (default: airsniffer)
  -u, --username <username>
                          The Postgres username. (default: airsniffer)
  -p, --password <password>
                          The Postgres password. (default: password)
  -h, --help              Show help information.
```

### lametric

```sh
USAGE: airsniffer lametric [<url>] [<lametric>] [--access-token <access-token>]

ARGUMENTS:
  <url>                   The url of the airsniffer without /?json. (default: http://airsniffer.local)
  <lametric>              The push-url of the Lametric Time (default:
                          https://<ip-address>:4343/api/v1/dev/widget/update/com.lametric.bad002a8174dea4fbce93630df3e9afb/1)

OPTIONS:
  -a, --access-token <access-token>
                          The Access Token to authenticate against the Lametric Time
  -h, --help              Show help information.
```

## Database Schema

The table `aq_value` needs to be populated with the airsniffer value types you want to store in the database beforehand. You should use the value/var name provided by the airsniffer as the ID.

![diagram](https://user-images.githubusercontent.com/38291523/157752437-6fa7a10f-9b7b-4a0d-8846-5100655a9130.jpg)
