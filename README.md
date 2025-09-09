# zabbix-netbox-sync (work in progress)

Tool to populate NetBox from Zabbix.

It retrieves data from Zabbix based on a filter configuration and creates or updates matching objects in NetBox.

## Usage

```
$ zabbix-netbox-sync -config /etc/zabbix-netbox-sync.yaml [ -dry | -wet ]
```

Use `-dry` for a run with only informative output and no changes to NetBox, and `-wet` for a run including changes to NetBox.

Optionally adjust the noisiness using `-loglevel <level>`.

## Configuration

Reference the [example configuration](./config.example.yaml).

### Authentication

The following environment variables can be used to make the tool authenticate with the provided NetBox and Zabbix instances:

- `NETBOX_TOKEN` - if not defined, the tool will connect to NetBox anonymously
- `ZABBIX_USER` - if not defined, the tool will default to the Zabbix username "guest"
- `ZABBIX_PASSPHRASE` - if not defined, the tool will connect to Zabbix anonymously
