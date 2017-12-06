# fty-alert-list

Agent fty-alert-list serves as a broker between UI and fty-alert-engine. It also supports acknowledging alerts.

## How to build

To build fty-alert-list project run:

```bash
./autogen.sh
./configure
make
make check # to run self-test
```

## How to run

To run fty-alert-list project:

* from within the source tree, run:

```bash
./src/fty-alert-list
```

For the other options available, refer to the manual page of fty-alert-list

* from an installed base, using systemd, run:

```bash
systemctl start fty-alert-list
```

### Configuration file

Configuration file - fty-alert-list.cfg - is currently ignored.

Agent has an alerts state file stored in /var/lib/fty/fty-alert-list/state\_file.

## Architecture

### Overview

fty-alert-list is composed of 1 actor and 1 timer:

* fty-alert-list-server: main actor

Timer in main() triggers cleanup of expired alerts out of alert cache every minute.

## Protocols

### Published metrics

Agent doesn't publish any metrics.

### Published alerts

Agent publishes alerts on ALERTS stream.

### Mailbox requests

Agent fty-alert-list-server can be requested for:

* list of alerts of specified state

* acknowledging an alert

#### List of alerts of specified state

The USER peer sends the following message using MAILBOX SEND to
FTY-ALERT-LIST-SERVER ("fty-alert-list") peer:

* LIST/'state' - request list of alerts of specified 'state'

where
* '/' indicates a multipart string message
* 'state' MUST be one of [ ALL | ACTIVE | ACK-WIP | ACK-IGNORE | ACK-PAUSE | ACK-SILENCE ]
* subject of the message MUST be "rfc-alerts-list".

The FTY-ALERT-LIST-SERVER peer MUST respond with one of the messages back to USER
peer using MAILBOX SEND.

* LIST/'state'/'alert\_1'[/'alert\_2']...[/'alert\_N']
* ERROR/reason

where
* '/' indicates a multipart frame message
* 'state' is string and value MUST be repeated from request
* 'reason' is string detailing reason for error. If requested 'state' does not
    exist, the FTY-ALERT-LIST-SERVER peer MUST assign NOT_FOUND string as reason.
    If first frame of the message is not LIST, the FTY-ALERT-LIST-SERVER peer MUST
    assign BAD_COMMAND string as a reason.
* 'alert\_X' is an encoded fty-proto ALERT message representing alert
    of requested state
* subject of the message MUST be "rfc-alerts-list".

#### Acknowledging an alert

The USER peer sends the following messages using MAILBOX SEND to
FTY-ALERT-LIST-SERVER ("fty-alert-list") peer:

* 'rule'/'asset'/'state'

where
* '/' indicates a multipart string message
* 'rule' MUST be name of the rule
* 'asset' MUST be name of the asset for which the rule exists
* 'state' must be one of the states ACTIVE, ACK-PAUSE, ACK-WIP, ACK-SILENCE, ACK-IGNORE
* subject of the message MUST be 'rfc-alerts-acknowledge'

The FTY-ALERT-LIST-SERVER peer MUST respond with one of the messages back to USER
peer using MAILBOX SEND.

* OK/'rule'/'asset'/'state'
* ERROR/'reason'

where
* '/' indicates a multipart frame message
* 'rule', 'asset' and 'state' MUST be copied from request
* if FTY-ALERT-LIST-SERVER peer sends OK response, it MUST update the alert cache and republish the updated alert with recent timestamp
* 'reason' is string detailing reason for error. Possible values are: NOT\_FOUND, BAD\_MESSAGE, BAD\_STATE
* subject of the message MUST be 'rfc-evaluator-rules'

### Stream subscriptions

Agent is subscribed to \_ALERTS\_SYS stream and processes ALERT messages with state ACTIVE or RESOLVED.
If new state means a change from ACTIVE to RESOLVED or vice versa, it updates the cache.
If the stored state is one of the ACK states, it uses the cache to update the incoming alert.
In both cases, alert is then republished on ALERTS stream.
