
# Alerts-list agent 
Alerts-list agent implements ALERTS-LIST-PROVIDER part of RFC-Alerts-List protocol

## How to build

To build alets-list project run:

```bash
./autogen.sh
./configure
make
make check # to run self-test
```

## Protocols

### RFC-Alerts-List  -  Alerts list protocol
Connects USER peer to ALERTS-LIST-PROVIDER peer.

The USER peer sends one of the following messages using MAILBOX SEND to
ALERT-LIST-PROVIDER peer:

* LIST/state - request list of alerts of specified 'state'

where
* '/' indicates a multipart string message
* 'state' MUST be one of [ ALL | ACTIVE | ACK-WIP | ACK-IGNORE | ACK-PAUSE | ACK-SILENCE ]
* subject of the message MUST be "rfc-alerts-list".


The ALERT-LIST-PROVIDER peer MUST respond with one of the messages back to USER
peer using MAILBOX SEND.

* LIST/state/alert_1[/alert_2]...[/alert_N]
* ERROR/reason

where
* '/' indicates a multipart frame message
* 'state' is string and value MUST be repeated from request
* 'reason' is string detailing reason for error. If requested 'state' does not
    exist, the ALERT-LIST-PROVIDER peer MUST assign NOT_FOUND string as reason.
* 'alert_X' is an encoded ALERT message (from libbiosproto) representing alert
    of requested state and subject of the message MUST be "rfc-alerts-list".


