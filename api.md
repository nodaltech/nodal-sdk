# Nodal Cyberbrain API Documentation

This documentation covers ingress/egress interactions for the Mitigator, Feeder, and Reporter components.

## Mitigator

Mitigator components listen for mitigation requests from the brain, and perform specific actions to mitigate perceived hostile activity between targets.

### Logical Flow

The brain will send your mitigator `mitigation` objects. The mitigator is meant to absorb these, and if they apply:
 - Enact a mitigation and send back a copy of the `mitigation` object with fields (`mitigator`, `tag`, `enabled`) updated.
 - Store the mitigation object in state
 - Wait for the mitigation to expire, and when it does, remove the mitigation and send back another copy of the `mitigation` object with updated fields, specifically `enabled` set to false, and (`mitigator`) matching your mitigator.

This communication pattern is verbose, but ensures that all information is shared between both parties at all times. There is no hidden state.

### API

INGRESS cmd: `mitigation`
schema:
```json
{
    "mitigation_id": "{ip_a|mac_a}<->{ib_b|mac_b}" | "{ip_a|mac_a}<->*", // Identifier between the devices mitigation was requested on
    "tag": "some description", // Description of the mitigation being requested, or the reason for a request
    "mitigator": "mitigator name" | "*", // Name of the mitigator brain is requesting, * for any mitigator
    "enable": true | false,  // Whether to enable or disable the mitigation
    "targets": [ // A list of target devices to mitigate between, typically either two in the case of a pairwise block, or one in the case of an external global block.
        {
            "target": "{ip}" | "{mac}", // Ip or Mac address of target device
            "target_type": "Ip" | "Mac", // Enum specifying whether the target is of type Ip or Mac
            "internal": true | false // Whether or not the target device is external or internal
        },
        {
            "target": ...,
            "target_type": ...,
            "internal": ...
        }
    ],
    "expiry": 1744724448, // Desired expiry of the mitigation, unix timestamp format
    "ts": 1744731132 // Timestamp at which the mitigation was requested
}
```

EGRESS cmd: `mitigation`
schema:
```json
{
    "mitigation_id": "{ip_a|mac_a}<->{ib_b|mac_b}" | "{ip_a|mac_a}<->*", // Identifier between the devices mitigation was requested on, same as the one received when responding to a mitigation request
    "tag": "some description", // Description of the mitigation being requested, or the reason for a request. Can keep the same or alter with a mitigator specific message
    "mitigator": "your_mitigator_name", // Fill with the name of your mitigator if responding.
    "enable": true | false,  // True if you are applying a mitigation from a request, false if you're sending a updated 'mitigation' object to indicate a mitigation timed out within your mitigator.
    "targets": [ // A list of target devices to mitigate between, typically either two in the case of a pairwise block, or one in the case of an external global block. Keep the same as in the request.
        {
            "target": "{ip}" | "{mac}", // Ip or Mac address of target device
            "target_type": "Ip" | "Mac", // Enum specifying whether the target is of type Ip or Mac
            "internal": true | false // Whether or not the target device is external or internal
        },
        {
            "target": ...,
            "target_type": ...,
            "internal": ...
        }
    ],
    "expiry": 1744724448, // Desired expiry of the mitigation, unix timestamp format.
    "ts": 1744731132 // Timestamp at which the mitigation was requested
}
```

## Feeder

Feeder components have the ability to send events directly into brain, through non-relay-detector / packet derived channels.

### Logical Flow

Your feeder component picks up some information signaling that device X has performed a suspicious action, it creates a `feedevent` object and sends it to brain.

### API

EGRESS cmd: `event`
schema:
```json
{
    "event_id": "feedxyz123", // Some unique identifier for your event
    "ips": [ "{ip_a}", .. ], // A list of IP addresses (can be empty) for the device that caused the event
    "issues": [ // A list of issues your feeder correlates with the device
        "Feed deems this ip suspect"
    ],
    "mac": "{mac}", // The mac address of the device
    "ts": 1744724448, // The time at which the event was created, in unix timestamp format
    "peer_mac": "{peer_mac}", // The mac of a peer, if any, that was involved in weird activity
    "peer_ip": "{peer_ip}", // The ip of a peer, if any, that was involved in weird activity
}
```

## Reporter

Receives cases from brain as they occur

### Logical Flow

Your reporter component will wait for `case` objects from brain, once it has them it can feed them into a SIEM, or whatever else.

### API

INGRESS cmd: `case`
schema:
```json
{
    "case_id": "{case_id}", // Unique identifier
    "variant": "Activity | Analyst", // Activity for cases generated by repeated events, Analyst for cases generated by a user
    "description": "...", // Description of the case
    "mac": "{mac}", // The mac of the target device, or the device which caught a case
    "ips": [ // Any IP addresses associated with the target device
        "{ip_a}",
        "{ip_b}"
    ],
    "ns_ip": "{ns_ip}", // Suspected North-South C2 communicating with the target device
    "events": [
        {
            "event_id": "{event_id}", // Unique identifier
            "ts": 1744724448, // Timestamp at which the event was created
            "issues": [ // Issues found that sparked the event
                "{issue_a}",
                "{issue_b}"
            ],
            "mac": "{target_mac}", // Mac of the target device, will match mac in the case block 
            "ips": [ // Ips for the target device
                "{ip_a}",
                "{ip_b}",
            ],
            "peer_mac": "{peer_mac}", // Mac of the peer the target device was talking to when this event was created
            "trigger_packet": PacketInformation, // Packet header from target to peer that triggered the event
            "ns": { // Convized buffer of packets from the target device to the wan
                "{ns_peer_ip_a}": {
                    "{ns_peer_ip_a_conv_a}": [
                        PacketInformation,
                        PacketInformation
                    ],
                    ...
                },
                ...
            },
            "ew": { // Convized buffer of packets from the target device to other machines on the lan
                "{ew_peer_ip_a}": {
                    "{ew_peer_ip_a_conv_a}": [
                        PacketInformation,
                        PacketInformation
                    ],
                    ...
                },
                ...
            }
        }
    ],
    "inferences": [
        {
            "inference_id": "{inference_id}", // Unique identifier
            "ts": 1744724448, // When this inference was created
            "actor_mac": "{actor_mac}", // The mac of the device at the beginning of the APT chain, playing the 'actor'
            "gw_ip": "{gw_ip}", // The IP of the gateway device, second to last in the APT chain
            "ns_ip": "{ns_ip}", // The IP of the North-South device, or C2 within the suspected APT chain
            "chain_key": "{mac_actor},{ip_relay},{ip_gateway},{ip_ns}", // Comma separated descriptor of the devices in the suspected chain
            "model_name": "synth", // The model which found this chain
            "pred": NDArray // a (1, 2) array, where the 0 index is prob_benign and the 1 index is prob malign: [[0, 1]] would be fully malign
        },
        ...
    ],
    "fabric": NDArray, // Visualization of the current state of the fabric algorithm for target device at time of case creation, in NDArray form.
    "expiry": 1744724448, // At what time this case will auto-close
    "ts": 1744724448, // When this case was created
    "closed": true | false // If the case is closed
}
```