"""
Nodal SDK Syslog Reporter

This module provides SIEM-friendly syslog output for Nodal security cases.
Supports two output formats:

1. JSON Format (default):
   - Modern, structured JSON output
   - Best for: Microsoft Sentinel, Devo, Splunk with proper configuration
   - Each case generates 3 types of entries: metadata, events, inferences

2. CEF Format:
   - Common Event Format standard
   - Best for: Traditional SIEMs (QRadar, ArcSight), legacy systems
   - Native SIEM parsing without configuration

Usage:
    # Set format via environment variable:
    export NODAL_SYSLOG_FORMAT=cef
    python syslog.py

    # Or modify the output_format variable in main()

Example outputs:
    JSON: NODAL_CASE_META: {"case_id":"123","event_ids":["e1","e2"],...}
    CEF: NODAL_CEF_CASE_META: CEF:0|Nodal|SDK|1.0|1001|Security Case Metadata|5|cs1=123...
"""

import asyncio
import json
import os
import syslog
import time

from nodal_sdk import Reporter
from nodal_sdk.types import Case


def write_case_to_syslog_flattened(case: Case):
    """
    Write case data to syslog as separate entries for better SIEM ingestion.
    Creates separate log entries for case metadata, events, inferences, and individual packets.
    All nested structures are flattened for optimal SIEM field extraction.
    """
    try:
        base_timestamp = time.time()

        # 1. First, send case metadata with references to events and inferences
        case_metadata = {
            "timestamp": base_timestamp,
            "source": "nodal_sdk",
            "component": "case_reporter",
            "event_type": "security_case_metadata",
            "case_id": case.get("case_id", ""),
            "variant": case.get("variant", ""),
            "description": case.get("description", ""),
            "mac": case.get("mac", ""),
            "ips": case.get("ips", ""),
            "ns_ip": case.get("ns_ip", ""),
            "expiry": case.get("expiry", ""),
            "ts": case.get("ts", ""),
            "closed": case.get("closed", ""),
            # Reference arrays for correlation
            "event_ids": [event["event_id"] for event in case.get("events", [])],
            "inference_ids": [
                inference.get("inference_id", "")
                for inference in case.get("inferences", [])
            ],
            "event_count": len(case.get("events", [])),
            "inference_count": len(case.get("inferences", [])),
        }

        # Add fabric data if present
        fabric = case.get("fabric")
        if fabric is not None:
            case_metadata["fabric"] = (
                fabric.tolist() if hasattr(fabric, "tolist") else str(fabric)
            )

        # Send case metadata to syslog
        json_data = json.dumps(case_metadata, separators=(",", ":"))
        syslog.openlog("nodal-sdk", syslog.LOG_PID, syslog.LOG_LOCAL0)
        syslog.syslog(syslog.LOG_INFO, f"NODAL_CASE_META: {json_data}")
        syslog.closelog()

        # 2. Send each event as a separate syslog entry with flattened structure
        for event in case.get("events", []):
            # Flatten trigger_packet data
            trigger_packet = event.get("trigger_packet", {})
            transport = trigger_packet.get("transport", {})
            lifecycle = trigger_packet.get("lifecycle", {})

            event_entry = {
                "timestamp": base_timestamp,
                "source": "nodal_sdk",
                "component": "case_reporter",
                "event_type": "security_case_event",
                "case_id": case.get("case_id", ""),  # For correlation
                "event_id": event["event_id"],
                "event_ts": event["ts"],
                "event_descriptiomn": event["description"],
                "event_device": str(event["device"]),
                "event_device_ip": event.get("device_ip", ""),
                "event_peer": str(event.get("peer", {})),
                "event_peer_ip": event.get("peer_ip", ""),
                # Flattened trigger packet fields
                "trigger_packet_src_ip": trigger_packet.get("src_ip", ""),
                "trigger_packet_dest_ip": trigger_packet.get("dest_ip", ""),
                "trigger_packet_src_mac": trigger_packet.get("src_mac", ""),
                "trigger_packet_dest_mac": trigger_packet.get("dest_mac", ""),
                "trigger_packet_src_dev_type": trigger_packet.get("src_dev_type", ""),
                "trigger_packet_dest_dev_type": trigger_packet.get("dest_dev_type", ""),
                "trigger_packet_size": trigger_packet.get("size", ""),
                "trigger_packet_ts": trigger_packet.get("ts", ""),
                "trigger_packet_tus": trigger_packet.get("tus", ""),
                "trigger_packet_probe_name": trigger_packet.get("probe_name", ""),
                # Flattened transport fields
                "trigger_packet_transport_protocol": transport.get("protocol", ""),
                "trigger_packet_transport_p_type": transport.get("p_type", ""),
                "trigger_packet_transport_p_subtype": transport.get("p_subtype", ""),
                "trigger_packet_transport_flags": transport.get("flags", ""),
                "trigger_packet_transport_src_port": transport.get("src_port", ""),
                "trigger_packet_transport_dest_port": transport.get("dest_port", ""),
                # Flattened lifecycle fields
                "trigger_packet_lifecycle_bad_keys": lifecycle.get("bad_keys", []),
                # Flattened event_ns data
                "event_ns_data": (
                    json.dumps(event.get("ns", {})) if event.get("ns") else ""
                ),
                # Summary statistics for event_ew instead of full nested data
                "event_ew_peer_count": len(event.get("ew", {})),
                "event_ew_total_packets": sum(
                    len(packets) for packets in event.get("ew", {}).values()
                ),
                "event_ew_peer_keys": list(event.get("ew", {}).keys()),
            }

            json_data = json.dumps(event_entry, separators=(",", ":"))
            syslog.openlog("nodal-sdk", syslog.LOG_PID, syslog.LOG_LOCAL0)
            syslog.syslog(syslog.LOG_INFO, f"NODAL_CASE_EVENT: {json_data}")
            syslog.closelog()

            # 2a. Send individual packet entries for each packet in event_ew
            ew_data = event.get("ew", {})
            packet_seq = 0
            for peer_key, packets in ew_data.items():
                # Extract peer info from key (format: "mac-ip")
                peer_parts = peer_key.split("-", 1)
                peer_mac = peer_parts[0] if len(peer_parts) > 0 else ""
                peer_ip = peer_parts[1] if len(peer_parts) > 1 else ""

                for packet in packets:
                    packet_seq += 1
                    packet_transport = packet.get("transport", {})
                    packet_lifecycle = packet.get("lifecycle", {})

                    packet_entry = {
                        "timestamp": base_timestamp,
                        "source": "nodal_sdk",
                        "component": "case_reporter",
                        "event_type": "security_case_packet",
                        "case_id": case.get("case_id", ""),
                        "event_id": event["event_id"],
                        "packet_sequence": packet_seq,
                        "peer_key": peer_key,
                        "peer_mac": peer_mac,
                        "peer_ip": peer_ip,
                        # Flattened packet fields
                        "packet_src_ip": packet.get("src_ip", ""),
                        "packet_dest_ip": packet.get("dest_ip", ""),
                        "packet_src_mac": packet.get("src_mac", ""),
                        "packet_dest_mac": packet.get("dest_mac", ""),
                        "packet_src_dev_type": packet.get("src_dev_type", ""),
                        "packet_dest_dev_type": packet.get("dest_dev_type", ""),
                        "packet_size": packet.get("size", ""),
                        "packet_ts": packet.get("ts", ""),
                        "packet_tus": packet.get("tus", ""),
                        "packet_probe_name": packet.get("probe_name", ""),
                        # Flattened packet transport fields
                        "packet_transport_protocol": packet_transport.get(
                            "protocol", ""
                        ),
                        "packet_transport_p_type": packet_transport.get("p_type", ""),
                        "packet_transport_p_subtype": packet_transport.get(
                            "p_subtype", ""
                        ),
                        "packet_transport_flags": packet_transport.get("flags", ""),
                        "packet_transport_src_port": packet_transport.get(
                            "src_port", ""
                        ),
                        "packet_transport_dest_port": packet_transport.get(
                            "dest_port", ""
                        ),
                        # Flattened packet lifecycle fields
                        "packet_lifecycle_bad_keys": packet_lifecycle.get(
                            "bad_keys", []
                        ),
                    }

                    json_data = json.dumps(packet_entry, separators=(",", ":"))
                    syslog.openlog("nodal-sdk", syslog.LOG_PID, syslog.LOG_LOCAL0)
                    syslog.syslog(syslog.LOG_INFO, f"NODAL_CASE_PACKET: {json_data}")
                    syslog.closelog()

        # 3. Send each inference as a separate syslog entry
        for inference in case.get("inferences", []):
            c2_chain = inference.get("c2_chain")
            if c2_chain is None:
                continue

            actor = str(c2_chain[0][0])
            gw = str(c2_chain[-2][0])
            ns = str(c2_chain[-1][0])
            chain_key = ", ".join([str(item[0]) for item in c2_chain])

            inference_entry = {
                "timestamp": base_timestamp,
                "source": "nodal_sdk",
                "component": "case_reporter",
                "event_type": "security_case_inference",
                "case_id": case.get("case_id", ""),  # For correlation
                "inference_id": inference.get("inference_id", ""),
                "inference_ts": inference.get("ts", ""),
                "inference_actor_mac": actor,
                "inference_gw_ip": gw,
                "inference_ns_ip": ns,
                "inference_chain_key": chain_key,
                "inference_pred": inference.get("average"),
            }

            json_data = json.dumps(inference_entry, separators=(",", ":"))
            syslog.openlog("nodal-sdk", syslog.LOG_PID, syslog.LOG_LOCAL0)
            syslog.syslog(syslog.LOG_INFO, f"NODAL_CASE_INFERENCE: {json_data}")
            syslog.closelog()

        total_packets = sum(
            len(packets)
            for event in case.get("events", [])
            for packets in event.get("ew", {}).values()
        )
        print(
            f"Case {case.get('case_id', '')} written to syslog as {len(case.get('events', []))} events, {total_packets} packets, and {len(case.get('inferences', []))} inferences at {base_timestamp}"
        )

    except Exception as e:
        print(f"Error writing case to syslog: {e}")
        raise


def flatten_case_to_syslog(case: Case):
    """
    Legacy function - now calls the new flattened implementation
    """
    write_case_to_syslog_flattened(case)


def escape_cef_header(value):
    """
    Escape special characters in CEF header fields.
    """
    if value is None:
        return ""
    return str(value).replace("\\", "\\\\").replace("|", "\\|")


def escape_cef_extension(value):
    """
    Escape special characters in CEF extension values.
    """
    if value is None:
        return ""
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace("=", "\\=")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )


def format_cef_extensions(data_dict):
    """
    Format a dictionary as CEF extension key=value pairs.
    """
    extensions = []
    for key, value in data_dict.items():
        if value is not None:
            # Convert lists/arrays to comma-separated strings
            if isinstance(value, list):
                value = ",".join(str(v) for v in value)
            escaped_value = escape_cef_extension(value)
            extensions.append(f"{key}={escaped_value}")
    return " ".join(extensions)


def write_case_to_syslog_cef(case: Case):
    """
    Write case data to syslog in CEF format for SIEM ingestion.
    Creates separate CEF entries for case metadata, events, inferences, and individual packets.
    All nested structures are flattened into CEF extension fields for optimal SIEM parsing.

    Required for QRadar and ArcSight
    """
    try:
        base_timestamp = time.time()

        # CEF Header constants
        cef_version = "0"
        device_vendor = escape_cef_header("Nodal")
        device_product = escape_cef_header("SDK")
        device_version = escape_cef_header("1.0")

        # 1. Send case metadata as CEF
        case_ips = case.get("ips", {})
        case_events = case.get("events", [])
        case_inferences = case.get("inferences", [])

        case_metadata_extensions = {
            "cs1": case.get("case_id", ""),  # Custom String 1 = Case ID
            "cs1Label": "CaseID",
            "cs2": case.get("variant", ""),  # Custom String 2 = Variant
            "cs2Label": "Variant",
            "msg": escape_cef_extension(case.get("description", "")),
            "smac": case.get("mac", ""),  # Source MAC
            "src": list(case_ips.keys())[0] if case_ips else "",  # Source IP (first IP)
            "cn1": len(case_events),  # Custom Number 1 = Event Count
            "cn1Label": "EventCount",
            "cn2": len(case_inferences),  # Custom Number 2 = Inference Count
            "cn2Label": "InferenceCount",
            "end": case.get("expiry", ""),  # End time
            "rt": int(
                case.get("ts", base_timestamp) * 1000
            ),  # Receipt time in milliseconds
            "cs3": ",".join(
                [event.get("event_id", "") for event in case_events]
            ),  # Event IDs
            "cs3Label": "EventIDs",
            "cs4": ",".join(
                [inference.get("inference_id", "") for inference in case_inferences]
            ),  # Inference IDs
            "cs4Label": "InferenceIDs",
            "cs5": "true" if case.get("closed", False) else "false",
            "cs5Label": "Closed",
            "cs6": case.get("ns_ip", ""),
            "cs6Label": "NamespaceIP",
        }

        # Add additional IPs if present
        if len(case_ips) > 1:
            additional_ips = list(case_ips.keys())[1:]
            case_metadata_extensions["flexString1"] = ",".join(additional_ips)
            case_metadata_extensions["flexString1Label"] = "AdditionalIPs"

        # Add fabric data if present
        fabric = case.get("fabric")
        if fabric is not None:
            fabric_data = fabric.tolist() if hasattr(fabric, "tolist") else str(fabric)
            case_metadata_extensions["flexString2"] = str(fabric_data)
            case_metadata_extensions["flexString2Label"] = "FabricData"

        extensions_str = format_cef_extensions(case_metadata_extensions)
        cef_message = f"CEF:{cef_version}|{device_vendor}|{device_product}|{device_version}|1001|Security Case Metadata|5|{extensions_str}"

        syslog.openlog("nodal-sdk", syslog.LOG_PID, syslog.LOG_LOCAL0)
        syslog.syslog(syslog.LOG_INFO, f"NODAL_CEF_CASE_META: {cef_message}")
        syslog.closelog()

        # 2. Send each event as a separate CEF entry with flattened structure
        for event in case_events:
            # Flatten trigger_packet data
            trigger_packet = event.get("trigger_packet", {})
            transport = trigger_packet.get("transport", {})
            lifecycle = trigger_packet.get("lifecycle", {})
            event_ips = event.get("ips", [])

            event_extensions = {
                "cs1": case.get("case_id", ""),  # Case ID for correlation
                "cs1Label": "CaseID",
                "cs2": event.get("event_id", ""),  # Event ID
                "cs2Label": "EventID",
                "smac": event.get("device", ""),  # Source MAC
                "dmac": event.get("peer", ""),  # Destination MAC
                "src": event.get("device_ip", ""),  # Source IP
                "dst": event.get("peer_ip", ""),  # Destination IP
                "msg": escape_cef_extension(
                    event.get("description")
                ),  # Issues as message
                "rt": int(event.get("ts", base_timestamp) * 1000),  # Receipt time
                # Flattened trigger packet fields
                "cs3": trigger_packet.get("src_ip", ""),
                "cs3Label": "TriggerPacketSrcIP",
                "cs4": trigger_packet.get("dest_ip", ""),
                "cs4Label": "TriggerPacketDestIP",
                "cs5": trigger_packet.get("src_mac", ""),
                "cs5Label": "TriggerPacketSrcMAC",
                "cs6": trigger_packet.get("dest_mac", ""),
                "cs6Label": "TriggerPacketDestMAC",
                "cn3": trigger_packet.get("size", ""),
                "cn3Label": "TriggerPacketSize",
                "cn4": trigger_packet.get("ts", ""),
                "cn4Label": "TriggerPacketTimestamp",
                "cn5": trigger_packet.get("tus", ""),
                "cn5Label": "TriggerPacketMicroseconds",
                # Flattened transport fields
                "flexString1": transport.get("protocol", ""),
                "flexString1Label": "TriggerTransportProtocol",
                "flexString2": str(transport.get("p_type", "")),
                "flexString2Label": "TriggerTransportType",
                "flexString3": str(transport.get("p_subtype", "")),
                "flexString3Label": "TriggerTransportSubtype",
                "flexNumber1": transport.get("flags", ""),
                "flexNumber1Label": "TriggerTransportFlags",
                "flexNumber2": transport.get("src_port", ""),
                "flexNumber2Label": "TriggerTransportSrcPort",
                "flexNumber3": transport.get("dest_port", ""),
                "flexNumber3Label": "TriggerTransportDestPort",
                # Summary statistics for event_ew
                "cn6": len(event.get("ew", {})),
                "cn6Label": "EWPeerCount",
                "flexNumber4": sum(
                    len(packets) for packets in event.get("ew", {}).values()
                ),
                "flexNumber4Label": "EWTotalPackets",
                # Additional fields
                "deviceCustomString1": trigger_packet.get("src_dev_type", ""),
                "deviceCustomString1Label": "TriggerSrcDevType",
                "deviceCustomString2": trigger_packet.get("dest_dev_type", ""),
                "deviceCustomString2Label": "TriggerDestDevType",
                "deviceCustomString3": trigger_packet.get("probe_name", ""),
                "deviceCustomString3Label": "TriggerProbeName",
            }

            # Add lifecycle bad_keys if present
            bad_keys = lifecycle.get("bad_keys", [])
            if bad_keys:
                event_extensions["deviceCustomString4"] = ",".join(
                    str(k) for k in bad_keys
                )
                event_extensions["deviceCustomString4Label"] = "TriggerLifecycleBadKeys"

            # Add additional IPs if present
            if len(event_ips) > 1:
                event_extensions["deviceCustomString5"] = ",".join(event_ips[1:])
                event_extensions["deviceCustomString5Label"] = "AdditionalEventIPs"

            # Add event NS data if present
            event_ns = event.get("ns", {})
            if event_ns:
                event_extensions["deviceCustomString6"] = json.dumps(event_ns)
                event_extensions["deviceCustomString6Label"] = "EventNamespaceData"

            extensions_str = format_cef_extensions(event_extensions)
            cef_message = f"CEF:{cef_version}|{device_vendor}|{device_product}|{device_version}|1002|Security Case Event|6|{extensions_str}"

            syslog.openlog("nodal-sdk", syslog.LOG_PID, syslog.LOG_LOCAL0)
            syslog.syslog(syslog.LOG_INFO, f"NODAL_CEF_CASE_EVENT: {cef_message}")
            syslog.closelog()

            # 2a. Send individual packet entries for each packet in event_ew as separate CEF entries
            ew_data = event.get("ew", {})
            packet_seq = 0
            for peer_key, packets in ew_data.items():
                # Extract peer info from key (format: "mac-ip")
                peer_parts = peer_key.split("-", 1)
                peer_mac = peer_parts[0] if len(peer_parts) > 0 else ""
                peer_ip = peer_parts[1] if len(peer_parts) > 1 else ""

                for packet in packets:
                    packet_seq += 1
                    packet_transport = packet.get("transport", {})
                    packet_lifecycle = packet.get("lifecycle", {})

                    packet_extensions = {
                        "cs1": case.get("case_id", ""),  # Case ID for correlation
                        "cs1Label": "CaseID",
                        "cs2": event.get("event_id", ""),  # Event ID for correlation
                        "cs2Label": "EventID",
                        "cs3": peer_key,  # Peer key
                        "cs3Label": "PeerKey",
                        "cs4": peer_mac,  # Peer MAC
                        "cs4Label": "PeerMAC",
                        "cs5": peer_ip,  # Peer IP
                        "cs5Label": "PeerIP",
                        "cn1": packet_seq,  # Packet sequence
                        "cn1Label": "PacketSequence",
                        # Flattened packet fields
                        "src": packet.get("src_ip", ""),  # Source IP
                        "dst": packet.get("dest_ip", ""),  # Destination IP
                        "smac": packet.get("src_mac", ""),  # Source MAC
                        "dmac": packet.get("dest_mac", ""),  # Destination MAC
                        "cn2": packet.get("size", ""),  # Packet size
                        "cn2Label": "PacketSize",
                        "cn3": packet.get("ts", ""),  # Packet timestamp
                        "cn3Label": "PacketTimestamp",
                        "cn4": packet.get("tus", ""),  # Packet microseconds
                        "cn4Label": "PacketMicroseconds",
                        # Flattened packet transport fields
                        "flexString1": packet_transport.get("protocol", ""),
                        "flexString1Label": "PacketProtocol",
                        "flexString2": str(packet_transport.get("p_type", "")),
                        "flexString2Label": "PacketTransportType",
                        "flexString3": str(packet_transport.get("p_subtype", "")),
                        "flexString3Label": "PacketTransportSubtype",
                        "flexNumber1": packet_transport.get("flags", ""),
                        "flexNumber1Label": "PacketTransportFlags",
                        "flexNumber2": packet_transport.get("src_port", ""),
                        "flexNumber2Label": "PacketSrcPort",
                        "flexNumber3": packet_transport.get("dest_port", ""),
                        "flexNumber3Label": "PacketDestPort",
                        # Additional packet fields
                        "deviceCustomString1": packet.get("src_dev_type", ""),
                        "deviceCustomString1Label": "PacketSrcDevType",
                        "deviceCustomString2": packet.get("dest_dev_type", ""),
                        "deviceCustomString2Label": "PacketDestDevType",
                        "deviceCustomString3": packet.get("probe_name", ""),
                        "deviceCustomString3Label": "PacketProbeName",
                        "rt": int(base_timestamp * 1000),  # Receipt time
                    }

                    # Add packet lifecycle bad_keys if present
                    packet_bad_keys = packet_lifecycle.get("bad_keys", [])
                    if packet_bad_keys:
                        packet_extensions["deviceCustomString4"] = ",".join(
                            str(k) for k in packet_bad_keys
                        )
                        packet_extensions["deviceCustomString4Label"] = (
                            "PacketLifecycleBadKeys"
                        )

                    extensions_str = format_cef_extensions(packet_extensions)
                    cef_message = f"CEF:{cef_version}|{device_vendor}|{device_product}|{device_version}|1004|Security Case Packet|4|{extensions_str}"

                    syslog.openlog("nodal-sdk", syslog.LOG_PID, syslog.LOG_LOCAL0)
                    syslog.syslog(
                        syslog.LOG_INFO, f"NODAL_CEF_CASE_PACKET: {cef_message}"
                    )
                    syslog.closelog()

        # 3. Send each inference as a separate CEF entry
        for inference in case_inferences:
            c2_chain = inference.get("c2_chain")
            if c2_chain is None:
                continue

            actor = str(c2_chain[0][0])
            gw = str(c2_chain[-2][0])
            ns = str(c2_chain[-1][0])
            chain_key = ", ".join([str(item[0]) for item in c2_chain])

            inference_extensions = {
                "cs1": case.get("case_id", ""),  # Case ID for correlation
                "cs1Label": "CaseID",
                "cs2": inference.get("inference_id", ""),  # Inference ID
                "cs2Label": "InferenceID",
                "smac": actor,  # Actor MAC as source MAC
                "src": gw,  # Gateway IP as source
                "dst": ns,  # Namespace IP as destination
                "rt": int(inference.get("ts", base_timestamp) * 1000),  # Receipt time
                "cs3": chain_key,
                "cs3Label": "ChainKey",
                "flexString1": str(inference.get("average")),
                "flexString1Label": "PredictionData",
            }

            extensions_str = format_cef_extensions(inference_extensions)
            cef_message = f"CEF:{cef_version}|{device_vendor}|{device_product}|{device_version}|1003|Security Case Inference|7|{extensions_str}"

            syslog.openlog("nodal-sdk", syslog.LOG_PID, syslog.LOG_LOCAL0)
            syslog.syslog(syslog.LOG_INFO, f"NODAL_CEF_CASE_INFERENCE: {cef_message}")
            syslog.closelog()

        total_packets = sum(
            len(packets)
            for event in case_events
            for packets in event.get("ew", {}).values()
        )
        print(
            f"Case {case.get('case_id', '')} written to syslog in CEF format as {len(case_events)} events, {total_packets} packets, and {len(case_inferences)} inferences at {base_timestamp}"
        )

    except Exception as e:
        print(f"Error writing case to syslog (CEF): {e}")
        # Log the error to syslog
        syslog.openlog("nodal-sdk", syslog.LOG_PID, syslog.LOG_LOCAL0)
        syslog.syslog(
            syslog.LOG_ERR,
            f"NODAL_ERROR: Failed to log case (CEF) {case.get('case_id', 'unknown')}: {str(e)}",
        )
        syslog.closelog()
        raise


async def main():
    # Configuration - these should match your environment
    ghost_uri = "http://GHOST_IP:8080/api/components/handshake"
    token = "TOKEN"
    name = "rep"

    # Choose output format: "json" or "cef"
    # Can be set via environment variable NODAL_SYSLOG_FORMAT or changed here
    # JSON: Better for modern SIEMs with good JSON parsing (Sentinel, Devo)
    # CEF: Better for traditional SIEMs or those with native CEF support (QRadar, ArcSight)
    output_format = os.getenv("NODAL_SYSLOG_FORMAT", "cef").lower()

    if output_format not in ["json", "cef"]:
        print(f"Warning: Unknown format '{output_format}', defaulting to JSON")
        output_format = "json"

    # Initialize syslog for startup
    syslog.openlog("nodal-sdk", syslog.LOG_PID, syslog.LOG_LOCAL0)
    syslog.syslog(
        syslog.LOG_INFO,
        f"NODAL_STARTUP: Syslog reporter starting with {output_format.upper()} format",
    )
    syslog.closelog()

    print("Starting Nodal SDK Syslog Reporter...")
    print(
        f"Cases will be written to syslog in {output_format.upper()} format for SIEM ingestion"
    )

    # Create reporter instance
    reporter = Reporter(name, 4001)

    try:
        # Register with the system
        await reporter.register("REPORTING_IP", ghost_uri, token)
        print("Successfully registered with Nodal system")

        # Main event loop - listen for incoming cases
        while True:
            async for cmd, data in reporter.recv():
                print(f"Received command: {cmd}")
                if cmd == "ping":
                    pass
                else:
                    print(type(data))
                    print(data.get("case_id", "no case id"))
                    with open("data.json", "w") as f:
                        json.dump(data, f)

                    if output_format.lower() == "cef":
                        write_case_to_syslog_cef(data)
                    else:
                        write_case_to_syslog_flattened(data)

    except KeyboardInterrupt:
        print("\nShutdown signal received")
        syslog.openlog("nodal-sdk", syslog.LOG_PID, syslog.LOG_LOCAL0)
        syslog.syslog(syslog.LOG_INFO, "NODAL_SHUTDOWN: Syslog reporter stopping")
        syslog.closelog()
    except Exception as e:
        print(f"Error in main loop: {e}")
        syslog.openlog("nodal-sdk", syslog.LOG_PID, syslog.LOG_LOCAL0)
        syslog.syslog(syslog.LOG_ERR, f"NODAL_ERROR: Reporter failed: {str(e)}")
        syslog.closelog()
        raise


if __name__ == "__main__":
    asyncio.run(main())
