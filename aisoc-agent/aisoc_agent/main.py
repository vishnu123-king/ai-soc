import os
import sys
import time
import signal
import argparse
import json
from typing import List

from . import __version__
from .config import AgentConfig
from .logging import setup_agent_logger
from .buffer.spool import EventSpool
from .transport.client import TransportClient
from .transport.shipper import BatchShipper
from .heartbeat.heartbeat import HeartbeatManager
from .collectors.auth import AuthLogCollector
from .collectors.journald import JournaldCollector
from .collectors.auditd import AuditdCollector
from .collectors.process import ProcessCollector
from .collectors.network import NetworkCollector
from .normalizer.events import create_event

def cmd_version(args, config: AgentConfig) -> int:
    print(f"aisoc-agent v{__version__} (AI-SOC Lightweight Linux Endpoint Agent)")
    return 0

def cmd_config_check(args, config: AgentConfig) -> int:
    print("=== AI-SOC Agent Configuration & Environment Audit ===")
    dump = config.dump_safe()
    for k, v in dump.items():
        print(f"  {k:<22}: {v}")

    print("\n--- Filesystem & Permissions Checks ---")
    # Buffer dir
    buf_ok = os.path.exists(config.buffer_directory) and os.access(config.buffer_directory, os.W_OK)
    print(f"  Buffer Directory [{config.buffer_directory}]: {'[OK - Writable]' if buf_ok else '[FAIL - Not Writable]'}")
    
    # Token path
    tok_exists = os.path.exists(config.token_path)
    if tok_exists:
        try:
            mode = oct(os.stat(config.token_path).st_mode & 0o777)
            print(f"  Token File [{config.token_path}]: [EXISTS] Permissions: {mode}")
        except Exception:
            print(f"  Token File [{config.token_path}]: [EXISTS]")
    else:
        print(f"  Token File [{config.token_path}]: [NOT FOUND - Run 'aisoc-agent register']")

    # Auth log
    auth_ok = os.path.exists(config.auth_log_path) and os.access(config.auth_log_path, os.R_OK)
    print(f"  Auth Log [{config.auth_log_path}]: {'[OK - Readable]' if auth_ok else '[WARNING - Not Readable/Found]'}")

    # Audit log
    audit_ok = os.path.exists(config.audit_log_path) and os.access(config.audit_log_path, os.R_OK)
    print(f"  Audit Log [{config.audit_log_path}]: {'[OK - Readable]' if audit_ok else '[OPTIONAL - Not Readable/Found]'}")

    return 0

def cmd_status(args, config: AgentConfig) -> int:
    print("=== AI-SOC Agent Status ===")
    print(f"  Agent ID          : {config.agent_id}")
    print(f"  Agent Version     : {config.agent_version}")
    print(f"  Central SOC Server: {config.central_soc_url}")
    print(f"  Token Configured  : {'YES' if config.agent_token else 'NO (Enrollment required)'}")
    print(f"  Token Location    : {config.token_path}")
    print(f"  Buffer Directory  : {config.buffer_directory}")
    
    spool = EventSpool(config.buffer_directory)
    backlog = spool.count()
    print(f"  Spool Backlog     : {backlog} event(s) queued")

    # Reachability
    transport = TransportClient(config)
    reachable = transport.ping()
    print(f"  Central SOC Reach : {'ONLINE' if reachable else 'UNREACHABLE'}")
    transport.close()

    return 0

def cmd_register(args, config: AgentConfig) -> int:
    logger = setup_agent_logger(level=config.log_level)
    print(f"[*] Enrolling agent '{config.agent_id}' with Central SOC ({config.central_soc_url})...")
    transport = TransportClient(config)
    success, token, err = transport.register()
    transport.close()

    if success:
        print(f"[+] SUCCESS: Agent enrolled successfully.")
        print(f"[+] Bearer token securely persisted to {config.token_path} (mode 0600).")
        return 0
    else:
        print(f"[-] REGISTRATION FAILED: {err}")
        return 1

def cmd_test(args, config: AgentConfig) -> int:
    logger = setup_agent_logger(level="INFO")
    print(f"[*] Running AI-SOC Agent Diagnostic Pipeline for '{config.agent_id}'...")

    # Step 1: Config & Token check
    if not config.agent_token:
        print("[-] FAILED: No agent token found. Run 'aisoc-agent register' first.")
        return 1
    print("[+] Step 1: Local token detected and loaded.")

    # Step 2: Ping
    transport = TransportClient(config)
    if not transport.ping():
        print(f"[-] FAILED: Unable to reach Central SOC at {config.central_soc_url}")
        transport.close()
        return 1
    print(f"[+] Step 2: Central SOC endpoint reachability confirmed ({config.central_soc_url}).")

    # Step 3: Heartbeat
    hb_ok, hb_err = transport.send_heartbeat()
    if not hb_ok:
        print(f"[-] FAILED: Heartbeat validation failed: {hb_err}")
        transport.close()
        return 1
    print("[+] Step 3: Heartbeat successfully authenticated and acknowledged.")

    # Step 4: Test Event Ingestion
    test_ev = create_event(
        hostname=config.agent_id,
        agent_id=config.agent_id,
        event_type="test",
        action="agent_self_test",
        status="success",
        raw_message=f"Self-test diagnostic event from aisoc-agent v{config.agent_version} on {config.agent_id}",
        metadata={"diagnostic": True, "agent_version": config.agent_version}
    )
    ev_ok, ev_res, ev_err = transport.send_single_event(test_ev.to_dict())
    if not ev_ok:
        print(f"[-] FAILED: Event ingestion test failed: {ev_err}")
        transport.close()
        return 1
    print(f"[+] Step 4: Telemetry event successfully ingested (Server Event ID: {ev_res.get('id') if ev_res else 'OK'}).")

    transport.close()
    print("\n[✓] ALL DIAGNOSTIC TESTS PASSED: aisoc-agent is ready for production service.")
    return 0

def cmd_start(args, config: AgentConfig) -> int:
    logger = setup_agent_logger(level=config.log_level)
    logger.info(f"Starting aisoc-agent v{__version__} [Agent ID: {config.agent_id}]")
    logger.info(f"Target Central SOC: {config.central_soc_url}")

    # Check for token or auto-register if missing
    if not config.agent_token:
        logger.warning(f"No existing token found at {config.token_path}. Attempting automatic registration...")
        temp_transport = TransportClient(config)
        reg_ok, token, err = temp_transport.register()
        temp_transport.close()
        if not reg_ok:
            logger.error(f"Automatic registration failed: {err}. Please run 'aisoc-agent register' or configure AGENT_TOKEN.")
            return 1
        config.agent_token = token

    # Initialize Persistent Spool Buffer
    spool = EventSpool(config.buffer_directory)
    logger.info(f"Persistent EventSpool initialized at {config.buffer_directory} ({spool.count()} backlog events)")

    # Initialize Transport and Shipper
    transport = TransportClient(config)
    shipper = BatchShipper(config, spool, transport)

    # Initialize Heartbeat
    heartbeat = HeartbeatManager(config, transport)

    # Initialize Telemetry Collectors
    collectors = [
        AuthLogCollector(config, spool),
        JournaldCollector(config, spool),
        AuditdCollector(config, spool),
        ProcessCollector(config, spool),
        NetworkCollector(config, spool)
    ]

    # Start services
    heartbeat.start()
    shipper.start()
    for col in collectors:
        col.start()

    logger.info("aisoc-agent daemon is fully operational and collecting telemetry.")

    stop_signal = threading.Event()

    def _signal_handler(signum, frame):
        sig_name = signal.Signals(signum).name
        logger.info(f"Received termination signal ({sig_name}). Initiating graceful shutdown...")
        stop_signal.set()

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    try:
        while not stop_signal.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        logger.info("Shutting down collectors and flushing telemetry buffers...")
        for col in collectors:
            col.stop()
        
        # Give shipper a brief moment to ship any remaining queued events
        shipper.ship_once()
        shipper.stop()
        heartbeat.stop()
        transport.close()
        logger.info("aisoc-agent shutdown complete. Exiting.")

    return 0

def main() -> int:
    parent_parser = argparse.ArgumentParser(add_help=False)
    parent_parser.add_argument("-c", "--config", help="Path to custom agent.conf configuration file", default=None)

    parser = argparse.ArgumentParser(
        prog="aisoc-agent",
        parents=[parent_parser],
        description="AI-SOC Lightweight Linux Endpoint Agent for Security Telemetry Collection and Secure Transport."
    )

    subparsers = parser.add_subparsers(dest="command", help="Agent commands")

    subparsers.add_parser("start", parents=[parent_parser], help="Start the aisoc-agent daemon and collectors")
    subparsers.add_parser("register", parents=[parent_parser], help="Register or re-enroll this agent with Central SOC")
    subparsers.add_parser("status", parents=[parent_parser], help="Show local agent operational status and spool backlog")
    subparsers.add_parser("test", parents=[parent_parser], help="Run end-to-end diagnostic and connectivity tests")
    subparsers.add_parser("version", parents=[parent_parser], help="Display agent version")
    subparsers.add_parser("config-check", parents=[parent_parser], help="Validate configuration files and filesystem permissions")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    config = AgentConfig(config_file=args.config)

    handlers = {
        "start": cmd_start,
        "register": cmd_register,
        "status": cmd_status,
        "test": cmd_test,
        "version": cmd_version,
        "config-check": cmd_config_check
    }

    handler = handlers.get(args.command)
    if handler:
        return handler(args, config)
    else:
        parser.print_help()
        return 1

if __name__ == "__main__":
    import threading
    sys.exit(main())
else:
    import threading
