import pytest
from aisoc_agent.parsers.ssh import SSHParser
from aisoc_agent.parsers.sudo import SudoParser
from aisoc_agent.parsers.audit import AuditParser
from aisoc_agent.parsers.network import NetworkParser, decode_proc_net_ipv4

def test_ssh_parser_failed_password():
    parser = SSHParser(hostname="srv-prod-01", agent_id="agent-01")
    log_line = "sshd[12345]: Failed password for root from 198.51.100.99 port 54321 ssh2"
    ev = parser.parse_line(log_line)
    
    assert ev is not None
    assert ev.event_type == "authentication"
    assert ev.action == "ssh_login"
    assert ev.status == "failed"
    assert ev.username == "root"
    assert ev.source_ip == "198.51.100.99"
    assert ev.source_port == 54321
    assert ev.destination_port == 22
    assert ev.hostname == "srv-prod-01"
    assert ev.simulation is False

def test_ssh_parser_invalid_user():
    parser = SSHParser(hostname="srv-prod-01", agent_id="agent-01")
    log_line = "sshd[12346]: Invalid user hacker from 203.0.113.50 port 44321"
    ev = parser.parse_line(log_line)
    
    assert ev is not None
    assert ev.event_type == "authentication"
    assert ev.action == "ssh_login"
    assert ev.status == "failed"
    assert ev.username == "hacker"
    assert ev.source_ip == "203.0.113.50"
    assert ev.source_port == 44321

def test_ssh_parser_accepted_login():
    parser = SSHParser(hostname="srv-prod-01", agent_id="agent-01")
    log_line = "sshd[12347]: Accepted publickey for ubuntu from 10.0.4.50 port 51234 ssh2"
    ev = parser.parse_line(log_line)
    
    assert ev is not None
    assert ev.event_type == "authentication"
    assert ev.action == "ssh_login"
    assert ev.status == "success"
    assert ev.username == "ubuntu"
    assert ev.source_ip == "10.0.4.50"
    assert ev.metadata.get("auth_method") == "publickey"

def test_sudo_parser_command_execution():
    parser = SudoParser(hostname="srv-prod-01", agent_id="agent-01")
    log_line = "sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/systemctl restart nginx"
    ev = parser.parse_line(log_line)
    
    assert ev is not None
    assert ev.event_type == "privilege"
    assert ev.action == "sudo_exec"
    assert ev.status == "success"
    assert ev.username == "alice"
    assert ev.command == "/bin/systemctl restart nginx"
    assert ev.metadata.get("target_user") == "root"

def test_sudo_parser_incorrect_password():
    parser = SudoParser(hostname="srv-prod-01", agent_id="agent-01")
    log_line = "sudo:   bob : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/id"
    ev = parser.parse_line(log_line)
    
    assert ev is not None
    assert ev.event_type == "privilege"
    assert ev.action == "sudo_auth"
    assert ev.status == "failed"
    assert ev.username == "bob"

def test_sudo_parser_not_in_sudoers():
    parser = SudoParser(hostname="srv-prod-01", agent_id="agent-01")
    log_line = "sudo:   intruder : user NOT in sudoers ; TTY=pts/2 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash"
    ev = parser.parse_line(log_line)
    
    assert ev is not None
    assert ev.event_type == "privilege"
    assert ev.action == "sudo_exec"
    assert ev.status == "denied"
    assert ev.username == "intruder"
    assert ev.command == "/bin/bash"

def test_audit_parser_execve():
    parser = AuditParser(hostname="srv-prod-01", agent_id="agent-01")
    log_line = 'type=EXECVE msg=audit(1694500000.123:456): argc=3 a0="nc" a1="-e" a2="/bin/bash"'
    ev = parser.parse_line(log_line)
    
    assert ev is not None
    assert ev.event_type == "process"
    assert ev.action == "execve"
    assert ev.status == "success"
    assert "nc -e /bin/bash" in ev.command
    assert ev.process == "nc"

def test_audit_parser_user_auth():
    parser = AuditParser(hostname="srv-prod-01", agent_id="agent-01")
    log_line = 'type=USER_AUTH msg=audit(1694500000.124:457): pid=123 uid=0 auid=1000 ses=2 msg=\'op=PAM:authentication grantors=pam_unix acct="ubuntu" exe="/usr/sbin/sshd" hostname=192.168.1.50 addr=192.168.1.50 res=success\''
    ev = parser.parse_line(log_line)
    
    assert ev is not None
    assert ev.event_type == "authentication"
    assert ev.username == "ubuntu"
    assert ev.status == "success"
    assert ev.source_ip == "192.168.1.50"

def test_network_hex_decoding():
    ip, port = decode_proc_net_ipv4("0100007F:0016")
    assert ip == "127.0.0.1"
    assert port == 22

    # 10.0.4.15 is 0x0F04000A in little-endian hex
    ip2, port2 = decode_proc_net_ipv4("0F04000A:115C")
    assert ip2 == "10.0.4.15"
    assert port2 == 4444
