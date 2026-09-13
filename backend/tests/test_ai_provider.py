import asyncio
from backend.app.ai import analyze_incident_safely
from backend.app.ai.mock import MockAIProvider

def test_mock_ai_provider_structure():
    async def _run():
        provider = MockAIProvider()
        incident_context = {
            "id": 1,
            "title": "Correlated Multi-Vector Attack",
            "severity": "CRITICAL",
            "hostname": "test-host",
            "source_ip": "198.51.100.42",
            "username": "root",
            "detections": [
                {"rule_id": "RULE-AUTH-001", "title": "SSH Brute Force", "severity": "HIGH"},
                {"rule_id": "RULE-PROC-001", "title": "Reverse Shell", "severity": "CRITICAL"}
            ],
            "events": [
                {"timestamp": "2026-09-12T00:00:00", "action": "ssh_login", "status": "failed", "username": "root"}
            ]
        }

        analysis = await provider.analyze_incident(incident_context)
        assert analysis.summary != ""
        assert len(analysis.observed_evidence) >= 1
        assert len(analysis.hypotheses) >= 1
        assert len(analysis.containment_recommendations) >= 1
        assert analysis.confidence >= 0.85
    
    asyncio.run(_run())

def test_safe_ai_fallback():
    async def _run():
        # If API key is not present or primary LLM fails, safe fallback must return valid analysis
        incident_context = {
            "id": 2,
            "title": "Reconnaissance Alert",
            "severity": "MEDIUM",
            "hostname": "test-host-2",
            "source_ip": "198.51.100.43",
            "username": "admin",
            "detections": [],
            "events": []
        }
        analysis = await analyze_incident_safely(incident_context)
        assert analysis is not None
        assert analysis.summary != ""

    asyncio.run(_run())
