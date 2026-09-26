import pytest
from runtime.recon.classifier import TargetClassifier
from runtime.recon.planner import ReconPlanner
from runtime.recon.evidence import EvidenceNormalizer
from runtime.recon.waf import WAFHandler
from runtime.recon.stopping import StoppingEngine

def test_target_classification():
    classifier = TargetClassifier()
    assert "WEB" in classifier.classify("https://example.com")
    assert "API" in classifier.classify("https://api.example.com/api/v1/users")
    assert "ANDROID" in classifier.classify("app-release.apk")
    assert "NETWORK" in classifier.classify("192.168.1.1")
    assert "CLOUD" in classifier.classify("test-bucket.s3.amazonaws.com")

def test_recon_planner():
    planner = ReconPlanner()
    action1 = planner.plan("https://example.com", {"WEB"}, [])
    assert action1 == "DNS_ENUM"
    action2 = planner.plan("https://example.com", {"WEB"}, [{"action": "DNS_ENUM"}])
    assert action2 == "HTTP_PROBE"

def test_evidence_normalization_and_dedup():
    norm = EvidenceNormalizer()
    e1, dup1 = norm.normalize({"value": "API.example.com", "type": "DOMAIN"}, "m1")
    e2, dup2 = norm.normalize({"value": "api.example.com/", "type": "DOMAIN"}, "m1")
    
    assert not dup1
    assert dup2
    assert e1["value"] == "api.example.com"
    assert e1["mission_id"] == "m1"
    assert e1["provenance_hash"] == e2["provenance_hash"]

def test_waf_handling():
    waf = WAFHandler()
    assert waf.detect_block({"status_code": 403, "headers": {"cf-ray": "1234"}})
    res = waf.handle_block("https://target.com")
    assert res["status"] == "REPLAN"

def test_stopping_engine():
    engine = StoppingEngine(max_actions=5)
    assert not engine.should_stop(actions_count=2, new_info_gain=True, duplicate_rate=0.1)
    assert engine.should_stop(actions_count=5, new_info_gain=True, duplicate_rate=0.1)
    assert engine.should_stop(actions_count=3, new_info_gain=False, duplicate_rate=0.9)
