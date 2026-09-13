from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict

class AIAnalysisSchema(BaseModel):
    summary: str = Field(..., description="Concise executive and technical summary of the correlated incident")
    attack_type: str = Field(..., description="Primary attack categorization (e.g. SSH Brute Force with Lateral Movement)")
    severity_assessment: str = Field(..., description="Severity evaluation with justification")
    confidence: float = Field(default=0.90, ge=0.0, le=1.0)
    attack_progression: List[str] = Field(default_factory=list, description="Chronological sequence of attacker actions")
    observed_evidence: List[str] = Field(default_factory=list, description="Strictly observed facts directly from telemetry logs")
    hypotheses: List[str] = Field(default_factory=list, description="Plausible threat actor goals and next moves")
    mitre_analysis: List[str] = Field(default_factory=list, description="MITRE ATT&CK technique analysis")
    investigation_steps: List[str] = Field(default_factory=list, description="Prioritized forensic & triage steps")
    containment_recommendations: List[str] = Field(default_factory=list, description="Defensive containment and remediation recommendations")
    model_provider: Optional[str] = None
    created_at: Optional[datetime] = None

    # Dual-compatibility alias fields for frontend
    incident_summary: Optional[str] = None
    likely_attack_type: Optional[str] = None
    evidence: Optional[List[str]] = None
    recommended_investigation_steps: Optional[List[str]] = None
    recommended_containment_steps: Optional[List[str]] = None

    def model_post_init(self, __context: Any) -> None:
        if not self.incident_summary:
            self.incident_summary = self.summary
        if not self.likely_attack_type:
            self.likely_attack_type = self.attack_type
        if self.evidence is None:
            self.evidence = self.observed_evidence
        if self.recommended_investigation_steps is None:
            self.recommended_investigation_steps = self.investigation_steps
        if self.recommended_containment_steps is None:
            self.recommended_containment_steps = self.containment_recommendations


    model_config = ConfigDict(from_attributes=True)
