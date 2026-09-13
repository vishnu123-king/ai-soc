export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type IncidentStatus = 'OPEN' | 'INVESTIGATING' | 'CONTAINED' | 'CLOSED';

export interface SecurityLog {
  id: number;
  timestamp: string;
  hostname: string;
  source_ip?: string;
  destination_ip?: string;
  username?: string;
  event_type: string;
  action?: string;
  status: string;
  process?: string;
  command?: string;
  raw_message: string;
  metadata?: Record<string, any>;
}

export interface Alert {
  id: number;
  rule_id: string;
  rule_name: string;
  severity: Severity;
  timestamp: string;
  hostname: string;
  source_ip?: string;
  destination_ip?: string;
  username?: string;
  mitre_technique_id?: string;
  mitre_technique_name?: string;
  description: string;
  evidence: any[];
  incident_id?: number;
}

export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
  description?: string;
}

export interface AIAnalysis {
  incident_summary: string;
  likely_attack_type: string;
  severity_assessment: string;
  confidence: number;
  attack_progression: string[];
  evidence: string[];
  mitre_techniques: string[];
  recommended_investigation_steps: string[];
  recommended_containment_steps: string[];
  model_provider?: string;
  analyzed_at?: string;
}

export interface Incident {
  id: number;
  title: string;
  severity: Severity;
  status: IncidentStatus;
  risk_score: number;
  risk_explanation: string;
  affected_host: string;
  source_ip?: string;
  username?: string;
  mitre_techniques: MitreTechnique[];
  created_at: string;
  updated_at: string;
  ai_model_used?: string;
  ai_analyzed_at?: string;
  alerts?: Alert[];
  ai_analysis?: AIAnalysis;
}

export interface DashboardStats {
  total_events: number;
  total_alerts: number;
  active_incidents: number;
  critical_incidents: number;
  high_incidents: number;
  medium_incidents: number;
  low_incidents: number;
  security_score: number;
  threat_distribution: { name: string; count: number }[];
  timeline_stats: { time: string; events: number; alerts: number }[];
  recent_alerts: Alert[];
}

export interface DetectionRule {
  rule_id: string;
  rule_name: string;
  severity: Severity;
  mitre_technique_id: string;
  mitre_technique_name: string;
}
