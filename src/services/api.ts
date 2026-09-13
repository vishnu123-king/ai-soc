import { DashboardStats, Incident, SecurityLog, Alert, DetectionRule, MitreTechnique, AIAnalysis } from '../types';

const API_BASE = '/api';

export async function fetchStats(): Promise<DashboardStats> {
  const res = await fetch(`${API_BASE}/stats`);
  if (!res.ok) throw new Error(`Failed to fetch stats: ${res.statusText}`);
  return res.json();
}

export async function fetchIncidents(params?: { status?: string; severity?: string; host?: string }): Promise<Incident[]> {
  const query = new URLSearchParams();
  if (params?.status && params.status !== 'ALL') query.append('status', params.status);
  if (params?.severity && params.severity !== 'ALL') query.append('severity', params.severity);
  if (params?.host) query.append('host', params.host);

  const res = await fetch(`${API_BASE}/incidents?${query.toString()}`);
  if (!res.ok) throw new Error(`Failed to fetch incidents: ${res.statusText}`);
  return res.json();
}

export async function fetchIncidentDetail(id: number): Promise<Incident> {
  const res = await fetch(`${API_BASE}/incidents/${id}`);
  if (!res.ok) throw new Error(`Failed to fetch incident ${id}: ${res.statusText}`);
  return res.json();
}

export async function updateIncidentStatus(id: number, status: string): Promise<Incident> {
  const res = await fetch(`${API_BASE}/incidents/${id}/status`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status }),
  });
  if (!res.ok) throw new Error(`Failed to update status: ${res.statusText}`);
  return res.json();
}

export async function triggerAIAnalysis(id: number, provider: 'gemini' | 'local_qwen'): Promise<AIAnalysis> {
  const res = await fetch(`${API_BASE}/incidents/${id}/analyze?provider=${provider}`, {
    method: 'POST',
  });
  if (!res.ok) throw new Error(`AI Analysis failed: ${res.statusText}`);
  return res.json();
}

export async function fetchLogs(limit = 100, eventType?: string): Promise<SecurityLog[]> {
  const query = new URLSearchParams({ limit: String(limit) });
  if (eventType && eventType !== 'ALL') query.append('event_type', eventType);
  const res = await fetch(`${API_BASE}/logs?${query.toString()}`);
  if (!res.ok) throw new Error(`Failed to fetch logs: ${res.statusText}`);
  return res.json();
}

export async function ingestLog(logData: Partial<SecurityLog>): Promise<any> {
  const res = await fetch(`${API_BASE}/logs`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(logData),
  });
  if (!res.ok) throw new Error(`Failed to ingest log: ${res.statusText}`);
  return res.json();
}

export async function seedSampleAttack(): Promise<any> {
  const res = await fetch(`${API_BASE}/seed`, { method: 'POST' });
  if (!res.ok) throw new Error(`Failed to seed data: ${res.statusText}`);
  return res.json();
}

export async function resetDatabase(): Promise<any> {
  const res = await fetch(`${API_BASE}/reset`, { method: 'POST' });
  if (!res.ok) throw new Error(`Failed to reset database: ${res.statusText}`);
  return res.json();
}

export async function fetchRules(): Promise<DetectionRule[]> {
  const res = await fetch(`${API_BASE}/rules`);
  if (!res.ok) throw new Error(`Failed to fetch rules: ${res.statusText}`);
  return res.json();
}

export async function fetchMitreCatalog(): Promise<MitreTechnique[]> {
  const res = await fetch(`${API_BASE}/mitre`);
  if (!res.ok) throw new Error(`Failed to fetch MITRE data: ${res.statusText}`);
  return res.json();
}
