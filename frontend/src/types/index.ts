export interface Alert {
  id: number;
  event_id?: number;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  status: 'NEW' | 'INVESTIGATING' | 'RESOLVED' | 'FALSE_POSITIVE';
  risk_score: number;
  rule_triggered: string;
  ai_explanation?: string;
  recommended_action?: string;
  created_at: string;
  updated_at: string;
}

export interface SecurityEvent {
  id: number;
  event_type: string;
  source_ip: string;
  user_identifier?: string;
  location?: string;
  device_info?: string;
  failed_attempts: number;
  timestamp: string;
}

export interface AlertStats {
  total_alerts: number;
  open_alerts: number;
  investigating_alerts: number;
  resolved_alerts: number;
  critical_alerts: number;
  high_alerts: number;
  medium_alerts: number;
  low_alerts: number;
}

export interface AnalyticsOverview {
  total_events_ingested: number;
  failed_logins: number;
  total_alerts: number;
  resolved_alerts: number;
  resolution_rate_percent: number;
  average_alert_risk_score: number;
}
