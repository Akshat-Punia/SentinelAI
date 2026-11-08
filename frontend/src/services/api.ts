import { Alert, SecurityEvent, AlertStats, AnalyticsOverview } from '../types';

const BASE_URL = '/api/v1';

export class SentinelApi {
  private static token: string = '';

  static setToken(token: string) {
    this.token = token;
  }

  private static getHeaders() {
    return {
      'Content-Type': 'application/json',
      ...(this.token ? { Authorization: `Bearer ${this.token}` } : {})
    };
  }

  static async login(username = 'admin', password = 'AdminPassword123!') {
    const res = await fetch(`${BASE_URL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    if (res.ok) {
      const data = await res.json();
      this.token = data.access_token;
      return data;
    }
    return null;
  }

  static async getStats(): Promise<AlertStats> {
    const res = await fetch(`${BASE_URL}/alerts/stats`, { headers: this.getHeaders() });
    return res.json();
  }

  static async getAnalyticsOverview(): Promise<AnalyticsOverview> {
    const res = await fetch(`${BASE_URL}/analytics/overview`, { headers: this.getHeaders() });
    return res.json();
  }

  static async getAlerts(): Promise<Alert[]> {
    const res = await fetch(`${BASE_URL}/alerts?limit=25`, { headers: this.getHeaders() });
    return res.json();
  }

  static async getEvents(): Promise<SecurityEvent[]> {
    const res = await fetch(`${BASE_URL}/events?limit=15`, { headers: this.getHeaders() });
    return res.json();
  }

  static async ingestEvent(payload: Partial<SecurityEvent>) {
    const res = await fetch(`${BASE_URL}/events/ingest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    return res.json();
  }

  static async updateAlertStatus(alertId: number, status: string, comment = '') {
    const res = await fetch(`${BASE_URL}/alerts/${alertId}/status`, {
      method: 'PATCH',
      headers: this.getHeaders(),
      body: JSON.stringify({ status, comment })
    });
    return res.json();
  }

  static async chatAssistant(message: string, alertId?: number) {
    const res = await fetch(`${BASE_URL}/assistant/chat`, {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify({ message, alert_id: alertId })
    });
    return res.json();
  }

  static async analyzeAlert(alertId: number) {
    const res = await fetch(`${BASE_URL}/assistant/analyze/${alertId}`, {
      headers: this.getHeaders()
    });
    return res.json();
  }
}

