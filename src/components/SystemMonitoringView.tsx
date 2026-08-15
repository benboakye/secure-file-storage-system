import { useEffect, useState } from 'react'
import { Activity, AlertTriangle, Archive, CheckCircle2, Clock3, Database, HardDrive, Link2, LockKeyhole, ScanSearch, Server, ShieldAlert, ShieldCheck } from 'lucide-react'
import { getAdminMonitoring, type AdminMonitoringSummary } from '../apiClient'

export function SystemMonitoringView() {
  const [summary, setSummary] = useState<AdminMonitoringSummary | null>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    let cancelled = false
    getAdminMonitoring()
      .then((result) => { if (!cancelled) setSummary(result) })
      .catch((requestError) => { if (!cancelled) setError(requestError instanceof Error ? requestError.message : 'System monitoring could not be loaded.') })
    return () => { cancelled = true }
  }, [])

  return <div className="admin-dashboard-view admin-monitoring-view">
    <header className="admin-dashboard-header">
      <div><p className="kicker">System monitoring &amp; global controls</p><h1>Service operations</h1><p>Monitor live service signals and effective policy without exposing infrastructure credentials or internal storage paths.</p></div>
      <div className="admin-domain-status"><Activity size={21} /><span><small>API status</small><strong>{summary?.api.status === 'operational' ? 'Operational' : 'Loading health'}</strong></span></div>
    </header>

    {error ? <div className="admin-dashboard-error" role="alert">{error}</div> : null}
    {summary?.audit.alerts.length ? <section className="audit-alert-stack" aria-label="Active monitoring alerts">{summary.audit.alerts.map((alert) => <article key={alert.id} className={`audit-alert ${alert.severity}`}><ShieldAlert size={20} /><span><strong>{alert.title}</strong><p>{alert.detail}</p></span><b>{alert.count}</b></article>)}</section> : null}

    <section className="admin-resource-stat-grid" aria-label="Operational statistics">
      <MonitoringStat Icon={Clock3} label="API uptime" value={summary ? formatDuration(summary.uptimeSeconds) : '—'} detail="Current process lifetime" />
      <MonitoringStat Icon={Activity} label="Processing queue" value={summary ? String(summary.worker.pendingProcessing) : '—'} detail={`${summary?.worker.mode ?? 'Loading'} worker`} />
      <MonitoringStat Icon={HardDrive} label="Quarantine usage" value={summary ? formatBytes(summary.quarantine.bytes) : '—'} detail={summary ? `${summary.quarantine.orphanedObjects} orphaned object${summary.quarantine.orphanedObjects === 1 ? '' : 's'}` : 'Loading disk measurement'} />
      <MonitoringStat Icon={AlertTriangle} label="Failed records" value={summary ? String(summary.worker.failedRecords) : '—'} detail="Durable lifecycle failures" />
    </section>

    <section className="monitoring-layout">
      <div className="admin-dashboard-panel">
        <div className="admin-dashboard-panel-heading"><div><span>Live dependencies</span><h2>Service status</h2></div><strong className="posture-state connected">Server confirmed</strong></div>
        <div className="monitoring-service-list">
          <Service Icon={Server} name="HTTP API" detail="Health endpoint and privileged request path" connected={summary?.api.status === 'operational'} label="Operational" />
          <Service Icon={Database} name="Authentication database" detail={summary ? `${summary.persistence.authentication.driver} identity and session repository` : 'Loading persistence driver'} connected={summary?.persistence.authentication.durable ?? false} label={summary?.persistence.authentication.durable ? 'Durable' : 'Runtime only'} />
          <Service Icon={Archive} name="Ingestion metadata" detail="Upload lifecycle, quota, and idempotency records" connected={summary?.persistence.ingestionDurable ?? false} label={summary?.persistence.ingestionDurable ? 'Durable' : 'Runtime only'} />
          <Service Icon={Activity} name="Inspection worker" detail={`${summary?.worker.pendingProcessing ?? 0} records awaiting a terminal decision`} connected={Boolean(summary)} label={summary ? 'In process' : 'Loading'} />
          <Service Icon={ScanSearch} name="Content inspection" detail={summary?.scanner.detail ?? 'Loading scanner capability'} connected={summary?.scanner.connected ?? false} label={scannerStatusLabel(summary?.scanner)} partial={!summary?.scanner.productionReady} />
          <Service Icon={Link2} name="Audit integrity" detail={summary ? `${summary.audit.eventCount} chained events; ${summary.audit.anchor.anchoredThrough} externally anchored` : 'Verifying ordered audit evidence'} connected={Boolean(summary?.audit.integrityValid && summary.audit.pendingEvidence === 0 && summary.audit.anchor.valid)} label={summary?.audit.integrityValid && summary.audit.pendingEvidence === 0 && summary.audit.anchor.valid ? 'Verified' : 'Attention required'} partial={!summary?.audit.anchor.productionReady} />
        </div>
      </div>

      <aside className="monitoring-side">
        <section className="admin-dashboard-panel">
          <div className="admin-dashboard-panel-heading"><div><span>Effective configuration</span><h2>Global policy</h2></div></div>
          <dl className="monitoring-policy-list">
            <Policy label="Maximum upload" value={summary ? formatBytes(summary.policies.ingestion.maxUploadBytes) : '—'} />
            <Policy label="Default user quota" value={summary ? formatBytes(summary.policies.ingestion.defaultOwnerQuotaBytes) : '—'} />
			<Policy label="Enforced storage pool" value={summary ? formatBytes(summary.policies.ingestion.storageCapacityBytes) : '—'} />
			<Policy label="Capacity safety reserve" value={summary ? formatBytes(summary.policies.ingestion.storageReserveBytes) : '—'} />
            <Policy label="Reservation lifetime" value={summary ? formatDuration(summary.policies.ingestion.reservationTtlSeconds) : '—'} />
			<Policy label="Metrics exporter" value={summary ? (summary.telemetry.exporterEnabled ? 'Bearer protected' : 'Disabled') : '—'} />
			<Policy label="Successful scrapes" value={summary ? String(summary.telemetry.scrapesTotal) : '—'} />
			<Policy label="Last metrics scrape" value={summary?.telemetry.lastScrapeAt ? formatTimestamp(summary.telemetry.lastScrapeAt) : 'No recent scrape'} />
            <Policy label="Inspection timeout" value={summary ? `${summary.policies.ingestion.inspectionTtlSeconds} seconds` : '—'} />
            <Policy label="Session lifetime" value={summary ? formatDuration(summary.policies.sessionTtlSeconds) : '—'} />
            <Policy label="Allowed web origins" value={summary ? String(summary.policies.allowedOrigins) : '—'} />
            <Policy label="Secure cookies" value={summary ? (summary.policies.secureCookies ? 'Required' : 'Disabled for localhost') : '—'} />
            <Policy label="Deployment profile" value={summary?.policies.deploymentMode ?? '—'} />
            <Policy label="API transport" value={summary ? (summary.policies.httpsRequired ? 'HTTPS required' : 'Local HTTP permitted') : '—'} />
          </dl>
        </section>
        <section className="admin-dashboard-panel">
          <div className="admin-dashboard-panel-heading"><div><span>Observability</span><h2>Integration status</h2></div></div>
          <div className="security-gap-list">
			<Gap Icon={Activity} label="External telemetry" connected={summary?.telemetry.connected ?? false} />
            <Gap Icon={Archive} label="Backup monitoring" connected={summary?.backupMonitoringConnected ?? false} />
            <Gap Icon={LockKeyhole} label="Managed key custody" connected={summary?.keyService.productionReady ?? false} />
            <Gap Icon={Link2} label="Independent audit anchor" connected={Boolean(summary?.audit.anchor.productionReady && summary.audit.anchor.valid)} />
          </div>
        </section>
        <section className="admin-dashboard-panel">
          <div className="admin-dashboard-panel-heading"><div><span>Security signals</span><h2>Last 24 hours</h2></div></div>
          <dl className="monitoring-policy-list">
            <Policy label="Audit events" value={summary ? String(summary.audit.eventsLast24Hours) : '—'} />
            <Policy label="Denied operations" value={summary ? String(summary.audit.deniedLast24Hours) : '—'} />
            <Policy label="High-risk events" value={summary ? String(summary.audit.highRiskLast24Hours) : '—'} />
            <Policy label="Pending evidence" value={summary ? String(summary.audit.pendingEvidence) : '—'} />
            <Policy label="Active alerts" value={summary ? String(summary.audit.alerts.length) : '—'} />
          </dl>
        </section>
      </aside>
    </section>

    <div className="admin-dashboard-notice"><ShieldCheck size={20} /><span><strong>{summary?.policies.deploymentMode === 'production' ? 'Production transport policy' : 'Local development boundary'}</strong><p>{summary?.policies.deploymentMode === 'production' ? 'HTTPS, secure cookies, verified PostgreSQL transport, remote security providers, and externally sourced core secrets were required before this process started.' : 'Secure cookies are disabled only because this instance runs over local HTTP. Production mode refuses to start without HTTPS and the approved remote security boundaries.'}</p></span></div>
  </div>
}

function MonitoringStat({ Icon, label, value, detail }: { Icon: typeof Activity; label: string; value: string; detail: string }) {
  return <article><span><Icon size={20} /></span><small>{label}</small><strong>{value}</strong><p>{detail}</p></article>
}

function Service({ Icon, name, detail, connected, label, partial = false }: { Icon: typeof Server; name: string; detail: string; connected: boolean; label: string; partial?: boolean }) {
  return <div><span className={connected ? 'monitoring-service-icon connected' : 'monitoring-service-icon'}>{connected ? <CheckCircle2 size={18} /> : <Icon size={18} />}</span><span><strong>{name}</strong><small>{detail}</small></span><em className={`posture-state ${connected && !partial ? 'connected' : partial ? 'partial' : 'pending'}`}>{label}</em></div>
}

function Policy({ label, value }: { label: string; value: string }) {
  return <div><dt>{label}</dt><dd>{value}</dd></div>
}

function Gap({ Icon, label, connected }: { Icon: typeof Activity; label: string; connected: boolean }) {
  return <div><Icon size={17} /><strong>{label}</strong><span className={`posture-state ${connected ? 'connected' : 'pending'}`}>{connected ? 'Connected' : 'Not connected'}</span></div>
}

function formatBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let value = bytes / 1024
  let unit = 0
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit += 1 }
  return `${value >= 10 ? value.toFixed(1) : value.toFixed(2)} ${units[unit]}`
}

function formatDuration(seconds: number) {
  if (seconds < 60) return `${seconds}s`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`
  return `${Math.floor(seconds / 86400)}d ${Math.floor((seconds % 86400) / 3600)}h`
}

function formatTimestamp(value: string) {
	return new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit', second: '2-digit' }).format(new Date(value))
}

function scannerStatusLabel(scanner: AdminMonitoringSummary['scanner'] | undefined) {
  if (!scanner) return 'Loading'
  if (scanner.productionReady) return 'Production ready'
  if (scanner.connected && scanner.adapter === 'clamd-instream') return 'Signature attention'
  return scanner.connected ? 'Development adapter' : 'Unavailable'
}
