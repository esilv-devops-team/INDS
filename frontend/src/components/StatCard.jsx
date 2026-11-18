export default function StatCard({ label, value, note, color }) {
  return (
    <div className="stat-card">
      <span className="stat-label">{label}</span>
      <strong className="stat-value" style={color ? { color } : undefined}>{value}</strong>
      {note && <span className="stat-note">{note}</span>}
    </div>
  )
}