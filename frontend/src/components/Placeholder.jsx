export default function Placeholder({ story, text }) {
  return (
    <section className="panel placeholder">
      <h2>Not built yet</h2>
      <p>{text}</p>
      <p className="muted">Planned in {story}.</p>
    </section>
  )
}