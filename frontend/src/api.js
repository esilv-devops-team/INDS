export async function api(path, options = {}) {
  const response = await fetch(path, {
    method: options.method || 'GET',
    headers: options.body ? { 'Content-Type': 'application/json' } : {},
    body: options.body ? JSON.stringify(options.body) : undefined,
    credentials: 'same-origin',
  })

  const data = await response.json().catch(() => null)
  if (!response.ok) {
    const error = new Error(data?.error?.message || 'Request failed')
    error.status = response.status
    throw error
  }
  return data
}