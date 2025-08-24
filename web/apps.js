// Dev local via Netlify CLI: https://docs.netlify.com/api-and-cli-guides/cli-guides/get-started-with-cli/
const API = '/api'
const $ = (s) => document.querySelector(s)
const token = {
  get: () => localStorage.getItem('token'),
  set: (t) => localStorage.setItem('token', t),
  clear: () => localStorage.removeItem('token')
}

function refresh() {
  $('#tokStatus').textContent = token.get() ? '✓ guardado' : '—'
  // Si venimos del callback con ?token=...
  const url = new URL(location.href)
  const t = url.searchParams.get('token')
  if (t) {
    token.set(t)
    url.searchParams.delete('token')
    history.replaceState({}, '', url.toString())
  }
}
refresh()

$('#btnLogin').addEventListener('click', async () => {
  const email = $('#email').value.trim()
  const password = $('#password').value.trim()
  const res = await fetch(`${API}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  })
  const data = await res.json()
  if (res.ok) {
    token.set(data.token)
    alert('Login OK')
  } else alert(data.error || 'Login error')
  refresh()
})

$('#btnLogout').addEventListener('click', () => {
  token.clear()
  refresh()
})

$('#btnMe').addEventListener('click', async () => {
  const res = await fetch(`${API}/auth/me`, {
    headers: { Authorization: 'Bearer ' + token.get() }
  })
  const data = await res.json()
  $('#out').textContent = JSON.stringify(data, null, 2)
})

$('#btnGH').addEventListener('click', () => {
  location.href = `${API}/oauth/github/login`
})
