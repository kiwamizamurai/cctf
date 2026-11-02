import { atom, read, update } from 'claude-code'
import type { EngineInterface, Register } from 'claude-code'

// Live HUD for the autonomous CTF harness. Reads the harness state the solver
// writes via ctf_state.py:
//   .claude/state/ctf/queue.json     { challenges: { slug: {status, flag, ...} } }
//   .claude/state/ctf/ledger.ndjson  one JSON decision record per line
// and draws a dashboard pane. No harness writes are done here — read only.

const PANE = 'ctf-harness-hud'
const QUEUE = '.claude/state/ctf/queue.json'
const LEDGER = '.claude/state/ctf/ledger.ndjson'

// a tick we bump on a timer so the pane redraws with fresh state
const tick = atom({ plugin: 'ctf-harness-hud', key: 'tick' } as const, 0)

type Challenge = {
  slug: string
  category?: string
  difficulty?: string
  status: string
  flag?: string
  date?: string
  updated?: string
  notes?: string[]
}
type Queue = { challenges: Record<string, Challenge> }
type Ledger = { t: string; event: string; slug?: string; data?: Record<string, unknown> }

type Dollar = EngineInterface

const STATUS_ORDER = ['solving', 'stuck', 'todo', 'solved', 'skip']
const COLOR: Record<string, string> = {
  solved: 'green',
  solving: 'cyan',
  stuck: 'yellow',
  todo: 'gray',
  skip: 'magenta',
}
const MARK: Record<string, string> = {
  solved: '✓',
  solving: '▸',
  stuck: '✗',
  todo: '·',
  skip: '-',
}

async function readQueue($: Dollar): Promise<Queue | null> {
  try {
    const raw = await $.fs.read(QUEUE)
    const q = JSON.parse(raw)
    return q && q.challenges ? q : { challenges: {} }
  } catch {
    return null
  }
}

async function readLedger($: Dollar, last = 8): Promise<Ledger[]> {
  try {
    const raw = await $.fs.read(LEDGER)
    const lines = raw.split('\n').filter(l => l.trim())
    return lines
      .slice(-last)
      .map(l => {
        try {
          return JSON.parse(l) as Ledger
        } catch {
          return null
        }
      })
      .filter((x): x is Ledger => x !== null)
      .reverse()
  } catch {
    return []
  }
}

function counts(list: Challenge[]) {
  const c: Record<string, number> = {}
  for (const ch of list) c[ch.status] = (c[ch.status] || 0) + 1
  return c
}

function bar(done: number, total: number, width: number) {
  if (total <= 0) return '░'.repeat(width)
  const filled = Math.round((done / total) * width)
  return '█'.repeat(filled) + '░'.repeat(Math.max(0, width - filled))
}

function byCategory(list: Challenge[]) {
  const m: Record<string, { solved: number; total: number }> = {}
  for (const ch of list) {
    const k = ch.category || '—'
    const e = (m[k] = m[k] || { solved: 0, total: 0 })
    e.total++
    if (ch.status === 'solved') e.solved++
  }
  return Object.entries(m).sort((a, b) => b[1].total - a[1].total)
}

function hhmm(t?: string) {
  if (!t) return ''
  const m = /T(\d{2}:\d{2})/.exec(t)
  return m ? m[1] : t.slice(-8, -3)
}

export const register: Register = on => {
  let lastSolved = -1

  on('session.start', async ($, e, next) => {
    await $.command.register({
      name: 'ctf-hud',
      description: 'Open the autonomous CTF harness HUD (progress, flags, stuck, activity)',
    })
    void $.ui.open({ id: PANE, title: 'CTF Harness HUD' })
    const now = await $.clock.now()
    await update($, tick, () => now)
    $.clock.every(2000, async () => {
      const t = await $.clock.now()
      await update($, tick, () => t)
      // status line + toast on a newly captured flag
      const q = await readQueue($)
      if (q) {
        const list = Object.values(q.challenges)
        const solved = list.filter(c => c.status === 'solved').length
        $.ui.status(`⚑ CTF ${solved}/${list.length}`)
        if (lastSolved >= 0 && solved > lastSolved) {
          const latest = list
            .filter(c => c.status === 'solved' && c.flag)
            .sort((a, b) => (a.updated || '').localeCompare(b.updated || ''))
            .at(-1)
          if (latest) $.ui.toast(`🚩 solved ${latest.slug}: ${latest.flag}`)
        }
        lastSolved = solved
      }
    })
    return next(e)
  })

  on('command.run', { command: 'ctf-hud' }, async $ => {
    await $.ui.open({ id: PANE, title: 'CTF Harness HUD' })
    return { text: 'CTF Harness HUD opened.' }
  })

  on('ui.render', { component: 'Pane', requestId: PANE }, async ($, e) => {
    const { Box, Text } = $.ui.resolve(e)
    await read($, tick) // subscribe: redraw when the timer bumps the tick

    const width = Math.max(24, (e.props.bodyColumns ?? 48) - 2)
    const rows = Math.max(8, (e.viewport?.rows ?? 24) - 2)

    const q = await readQueue($)
    if (!q) {
      return (
        <Box flexDirection="column">
          <Text bold color="cyan">⚑ CTF HARNESS HUD</Text>
          <Text dimColor>No harness state yet.</Text>
          <Text dimColor>Run the loop; it writes .claude/state/ctf/queue.json.</Text>
        </Box>
      )
    }

    const list = Object.values(q.challenges)
    const c = counts(list)
    const total = list.length
    const solved = c.solved || 0
    const remaining = (c.todo || 0) + (c.solving || 0) + (c.stuck || 0)
    const pct = total ? Math.round((solved / total) * 100) : 0
    const current = list.filter(x => x.status === 'solving')
    const stuck = list.filter(x => x.status === 'stuck')
    const recentFlags = list
      .filter(x => x.status === 'solved' && x.flag)
      .sort((a, b) => (b.updated || '').localeCompare(a.updated || ''))
      .slice(0, 5)
    const cats = byCategory(list)
    const ledger = await readLedger($, 6)

    const flagW = Math.max(8, width - 18)

    return (
      <Box flexDirection="column">
        <Text bold color="cyan">⚑ CTF HARNESS HUD</Text>

        {/* progress */}
        <Text>
          <Text color="green" bold>{solved}</Text>
          <Text dimColor>/{total} solved </Text>
          <Text color="green">{bar(solved, total, Math.min(24, width - 16))}</Text>
          <Text dimColor> {pct}%</Text>
        </Text>
        <Text dimColor>
          remaining {remaining}  ·  stuck {c.stuck || 0}  ·  solving {c.solving || 0}  ·  todo {c.todo || 0}
        </Text>

        {/* by category */}
        <Text bold> by category</Text>
        {cats.map(([name, s]) => (
          <Text>
            {' '}
            <Text color={s.solved === s.total ? 'green' : 'white'}>
              {s.solved}/{s.total}
            </Text>
            <Text dimColor> {name}</Text>
          </Text>
        ))}

        {/* current */}
        <Text bold> in progress</Text>
        {current.length === 0 && <Text dimColor> (none)</Text>}
        {current.map(ch => (
          <Text color="cyan">
            {' '}▸ {ch.slug}
            <Text dimColor> {ch.category || ''} {ch.difficulty || ''}</Text>
          </Text>
        ))}

        {/* recent flags */}
        <Text bold> recent flags</Text>
        {recentFlags.length === 0 && <Text dimColor> (none yet)</Text>}
        {recentFlags.map(ch => (
          <Text>
            {' '}<Text color="green">🚩</Text> <Text dimColor>{ch.slug.slice(0, 16)}</Text>{' '}
            <Text color="green">{(ch.flag || '').slice(0, flagW)}</Text>
          </Text>
        ))}

        {/* stuck */}
        {stuck.length > 0 && (
          <>
            <Text bold color="yellow"> stuck</Text>
            {stuck.slice(0, 4).map(ch => (
              <Text color="yellow">
                {' '}✗ {ch.slug}
                <Text dimColor> {ch.notes && ch.notes.length ? '— ' + ch.notes.at(-1)!.slice(0, width - 10) : ''}</Text>
              </Text>
            ))}
          </>
        )}

        {/* activity */}
        <Text bold> activity</Text>
        {ledger.length === 0 && <Text dimColor> (empty)</Text>}
        {ledger.map(r => (
          <Text dimColor>
            {' '}{hhmm(r.t)} {r.event}
            {r.slug ? ' ' + r.slug.slice(0, width - 22) : ''}
          </Text>
        ))}
      </Box>
    )
  })
}
