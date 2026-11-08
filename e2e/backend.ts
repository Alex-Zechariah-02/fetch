// Builds the programs the browser suites run (the gateway from the APIWard
// checkout beside this repository; the services, Accounts and demo tool from
// this one) from immutable source snapshots, and builds a website folder.
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { appendFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
export { adminURL, controls, httpOrigin, offsetPort, siteURL } from './ports'

// The two checkouts, side by side: this repository and APIWard beside it.
export const fetchRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
export const apiwardRoot = resolve(fetchRoot, '..', 'apiward')
const checkouts = [
  { name: 'apiward', root: apiwardRoot, inputs: ['cmd', 'internal', 'module', 'go.mod', 'go.sum'] },
  { name: 'fetch', root: fetchRoot, inputs: ['cmd', 'internal', 'go.mod', 'go.sum'] },
]
const executable = process.platform === 'win32' ? '.exe' : ''
const temporary: string[] = []

process.on('exit', () => {
  for (const dir of temporary) {
    try {
      rmSync(dir, { recursive: true, force: true })
    } catch {
      // A child may still hold a temporary file; preserve it for inspection.
    }
  }
})

export function temporaryDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  temporary.push(dir)
  return dir
}

function run(command: string, args: string[], cwd: string): string {
  const result = spawnSync(command, args, { cwd, encoding: 'utf8', env: { ...process.env, GIT_OPTIONAL_LOCKS: '0' } })
  if (result.status !== 0) throw new Error(`${command} ${args.join(' ')}: ${result.stderr || result.stdout || result.error}`)
  return result.stdout
}

function digest(data: string | Buffer): string {
  return createHash('sha256').update(data).digest('hex')
}

interface SourceFile {
  path: string
  sha256: string
}

interface BackendIdentity {
  commits: Record<string, string>
  source: 'head' | 'worktree'
  source_sha256: string
  diff_sha256: string
  files: SourceFile[]
}

let builtIdentity: BackendIdentity | undefined

export function gatewayIdentity(): BackendIdentity {
  if (!builtIdentity) throw new Error('build() has not run')
  return builtIdentity
}

interface Snapshot {
  commit: string
  diff: string
  files: SourceFile[]
  recheck: () => void
}

// snapshot copies one checkout's inputs into target: its committed files, or
// in worktree mode its working files, and records every file's digest.
function snapshot(checkout: (typeof checkouts)[number], mode: 'head' | 'worktree', target: string): Snapshot {
  const git = (args: string[], cwd = checkout.root) => run('git', ['--no-optional-locks', ...args], cwd)
  const commit = git(['rev-parse', 'HEAD']).trim()
  const diffArgs = ['diff', '--no-ext-diff', '--binary', commit, '--', ...checkout.inputs]
  const diff = mode === 'worktree' ? git(diffArgs) : ''
  const selectedPaths = () => (mode === 'head'
    ? git(['ls-tree', '-rz', '--name-only', commit, '--', ...checkout.inputs])
    : git(['ls-files', '-z', '--cached', '--others', '--exclude-standard', '--', ...checkout.inputs]))
    .split('\0').filter((path) => path !== '' && (mode === 'head' || existsSync(join(checkout.root, path)))).sort()
  const paths = selectedPaths()
  mkdirSync(target, { recursive: true })
  if (mode === 'head') {
    git(['archive', '--format=tar', '-o', join(target, 'head.tar'), commit, '--', ...checkout.inputs])
    run('tar', ['-xf', 'head.tar'], target)
  }
  const files = paths.map((path) => {
    const data = readFileSync(join(mode === 'head' ? target : checkout.root, path))
    if (mode === 'worktree') {
      const copy = join(target, path)
      mkdirSync(dirname(copy), { recursive: true })
      writeFileSync(copy, data)
    }
    return { path: `${checkout.name}/${path}`, sha256: digest(data) }
  })
  const recheck = () => {
    if (mode === 'worktree' && (
      diff !== git(diffArgs) ||
      JSON.stringify(paths) !== JSON.stringify(selectedPaths()) ||
      paths.some((path, i) => digest(readFileSync(join(checkout.root, path))) !== files[i].sha256)
    )) throw new Error(`${checkout.name} source changed during the snapshot; build was refused`)
    if (commit !== git(['rev-parse', 'HEAD']).trim()) throw new Error(`${checkout.name} HEAD changed during the snapshot`)
  }
  return { commit, diff, files, recheck }
}

// Both modes compile an isolated immutable snapshot. The default retains the
// clean committed-source workflow; worktree mode explicitly includes local
// backend changes and records every input file, never just a commit label.
export function build(): string {
  const mode = process.env.E2E_BACKEND_SOURCE ?? 'head'
  if (mode !== 'head' && mode !== 'worktree') throw new Error('E2E_BACKEND_SOURCE must be head or worktree')
  if (!existsSync(join(apiwardRoot, 'cmd', 'gateway'))) throw new Error(`${apiwardRoot} is not an APIWard checkout: clone github.com/Alex-Zechariah-02/apiward beside this repository`)
  const source = temporaryDir('gateway-e2e-src-')
  const bin = temporaryDir('gateway-e2e-bin-')
  const snapshots = checkouts.map((checkout) => snapshot(checkout, mode, join(source, checkout.name)))
  for (const taken of snapshots) taken.recheck()
  const files = snapshots.flatMap((taken) => taken.files)
  const identity: BackendIdentity = {
    commits: Object.fromEntries(checkouts.map((checkout, i) => [checkout.name, snapshots[i].commit])),
    source: mode,
    source_sha256: digest(JSON.stringify(files)),
    diff_sha256: digest(snapshots.map((taken) => taken.diff).join('')),
    files,
  }
  const programs = [
    { name: 'gateway', dir: 'apiward', args: ['./cmd/gateway'] },
    { name: 'services', dir: 'fetch', args: ['./cmd/services'] },
    { name: 'accounts', dir: 'fetch', args: ['./cmd/accounts'] },
    { name: 'demo', dir: 'fetch', args: ['./cmd/demo'] },
    { name: 'gateway-fault', dir: 'apiward', args: ['-tags', 'faultinject', './cmd/gateway'] },
  ]
  try {
    for (const program of programs) run('go', ['build', '-trimpath', '-o', join(bin, program.name + executable), ...program.args], join(source, program.dir))
    writeFileSync(join(bin, 'source.json'), JSON.stringify(identity, null, 2))
    if (process.env.E2E_EVIDENCE) appendFileSync(process.env.E2E_EVIDENCE, JSON.stringify({ kind: 'backend-build', ...identity }) + '\n')
    builtIdentity = identity
    return bin
  } finally {
    rmSync(source, { recursive: true, force: true })
  }
}

// buildApplication builds the website in folder (an absolute path) for
// production and returns its dist folder.
export function buildApplication(folder: string): string {
  const shell = (command: string, env: NodeJS.ProcessEnv = process.env) => {
    const result = spawnSync(command, { cwd: folder, encoding: 'utf8', shell: true, env })
    if (result.status !== 0) throw new Error(`${command}: ${result.stderr || result.stdout || result.error}`)
  }
  if (!existsSync(join(folder, 'node_modules'))) shell('npm ci --prefer-offline --no-audit --no-fund')
  // A Vite dev server started earlier in this process sets NODE_ENV to
  // development, which would make this a development build of React.
  shell('npm run build', { ...process.env, NODE_ENV: 'production' })
  return join(folder, 'dist')
}
