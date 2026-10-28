#!/usr/bin/env node
/**
 * Build a clean, GitHub-web-uploadable snapshot of this project.
 *
 * Why: the working directory also contains DSH runtime/user data
 * (.dsh-group/, own/, shared/, backup/) that may hold the room password,
 * shared files and plaintext backup history. Those must never be uploaded.
 *
 * Usage (from the repository root):
 *   node scripts/export-github.mjs [destination]
 *
 * Default destination: <repo>/github-upload
 * The destination is only deleted/replaced when it carries this script's
 * marker file, so pointing the script at the wrong folder is refused.
 */
import { existsSync } from 'node:fs'
import { cp, mkdir, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const repoRoot = path.resolve(here, '..')
const destination = path.resolve(process.argv[2] ?? path.join(repoRoot, 'github-upload'))
// Ownership marker lives OUTSIDE the exported folder so it is never uploaded.
const markerPath = path.join(repoRoot, '.github-upload.marker.json')

const COPY_FILES = [
  'README.md',
  'LICENSE',
  'CHANGELOG.md',
  '.gitignore',
  '.gitattributes',
  'DESIGN.md',
  'SECURITY.md',
  'VERIFICATION.md',
]
const COPY_DIRS = ['group-collab', '.github', 'scripts']
const EXCLUDED_DIR_NAMES = new Set(['node_modules', '.git', '.dsh-group', 'github-upload'])
// Runtime/user folders must never leak even if a future layout puts them inside the bundle.
const EXCLUDED_TOP_NAMES = new Set(['own', 'shared', 'backup'])

// Values of real local room passwords from the development session that must never
// appear in a published snapshot (add more here if you rotate them). Fragments are
// joined at runtime so this script never contains the literals it scans for.
const SECRET_PATTERNS = [
  new RegExp(['Gc', '-2v', '-Secure'].join('')),
  new RegExp(['Group', 'Demo', '2026'].join('')),
]

const isInside = (parent, child) => {
  const relative = path.relative(parent, child)
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative))
}

async function assertSafeDestination() {
  if (destination === repoRoot || !isInside(repoRoot, destination)) {
    throw new Error(`拒绝导出到仓库外或仓库根目录: ${destination}`)
  }
  if (!existsSync(destination)) return
  let marker
  try {
    marker = JSON.parse(await readFile(markerPath, 'utf8'))
  } catch {
    marker = undefined
  }
  if (marker === undefined || path.resolve(marker.destination ?? '') !== destination) {
    throw new Error(
      `目标目录已存在且不是本脚本生成的快照（缺少或无效的 ${markerPath}），拒绝覆盖: ${destination}\n` +
        '请手动确认并删除该目录，或指定另一个目标路径。',
    )
  }
}

function copyFilter(source) {
  const name = path.basename(source)
  if (EXCLUDED_DIR_NAMES.has(name)) return false
  if (EXCLUDED_TOP_NAMES.has(name)) return false
  if (name.endsWith('.log') || name.endsWith('.tmp')) return false
  return true
}

async function walk(dir) {
  const out = []
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) out.push(...(await walk(full)))
    else out.push(full)
  }
  return out
}

async function scanForSecrets(root) {
  const hits = []
  for (const file of await walk(root)) {
    const info = await stat(file)
    if (info.size > 2 * 1024 * 1024) continue
    let text
    try {
      text = await readFile(file, 'utf8')
    } catch {
      continue // binary/unreadable files are copied as-is
    }
    for (const pattern of SECRET_PATTERNS) {
      if (pattern.test(text)) hits.push(`${path.relative(repoRoot, file)} matches ${pattern}`)
    }
    if (path.basename(file) === 'member.json' || /^rooms[\\/].*\.json$/u.test(path.relative(root, file))) {
      hits.push(`runtime data file present: ${path.relative(repoRoot, file)}`)
    }
  }
  return hits
}

async function main() {
  await assertSafeDestination()
  await rm(destination, { recursive: true, force: true })
  await mkdir(destination, { recursive: true })

  for (const file of COPY_FILES) {
    const source = path.join(repoRoot, file)
    if (!existsSync(source)) throw new Error(`缺少文件: ${file}`)
    await cp(source, path.join(destination, file))
  }
  for (const dir of COPY_DIRS) {
    const source = path.join(repoRoot, dir)
    if (!existsSync(source)) throw new Error(`缺少目录: ${dir}`)
    await cp(source, path.join(destination, dir), { recursive: true, filter: copyFilter })
  }

  const hits = await scanForSecrets(destination)
  if (hits.length > 0) {
    await rm(destination, { recursive: true, force: true })
    throw new Error(`敏感信息扫描失败，已删除导出目录:\n- ${hits.join('\n- ')}`)
  }

  const files = await walk(destination)
  let bytes = 0
  for (const file of files) bytes += (await stat(file)).size
  await writeFile(
    markerPath,
    `${JSON.stringify({ destination, generatedAt: new Date().toISOString(), source: repoRoot, fileCount: files.length }, null, 2)}\n`,
    'utf8',
  )
  console.log(`exported ${files.length} files (${bytes} bytes) -> ${destination}`)
  console.log('next: upload this folder\'s contents to GitHub (Add file -> Upload files), or git init inside it.')
}

main().catch((error) => {
  console.error(`export-github failed: ${error instanceof Error ? error.message : String(error)}`)
  process.exitCode = 1
})
