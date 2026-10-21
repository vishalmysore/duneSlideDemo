/**
 * vfs.js — in-memory filesystem with symlinks. Nothing here touches a real disk.
 *
 * Every node is { type: 'file' | 'link', ... }. Paths are absolute POSIX strings.
 * realpath() can fail the way real canonicalizers fail (loops, unreadable
 * targets), which is exactly the case a harness has to decide how to handle.
 */

export const WORKSPACE = '/workspace'

export function normalize(p) {
  const parts = []
  for (const seg of p.split('/')) {
    if (!seg || seg === '.') continue
    if (seg === '..') parts.pop()
    else parts.push(seg)
  }
  return '/' + parts.join('/')
}

export function join(base, rel) {
  return rel.startsWith('/') ? normalize(rel) : normalize(base + '/' + rel)
}

export function isInside(path, root = WORKSPACE) {
  return path === root || path.startsWith(root + '/')
}

export class CanonicalizeError extends Error {
  constructor(code, path) {
    super(`${code}: cannot canonicalize ${path}`)
    this.code = code
    this.path = path
  }
}

export class VFS {
  constructor() {
    this.nodes = new Map()
    this.unreadable = new Set() // paths whose stat fails (simulated EACCES)
  }

  clone() {
    const v = new VFS()
    for (const [k, n] of this.nodes) v.nodes.set(k, { ...n })
    for (const u of this.unreadable) v.unreadable.add(u)
    return v
  }

  writeFile(path, content, meta = {}) {
    path = normalize(path)
    const existed = this.nodes.get(path)?.type === 'file'
    this.nodes.set(path, { type: 'file', content, ...meta })
    return { existed }
  }

  symlink(path, target) {
    this.nodes.set(normalize(path), { type: 'link', target })
  }

  exists(path) { return this.nodes.has(normalize(path)) }
  get(path)    { return this.nodes.get(normalize(path)) }

  /** Resolve every symlink component. Throws CanonicalizeError on failure. */
  realpath(path, depth = 0, opts = {}) {
    if (depth > 8) throw new CanonicalizeError('ELOOP', path)
    const segs = normalize(path).split('/').filter(Boolean)
    let cur = ''
    for (let i = 0; i < segs.length; i++) {
      cur = cur + '/' + segs[i]
      if (!opts.ignorePerms && this.unreadable.has(cur)) throw new CanonicalizeError('EACCES', cur)
      const node = this.nodes.get(cur)
      if (node?.type === 'link') {
        const target = join(cur.slice(0, cur.lastIndexOf('/')) || '/', node.target)
        const rest = segs.slice(i + 1).join('/')
        return this.realpath(rest ? target + '/' + rest : target, depth + 1, opts)
      }
    }
    return cur || '/'
  }

  /** Where the OS would actually put a write: it follows links regardless of what a checker could stat. */
  osResolve(path) {
    try { return this.realpath(path, 0, { ignorePerms: true }) } catch { return normalize(path) }
  }

  list() {
    return [...this.nodes.entries()]
      .map(([path, n]) => ({ path, ...n }))
      .sort((a, b) => a.path.localeCompare(b.path))
  }
}
