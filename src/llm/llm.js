/**
 * llm.js — optional WebLLM reviewer. The harness never asks the model for a
 * security decision; the model only explains a finished run in plain words.
 */
export const WEBLLM_MODELS = [
  { id: 'Llama-3.2-1B-Instruct-q4f32_1-MLC', name: 'Llama 3.2 1B (~0.9 GB) — Fast' },
  { id: 'Llama-3.2-3B-Instruct-q4f16_1-MLC', name: 'Llama 3.2 3B (~2.0 GB)' },
  { id: 'Qwen2.5-3B-Instruct-q4f16_1-MLC',   name: 'Qwen 2.5 3B (~2.0 GB)' },
  { id: 'Phi-3.5-mini-instruct-q4f16_1-MLC', name: 'Phi-3.5 Mini (~2.2 GB)' },
]

let worker = null, status = 'idle', gen = 0, pendingLoad = null, pendingGen = null, onProgress = null

function ensure() {
  if (worker) return
  worker = new Worker(new URL('./worker.js', import.meta.url), { type: 'module' })
  worker.onmessage = ({ data: m }) => {
    if (m.status === 'ready')       { status = 'ready'; onProgress?.({ type: 'ready' }); pendingLoad?.resolve(); pendingLoad = null }
    else if (m.status === 'error')  { status = 'error'; const e = new Error(m.error); pendingLoad?.reject(e); pendingGen?.reject(e); pendingLoad = pendingGen = null }
    else if (m.status === 'downloading') onProgress?.({ type: 'downloading', progress: m.progress })
    else if (m.status === 'phase')  onProgress?.({ type: 'phase', phase: m.phase })
    else if (m.status === 'success') { pendingGen?.resolve(m.generatedText); pendingGen = null }
  }
}

export const modelReady = () => status === 'ready'

export function loadModel(modelId, cb) {
  ensure(); status = 'loading'; onProgress = cb; gen++
  return new Promise((resolve, reject) => {
    pendingLoad = { resolve, reject }
    worker.postMessage({ action: 'load', modelId, gen })
  })
}

export function generate(systemPrompt, userText) {
  if (status !== 'ready') return Promise.reject(new Error('Load a model first.'))
  gen++
  return new Promise((resolve, reject) => {
    pendingGen = { resolve, reject }
    worker.postMessage({ action: 'generate', systemPrompt, messages: [{ role: 'user', content: userText }], gen })
  })
}
