import bcrypt from 'bcryptjs'
import CryptoJS from 'crypto-js'

type EncryptedPayload = {
  ciphertext: string
  passwordHash: string
}

type InitRoot = ParentNode | Document

const SELECTORS = {
  container: '[data-encrypted-post]',
  payload: '[data-encrypted-payload]',
  form: '[data-role="unlock-form"]',
  passwordInput: '[data-role="password-input"]',
  error: '[data-role="unlock-error"]',
  content: '[data-role="unlock-content"]',
  button: '[data-role="unlock-button"]'
} as const

const STATE_ATTR = 'data-state'
const INITIALIZED_ATTR = 'data-initialized'

type SupportedContainer = HTMLElement & {
  [INITIALIZED_ATTR]?: string
}

function parsePayload(raw: string): EncryptedPayload | null {
  try {
    const payload = JSON.parse(raw) as Partial<EncryptedPayload>
    if (typeof payload?.ciphertext !== 'string') return null
    if (typeof payload?.passwordHash !== 'string') return null
    return {
      ciphertext: payload.ciphertext,
      passwordHash: payload.passwordHash
    }
  } catch (
    error // eslint-disable-line @typescript-eslint/no-unused-vars
  ) {
    return null
  }
}

function setState(container: HTMLElement, state: 'locked' | 'loading' | 'unlocked') {
  container.setAttribute(STATE_ATTR, state)
}

function setError(el: HTMLElement | null, message: string | null) {
  if (!el) return
  el.textContent = message ?? ''
  el.toggleAttribute('hidden', !message)
}

function toggleLoading(button: HTMLButtonElement, isLoading: boolean) {
  button.dataset.loading = isLoading ? 'true' : 'false'
  button.disabled = isLoading
  button.setAttribute('aria-busy', isLoading ? 'true' : 'false')
}

export function initEncryptedPosts(root: InitRoot = document): void {
  const containers = root.querySelectorAll<SupportedContainer>(SELECTORS.container)

  containers.forEach((container) => {
    if (container.dataset.initialized === 'true') return

    const payloadScript = container.querySelector<HTMLScriptElement>(SELECTORS.payload)

    if (!payloadScript?.textContent) {
      container.dataset.initialized = 'true'
      setError(
        container.querySelector<HTMLElement>(SELECTORS.error),
        '文章加密信息缺失，无法解锁。'
      )
      return
    }

    const payload = parsePayload(payloadScript.textContent)

    if (!payload) {
      container.dataset.initialized = 'true'
      setError(
        container.querySelector<HTMLElement>(SELECTORS.error),
        '文章加密信息无效，无法解锁。'
      )
      return
    }

    payloadScript.remove()
    container.dataset.initialized = 'true'
    setState(container, 'locked')

    const form = container.querySelector<HTMLFormElement>(SELECTORS.form)
    const input = container.querySelector<HTMLInputElement>(SELECTORS.passwordInput)
    const errorEl = container.querySelector<HTMLElement>(SELECTORS.error)
    const contentEl = container.querySelector<HTMLElement>(SELECTORS.content)
    const button = container.querySelector<HTMLButtonElement>(SELECTORS.button)

    if (!form || !input || !contentEl || !button) {
      setError(errorEl, '页面初始化失败，无法解锁。')
      return
    }

    form.addEventListener('submit', (event) => {
      event.preventDefault()

      const password = input.value.trim()

      if (!password) {
        setError(errorEl, '请输入密码')
        input.focus()
        return
      }

      setError(errorEl, null)
      setState(container, 'loading')
      toggleLoading(button, true)

      try {
        const matched = bcrypt.compareSync(password, payload.passwordHash)

        if (!matched) {
          setState(container, 'locked')
          setError(errorEl, '密码不正确')
          return
        }

        const decryptedBytes = CryptoJS.AES.decrypt(payload.ciphertext, password)
        const decrypted = decryptedBytes.toString(CryptoJS.enc.Utf8)

        if (!decrypted) {
          setState(container, 'locked')
          setError(errorEl, '解密失败，请重试')
          return
        }

        contentEl.innerHTML = decrypted
        contentEl.classList.remove('hidden')
        form.classList.add('hidden')
        setState(container, 'unlocked')
        input.value = ''
      } catch (error) {
        console.error('Failed to unlock encrypted post', error)
        setState(container, 'locked')
        setError(errorEl, '发生错误，请稍后重试')
      } finally {
        if (container.getAttribute(STATE_ATTR) !== 'unlocked') {
          toggleLoading(button, false)
        } else {
          button.dataset.loading = 'false'
        }
      }
    })
  })
}

if (typeof window !== 'undefined') {
  window.addEventListener('DOMContentLoaded', () => {
    initEncryptedPosts()
  })
}
