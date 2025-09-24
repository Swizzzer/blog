import { h } from 'hastscript'
import type { ShikiTransformer } from 'shiki'

export {
  transformerNotationDiff,
  transformerNotationHighlight
} from './shiki-official-transformers'

function parseMetaString(str = '') {
  return Object.fromEntries(
    str.split(' ').reduce((acc: [string, string | true][], cur) => {
      const matched = cur.match(/(.+)?=("(.+)"|'(.+)')$/)
      if (matched === null) return acc
      const key = matched[1]
      const value = matched[3] || matched[4] || true
      acc = [...acc, [key, value]]
      return acc
    }, [])
  )
}

// Nest a div in the outer layer
export const updateStyle = (): ShikiTransformer => {
  return {
    name: 'shiki-transformer-update-style',
    pre(node) {
      const container = h('pre', node.children)
      node.children = [container]
      node.tagName = 'div'
    }
  }
}

// Process meta string, like ```ts title="test.ts"
export const processMeta = (): ShikiTransformer => {
  return {
    name: 'shiki-transformer-process-meta',
    preprocess() {
      if (!this.options.meta) return
      const rawMeta = this.options.meta?.__raw
      if (!rawMeta) return
      const meta = parseMetaString(rawMeta)
      Object.assign(this.options.meta, meta)
    }
  }
}

// Add a title to the code block
export const addTitle = (): ShikiTransformer => {
  return {
    name: 'shiki-transformer-add-title',
    pre(node) {
      const rawMeta = this.options.meta?.__raw
      if (!rawMeta) return
      const meta = parseMetaString(rawMeta)
      // If meta is needed to parse in other transformers
      // if (this.options.meta) {
      //   Object.assign(this.options.meta, meta)
      // }

      if (!meta.title) return

      const div = h(
        'div',
        {
          class: 'title text-sm text-foreground px-3 py-1 bg-primary-foreground rounded-lg border'
        },
        meta.title.toString()
      )
      node.children.unshift(div)
    }
  }
}

// Add a language tag to the code block
export const addLanguage = (): ShikiTransformer => {
  return {
    name: 'shiki-transformer-add-language',
    pre(node) {
      const span = h(
        'span',
        {
          class: 'language ps-1 pe-3 text-sm bg-muted text-muted-foreground'
        },
        this.options.lang
      )
      node.children.push(span)
    }
  }
}

// Add a copy button to the code block
export const addCopyButton = (timeout?: number): ShikiTransformer => {
  const toggleMs = timeout || 3000

  return {
    name: 'shiki-transformer-copy-button',
    pre(node) {
      const button = h(
        'button',
        {
          class: 'copy text-muted-foreground p-1 box-content border rounded bg-primary-foreground',
          'data-code': this.source,
          onclick: `
          navigator.clipboard.writeText(this.dataset.code);
          this.classList.add('copied');
          setTimeout(() => this.classList.remove('copied'), ${toggleMs})
        `
        },
        [
          h('div', { class: 'ready' }, [
            h(
              'svg',
              {
                class: 'size-5'
              },
              [
                h('use', {
                  href: '/icons/code.svg#mingcute-clipboard-line'
                })
              ]
            )
          ]),
          h('div', { class: 'success hidden' }, [
            h(
              'svg',
              {
                class: 'size-5'
              },
              [
                h('use', {
                  href: '/icons/code.svg#mingcute-file-check-line'
                })
              ]
            )
          ])
        ]
      )

      node.children.push(button)
    }
  }
}

// Add a collapse button to the code block
export const addCollapseButton = (): ShikiTransformer => {
  return {
    name: 'shiki-transformer-collapse-button',
    pre(node) {
      const button = h(
        'button',
        {
          class: 'collapse text-muted-foreground p-1 box-content border rounded bg-primary-foreground',
          onclick: `
            const codeBlock = this.closest('.astro-code');
            const pre = codeBlock.querySelector('pre');
            const code = pre.querySelector('code');
            const isCollapsed = codeBlock.classList.contains('collapsed');
            
            if (isCollapsed) {
              codeBlock.classList.remove('collapsed');
              pre.style.maxHeight = '';
              pre.style.overflow = '';
              this.querySelector('.expand').classList.add('hidden');
              this.querySelector('.collapse-icon').classList.remove('hidden');
            } else {
              codeBlock.classList.add('collapsed');
              
              // 动态计算前2行的高度
              const lines = code.querySelectorAll('.line');
              if (lines.length >= 2) {
                const firstLineHeight = lines[0].getBoundingClientRect().height;
                const secondLineHeight = lines[1].getBoundingClientRect().height;
                const preStyles = window.getComputedStyle(pre);
                const paddingTop = parseFloat(preStyles.paddingTop);
                const paddingBottom = parseFloat(preStyles.paddingBottom);
                
                const collapsedHeight = firstLineHeight + secondLineHeight + paddingTop + paddingBottom + 'px';
                pre.style.maxHeight = collapsedHeight;
              } else {
                // 回退到固定高度
                pre.style.maxHeight = 'calc(1.5rem * 2 + 1.7rem)';
              }
              
              pre.style.overflow = 'hidden';
              this.querySelector('.expand').classList.remove('hidden');
              this.querySelector('.collapse-icon').classList.add('hidden');
            }
          `
        },
        [
          h('div', { class: 'collapse-icon' }, [
            h(
              'svg',
              {
                class: 'size-5'
              },
              [
                h('use', {
                  href: '/icons/code.svg#mingcute-up-line'
                })
              ]
            )
          ]),
          h('div', { class: 'expand hidden' }, [
            h(
              'svg',
              {
                class: 'size-5'
              },
              [
                h('use', {
                  href: '/icons/code.svg#mingcute-down-line'
                })
              ]
            )
          ])
        ]
      )

      node.children.push(button)
    }
  }
}
