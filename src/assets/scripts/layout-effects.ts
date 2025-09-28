import { animate } from 'animejs'

type Nullable<T> = T | null

let hasInitialized = false

const initRipple = () => {
  const rippleLayer = document.getElementById('ripple-layer') as Nullable<HTMLDivElement>
  if (!rippleLayer) return

  const ringDelays = [0, 140, 280]

  const spawnRipple = (event: PointerEvent) => {
    const { clientX, clientY } = event
    const rippleGroup = document.createElement('span')
    rippleGroup.className = 'click-ripple'

    const maxDimension = Math.max(
      document.documentElement.clientWidth,
      document.documentElement.clientHeight
    )
    const rippleSize = maxDimension * 0.9

    rippleGroup.style.setProperty('--ripple-size', `${rippleSize}px`)
    rippleGroup.style.setProperty('--ripple-x', `${clientX}px`)
    rippleGroup.style.setProperty('--ripple-y', `${clientY}px`)

    rippleLayer.appendChild(rippleGroup)

    let completed = 0
    const ringsTotal = ringDelays.length

    ringDelays.forEach(delay => {
      const ring = document.createElement('span')
      ring.className = 'click-ripple__ring'
      rippleGroup.appendChild(ring)

      animate(ring, {
        scale: { from: 0.35, to: 1.05 },
        opacity: { from: 0.65, to: 0 },
        duration: 1200,
        delay,
        ease: 'easeOutSine',
        onComplete: () => {
          completed += 1
          if (completed === ringsTotal) {
            rippleGroup.remove()
          }
        }
      })
    })
  }

  window.addEventListener('pointerdown', spawnRipple, { passive: true })
}

const run = () => {
  if (hasInitialized) return
  hasInitialized = true
  initRipple()
}

export const initLayoutEffects = () => {
  if (typeof window === 'undefined') return

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', run, { once: true })
  } else {
    run()
  }
}

initLayoutEffects()
