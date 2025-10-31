import { animate, createAnimatable } from 'animejs'

const CLOCK_SELECTOR = '#animated-clock'
const POINTER_CLOCK_SELECTOR = '#pointer-clock'
const GLOBAL_FLAG = '__clockAnimationInitialized__'

type AnimationController = ReturnType<typeof animate>

let clockAnimation: AnimationController | null = null
let pointerClockAnimatable: ReturnType<typeof createAnimatable> | null = null
let mouseMoveListenerAttached = false
let visibilityListenerAttached = false
let reduceMotionQuery: MediaQueryList | null = null
let reduceMotionListenerAttached = false

const shouldReduceMotion = () => {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return false

  if (!reduceMotionQuery) {
    reduceMotionQuery = window.matchMedia('(prefers-reduced-motion: reduce)')
  }

  return reduceMotionQuery.matches
}

const startClockAnimation = (clockElement: HTMLElement) => {
  if (clockAnimation) {
    clockAnimation.pause()
    clockAnimation = null
  }

  clockAnimation = animate(clockElement, {
    rotate: 360,
    ease: 'linear',
    duration: 8000,
    loop: true
  })

  if (shouldReduceMotion() || document.hidden) {
    clockAnimation.pause()
  }

  return clockAnimation
}

const createPointerClock = (clockElement: HTMLElement) => {
  if (pointerClockAnimatable) {
    return pointerClockAnimatable
  }

  pointerClockAnimatable = createAnimatable(clockElement, {
    rotate: { unit: 'rad' },
    ease: 'linear'
  })

  return pointerClockAnimatable
}

const rotateClock = (animatable: ReturnType<typeof createAnimatable>) => {
  const PI = Math.PI
  let angle = PI / 2
  let lastAngle = 0

  return (e: MouseEvent) => {
    const targets = animatable.targets as HTMLElement[]
    const $clock = targets[0]
    if (!$clock) return

    const { width, height, left, top } = $clock.getBoundingClientRect()
    const x = e.clientX - left - width / 2
    const y = e.clientY - top - height / 2
    const currentAngle = Math.atan2(y, x)
    const diff = currentAngle - lastAngle
    angle += diff > PI ? diff - 2 * PI : diff < -PI ? diff + 2 * PI : diff
    lastAngle = currentAngle
    animatable.rotate(angle)
  }
}

const ensureMouseMoveListener = (animatable: ReturnType<typeof createAnimatable>) => {
  if (mouseMoveListenerAttached) return

  const rotateClockHandler = rotateClock(animatable)
  window.addEventListener('mousemove', rotateClockHandler)
  mouseMoveListenerAttached = true
}

const ensureVisibilityListener = () => {
  if (visibilityListenerAttached) return

  const handleVisibilityChange = () => {
    const reduceMotion = shouldReduceMotion()

    if (document.hidden || reduceMotion) {
      clockAnimation?.pause()
    } else {
      clockAnimation?.play()
    }
  }

  document.addEventListener('visibilitychange', handleVisibilityChange)
  visibilityListenerAttached = true
}

const ensureReduceMotionListener = () => {
  if (!reduceMotionQuery || reduceMotionListenerAttached) return

  const handler = (event: MediaQueryListEvent | MediaQueryList) => {
    const matches = 'matches' in event ? event.matches : reduceMotionQuery!.matches

    if (matches) {
      clockAnimation?.pause()
      return
    }

    if (document.hidden) return

    clockAnimation?.play()
  }

  if (typeof reduceMotionQuery.addEventListener === 'function') {
    reduceMotionQuery.addEventListener('change', handler as EventListener)
  } else if (typeof (reduceMotionQuery as any).addListener === 'function') {
    ;(reduceMotionQuery as any).addListener(handler)
  }

  reduceMotionListenerAttached = true
}

const initializeAnimations = () => {
  const clockElement = document.querySelector<HTMLElement>(CLOCK_SELECTOR)
  const pointerClockElement = document.querySelector<HTMLElement>(POINTER_CLOCK_SELECTOR)

  if (!clockElement || !pointerClockElement) return

  const reduceMotionEnabled = shouldReduceMotion()
  ensureReduceMotionListener()

  if (!reduceMotionEnabled) {
    startClockAnimation(clockElement)
    ensureVisibilityListener()
  }

  const pointerClock = createPointerClock(pointerClockElement)
  ensureMouseMoveListener(pointerClock)
}

const attachAnimation = () => {
  if (typeof document === 'undefined') return

  const run = () => initializeAnimations()

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', run, { once: true })
  } else {
    run()
  }

  document.addEventListener('astro:page-load', run)
}

const initialize = () => {
  if (typeof window === 'undefined') return

  const globalScope = window as typeof window & Record<string, boolean>
  if (globalScope[GLOBAL_FLAG]) {
    return
  }

  globalScope[GLOBAL_FLAG] = true
  attachAnimation()
}

initialize()
