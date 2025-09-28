import { animate as animeAnimate, stagger, text } from 'animejs'

const SELECTOR = '#home-thankyou-text'
const GLOBAL_FLAG = '__homeThankYouAnimationInitialized__'

type SplitResult = {
  words: HTMLElement[]
  chars: HTMLElement[]
}

const TIMING = {
  duration: 900,
  staggerDelay: 225,
  reverseDelay: 750,
  loopDelay: 1000
}

type AnimationController = ReturnType<typeof animeAnimate>

let animationTimeline: AnimationController | null = null
let currentTarget: HTMLElement | null = null
let intersectionObserver: IntersectionObserver | null = null
let observedElement: HTMLElement | null = null
let visibilityListenerAttached = false
let reduceMotionQuery: MediaQueryList | null = null
let reduceMotionListenerAttached = false

const setAnimatedFlag = (element: HTMLElement) => {
  if (element.dataset.animated === 'true') return false

  element.dataset.animated = 'true'
  return true
}

const getOffset = (element: HTMLElement | null | undefined) => {
  const lineValue = element?.dataset?.line ?? '0'
  const line = Number(lineValue)
  return line % 2 ? '100%' : '-100%'
}

const buildTimeline = (target: HTMLElement) => {
  const { words, chars } = text.split(target, {
    words: { wrap: 'clip' },
    chars: true
  }) as SplitResult

  const segments = words.length > 0 ? words : chars

  const animation = animeAnimate(segments as any, {
    y: [
      {
        to: (el: Element) => {
          const exitTo = getOffset(el as HTMLElement)
          const entryFrom = exitTo === '100%' ? '-100%' : '100%'
          return [entryFrom, '0%']
        }
      },
      {
        to: (el: Element) => getOffset(el as HTMLElement),
        delay: TIMING.reverseDelay,
        ease: 'in(3)'
      }
    ] as any,
    duration: TIMING.duration,
    ease: 'out(3)',
    delay: stagger(TIMING.staggerDelay),
    loop: true,
    loopDelay: TIMING.loopDelay,
    autoplay: false
  })

  return animation
}

const ensureTimeline = (target: HTMLElement) => {
  if (animationTimeline && currentTarget === target) {
    return animationTimeline
  }

  if (animationTimeline && currentTarget && currentTarget !== target) {
    animationTimeline.pause()
    animationTimeline = null
    currentTarget = null
  }

  animationTimeline = buildTimeline(target)
  currentTarget = target
  return animationTimeline
}

const shouldReduceMotion = () => {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return false

  if (!reduceMotionQuery) {
    reduceMotionQuery = window.matchMedia('(prefers-reduced-motion: reduce)')
  }

  return reduceMotionQuery.matches
}

const ensureReduceMotionListener = () => {
  if (!reduceMotionQuery || reduceMotionListenerAttached) return

  const handler = (event: MediaQueryListEvent | MediaQueryList) => {
    const matches = 'matches' in event ? event.matches : reduceMotionQuery!.matches

    if (matches) {
      animationTimeline?.pause()
      return
    }

    if (document.hidden) return

    if (!animationTimeline) {
      const target = document.querySelector<HTMLElement>(SELECTOR)
      if (!target) return

      setAnimatedFlag(target)
      const timeline = ensureTimeline(target)
      ensureVisibilityListener()
      ensureIntersectionObserver(target)
      updatePlaybackState(target)
      timeline.play()
    } else {
      animationTimeline.play()
    }
  }

  if (typeof reduceMotionQuery.addEventListener === 'function') {
    reduceMotionQuery.addEventListener('change', handler as EventListener)
  } else if (typeof (reduceMotionQuery as any).addListener === 'function') {
    ;(reduceMotionQuery as any).addListener(handler)
  }

  reduceMotionListenerAttached = true
}

const ensureVisibilityListener = () => {
  if (visibilityListenerAttached) return

  const handleVisibilityChange = () => {
    if (!animationTimeline) return

    if (document.hidden || shouldReduceMotion()) {
      animationTimeline.pause()
    } else {
      animationTimeline.play()
    }
  }

  document.addEventListener('visibilitychange', handleVisibilityChange)
  visibilityListenerAttached = true
}

const ensureIntersectionObserver = (target: HTMLElement) => {
  if (typeof IntersectionObserver === 'undefined') {
    if (!document.hidden && !shouldReduceMotion()) {
      animationTimeline?.play()
    }
    return
  }

  if (!intersectionObserver) {
    intersectionObserver = new IntersectionObserver(
      entries => {
        entries.forEach(entry => {
          if (!animationTimeline) return
          if (currentTarget && entry.target !== currentTarget) return

          if (entry.isIntersecting && !document.hidden && !shouldReduceMotion()) {
            animationTimeline.play()
          } else {
            animationTimeline.pause()
          }
        })
      },
      { threshold: 0.25 }
    )
  }

  if (observedElement && observedElement !== target) {
    intersectionObserver.unobserve(observedElement)
  }

  intersectionObserver.observe(target)
  observedElement = target
}

const isElementVisible = (element: HTMLElement) => {
  const rect = element.getBoundingClientRect()
  return rect.bottom > 0 && rect.top < window.innerHeight
}

const updatePlaybackState = (target: HTMLElement) => {
  if (!animationTimeline) return

  if (shouldReduceMotion() || document.hidden) {
    animationTimeline.pause()
    return
  }

  if (isElementVisible(target)) {
    animationTimeline.play()
  }
}

const animate = () => {
  const target = document.querySelector<HTMLElement>(SELECTOR)
  if (!target) return

  const reduceMotionEnabled = shouldReduceMotion()
  ensureReduceMotionListener()

  if (reduceMotionEnabled) {
    setAnimatedFlag(target)
    return
  }

  const alreadyAnimated = !setAnimatedFlag(target)

  const timeline = ensureTimeline(target)

  ensureVisibilityListener()
  ensureIntersectionObserver(target)
  updatePlaybackState(target)

  if (!alreadyAnimated && timeline) {
    if (document.hidden || shouldReduceMotion() || !isElementVisible(target)) {
      timeline.pause()
    } else {
      timeline.play()
    }
  }
}

const attachAnimation = () => {
  if (typeof document === 'undefined') return

  const run = () => animate()

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', run, { once: true })
  } else {
    run()
  }

  document.addEventListener('astro:page-load', run)
}

const initialize = () => {
  if (typeof window === 'undefined') {
    return
  }

  const globalScope = window as typeof window & Record<string, boolean>
  if (globalScope[GLOBAL_FLAG]) {
    return
  }

  globalScope[GLOBAL_FLAG] = true
  attachAnimation()
}

initialize()
