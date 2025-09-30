declare module 'virtual:config' {
  const Config: import('astro-pure/types').ConfigOutput
  export default Config
}

declare module 'crypto-js' {
  const CryptoJS: any
  export default CryptoJS
}
