const debug = false

const loki = {
  enabled: false,
  url: "",
}

const endpoints = {
  "/my/doh/path": {
    dohProviders: [
      {
        host: "dns11.quad9.net",
        path: "/dns-query",
      },
      {
        main: true,
        host: "cloudflare-dns.com",
        path: "/dns-query",
      },
    ],
  },
}

export { debug, loki, endpoints }
