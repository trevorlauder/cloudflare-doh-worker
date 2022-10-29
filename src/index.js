// Copyright 2022 Trevor Lauder.
// SPDX-License-Identifier: MIT

import { endpoints, loki, debug } from "./config.js"
import { sendToLoki } from "./loki.js"
import { sendDohRequest } from "./dns.js"
import { supportedAcceptHeaders } from "./consts.js"

const dnsPacket = require("dns-packet")

addEventListener("fetch", (event) => {
  const url = new URL(event.request.url)

  if (url.pathname in endpoints) {
    const requestEndpoint = endpoints[url.pathname]

    event.respondWith(handleRequest(event, url.pathname, requestEndpoint["dohProviders"]))
  } else {
    return new Response("", { status: 404 })
  }
})

async function handleRequest(event, endpoint, dohProviders) {
  const requestTimeStamp = Date.now()
  let question = {}

  if (event.request.clone().method.toUpperCase() === "GET") {
    if (!supportedAcceptHeaders.includes(event.request.headers.get("Accept"))) {
      return new Response(`Unsupported Accept header\n\nUse one of: ${supportedAcceptHeaders}`, { status: 406 })
    }

    const { searchParams } = new URL(event.request.url)

    if (searchParams.has("dns")) {
      const dns = searchParams.get("dns")
      const base64DecodedDns = Buffer.from(dns, "base64").toString("ascii")
      const packet = dnsPacket.decode(Buffer.from(base64DecodedDns))

      question = {
        name: packet["questions"][0]["name"],
        type: packet["questions"][0]["type"],
      }
    } else if (searchParams.has("name")) {
      question = {
        name: searchParams.get("name"),
        type: searchParams.has("type") ? searchParams.get("type") : "",
      }
    } else {
      return new Response("GET requests must include one of name or dns as query parameters", { status: 400 })
    }
  } else if (event.request.clone().method.toUpperCase() === "POST") {
    const dns = await event.request.clone().arrayBuffer()
    const packet = dnsPacket.decode(Buffer.from(dns))

    question = {
      name: packet["questions"][0]["name"],
      type: packet["questions"][0]["type"],
    }
  }

  const results = await Promise.all(
    dohProviders.map((config) => {
      return sendDohRequest(event.request.clone(), config)
    }),
  )

  const responseResultsPossiblyBlocked = results.filter((obj) => {
    return obj.possiblyBlocked === true
  })

  const responseResultsBlocked = results.filter((obj) => {
    return obj.blocked === true
  })

  let newResponse

  if (responseResultsBlocked.length > 0) {
    newResponse = new Response(responseResultsBlocked[0].response.body, responseResultsBlocked[0].response)
  } else if (responseResultsPossiblyBlocked.length > 0) {
    newResponse = new Response(
      responseResultsPossiblyBlocked[0].response.body,
      responseResultsPossiblyBlocked[0].response,
    )
  } else {
    const responseResultsUseAnyResponse = results.filter((obj) => {
      return obj.main === true
    })

    const responseResultsUseSuccessfulResponse = results.filter((obj) => {
      return obj.main === true && obj.failed === false
    })

    if (responseResultsUseAnyResponse.length > 1) {
      newResponse = new Response("Multiple DoH providers have main set to true", { status: 409 })
    } else if (responseResultsUseSuccessfulResponse.length == 0) {
      newResponse = new Response("All providers responded with an error", { status: 500 })
    } else if (responseResultsUseSuccessfulResponse.length == 1) {
      newResponse = new Response(
        responseResultsUseSuccessfulResponse[0].response.body,
        responseResultsUseSuccessfulResponse[0].response,
      )
    } else if (responseResultsUseAnyResponse.length == 1) {
      newResponse = new Response(
        responseResultsUseAnyResponse[0].response.body,
        responseResultsUseAnyResponse[0].response,
      )
    } else {
      newResponse = new Response("An unkown error occurred", {
        status: 500,
      })
    }
  }

  const responseFrom = newResponse.headers.get("CLOUDFLARE-DOH-WORKER-RESPONSE-FROM")
  const resultsResponseCodes = results.map((result) => `${result.host}${result.path}:${result.response.status}`)
  const resultsPossiblyBlocked = responseResultsPossiblyBlocked.map((result) => `${result.host}${result.path}`)
  const resultsBlocked = responseResultsBlocked.map((result) => `${result.host}${result.path}`)

  if (debug) {
    console.log(`endpoint: '${endpoint}'`)
    console.log(`response_from: '${responseFrom}'`)
    console.log(`response_codes: '${resultsResponseCodes}'`)
    console.log(`possibly_blocked_by: '${resultsPossiblyBlocked}'`)
    console.log(`blocked_by: '${resultsBlocked}'`)
  }

  newResponse.headers.append("CLOUDFLARE-DOH-WORKER-RESPONSE-CODES", resultsResponseCodes)
  newResponse.headers.append("CLOUDFLARE-DOH-WORKER-POSSIBLY-BLOCKED-BY", resultsPossiblyBlocked)
  newResponse.headers.append("CLOUDFLARE-DOH-WORKER-BLOCKED-BY", resultsBlocked)

  if (loki.enabled) {
    event.waitUntil(sendToLoki(requestTimeStamp, endpoint, question, responseFrom, results))
  }

  return newResponse
}
