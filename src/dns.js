// Copyright 2025 Trevor Lauder.
// SPDX-License-Identifier: MIT

import * as dnsPacket from "dns-packet"

import { contentTypeDnsJsonRegex, contentTypeDnsMessageRegex } from "./consts.js"

function _isBlocked(status, answers) {
  let blocked
  let possiblyBlocked

  const responseAnswers = answers.filter((obj) => {
    return obj.data === "0.0.0.0" || obj.data === "::"
  })

  if (responseAnswers.length == 0) {
    blocked = false
  } else {
    blocked = true
  }

  if (status == 3 || status.toString().toUpperCase() == "NXDOMAIN") {
    possiblyBlocked = true
  } else {
    possiblyBlocked = false
  }

  return { blocked: blocked, possiblyBlocked: possiblyBlocked }
}

async function sendDohRequest(request, config) {
  const url = new URL(request.url)
  let headers = {}
  let main = false

  url.host = config.host
  url.pathname = config.path

  url.protocol = "https:/"
  url.port = "443"

  if ("headers" in config) {
    headers = config.headers
  }

  if ("main" in config) {
    main = config.main
  }

  const newRequest = new Request(url, request)

  Object.entries(headers).forEach(([k, v]) => newRequest.headers.set(k, v))

  const response = await fetch(url, newRequest)

  const newResponse = new Response(response.body, response)
  newResponse.headers.append("CLOUDFLARE-DOH-WORKER-RESPONSE-FROM", `${config.host}${config.path}`)

  if (newResponse.ok) {
    let blocked
    let possiblyBlocked
    let answers = []

    if (contentTypeDnsJsonRegex.test(newResponse.headers.get("content-type"))) {
      const responseJson = await newResponse.clone().json()

      if ("Answer" in responseJson) {
        answers = responseJson.Answer
      }

      ;({ blocked, possiblyBlocked } = _isBlocked(responseJson.Status, answers))
    } else if (contentTypeDnsMessageRegex.test(newResponse.headers.get("content-type"))) {
      const responseArrayBuffer = await newResponse.clone().arrayBuffer()

      const responseJson = dnsPacket.decode(Buffer.from(new Uint8Array(responseArrayBuffer)))

      if ("answers" in responseJson) {
        answers = responseJson.answers
      }

      ;({ blocked, possiblyBlocked } = _isBlocked(responseJson.rcode, answers))
    }

    return {
      host: config.host,
      path: config.path,
      response: newResponse,
      blocked: blocked,
      possiblyBlocked: possiblyBlocked,
      failed: false,
      main: main,
    }
  } else {
    return {
      host: config.host,
      path: config.path,
      response: newResponse,
      blocked: false,
      possiblyBlocked: false,
      failed: true,
      main: main,
    }
  }
}

export { sendDohRequest }
