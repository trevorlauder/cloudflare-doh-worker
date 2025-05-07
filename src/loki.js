// Copyright 2025 Trevor Lauder.
// SPDX-License-Identifier: MIT

import { loki } from "./config.js"

let responseCodes = {}
let blockedBy = {}
let possiblyBlockedBy = {}

function generateResponseObjects(item) {
  responseCodes[`${item.host}${item.path}`] = item.response.status
  blockedBy[`${item.host}${item.path}`] = item.blocked
  possiblyBlockedBy[`${item.host}${item.path}`] = item.possiblyBlocked
}

async function sendToLoki(requestTimeStamp, endpoint, question, responseFrom, results, env) {
  const headers = new Headers()

  const base64Credentials = btoa(`${env.LOKI_USERNAME}:${env.LOKI_PASSWORD}`)

  headers.set("Authorization", `Basic ${base64Credentials}`)
  headers.set("Content-Type", "application/json")

  results.forEach(generateResponseObjects)

  const responseFromArray = responseFrom.split("/")

  const blocked =
    results.filter((obj) => {
      return obj.blocked === true && obj.host === responseFromArray[0] && obj.path === `/${responseFromArray[1]}`
    }).length == 1

  const possiblyBlocked =
    results.filter((obj) => {
      return (
        obj.possiblyBlocked === true && obj.host === responseFromArray[0] && obj.path === `/${responseFromArray[1]}`
      )
    }).length == 1

  let resultStatus = ""

  if (blocked) {
    resultStatus = "blocked"
  } else if (possiblyBlocked) {
    resultStatus = "possibly blocked"
  } else {
    resultStatus = "not blocked"
  }

  const logJson = {
    endpoint: endpoint,
    question: {
      name: question.name,
      type: question.type,
    },
    result_status: resultStatus,
    blocked_by: blockedBy,
    possibly_blocked_by: possiblyBlockedBy,
    response_codes: responseCodes,
    response_from: responseFrom,
  }

  const lokiLog = {
    streams: [
      {
        stream: {
          source: "cloudflare-doh-worker",
        },
        values: [[Math.round(requestTimeStamp * 1000000).toString(), JSON.stringify(logJson)]],
      },
    ],
  }

  return await fetch(loki.url, {
    method: "POST",
    headers: headers,
    body: JSON.stringify(lokiLog),
  })
}

export { sendToLoki }
