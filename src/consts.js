// Copyright 2025 Trevor Lauder.
// SPDX-License-Identifier: MIT

const supportedAcceptHeaders = ["application/dns-json", "application/dns-message"]

const contentTypeDnsJsonRegex = new RegExp("application/dns-json|application/json")
const contentTypeDnsMessageRegex = new RegExp("application/dns-message")

export { supportedAcceptHeaders, contentTypeDnsJsonRegex, contentTypeDnsMessageRegex }
