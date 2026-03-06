#!/usr/bin/env python3

# Copyright 2025-2026 Trevor Lauder.
# SPDX-License-Identifier: MIT

"""Mock DoH server for ECS truncation integration tests.

Endpoints:
  POST /dns-query      — accepts DNS wire, records ECS, returns a synthetic NOERROR + dummy A
  GET  /dns-query?dns= — same via base64url ?dns= param
  GET  /last-ecs       — last recorded ECS as JSON (or null)
  DELETE /last-ecs     — clears ECS state between tests
"""

import base64
import json
import logging
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

import dns.edns
import dns.message
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset

_lock = threading.Lock()
_last_ecs: dict | None = None


def _synthetic_response(query: dns.message.Message) -> bytes:
  resp = dns.message.make_response(query)
  resp.set_rcode(dns.rcode.NOERROR)
  if query.question:
    rrset = dns.rrset.RRset(query.question[0].name, dns.rdataclass.IN, dns.rdatatype.A)
    rrset.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, "192.0.2.1"))
    rrset.ttl = 60
    resp.answer.append(rrset)
  return resp.to_wire()


def _extract_ecs(query: dns.message.Message) -> dict | None:
  for opt in query.options:
    if isinstance(opt, dns.edns.ECSOption):
      return {"address": opt.address, "prefix": opt.srclen, "family": opt.family}
  return None


class _Handler(BaseHTTPRequestHandler):
  def log_message(self, *_):
    pass  # silence access logs

  def _send_json(self, data, status: int = 200) -> None:
    body = json.dumps(data).encode()
    self.send_response(status)
    self.send_header("Content-Type", "application/json")
    self.send_header("Content-Length", str(len(body)))
    self.end_headers()
    self.wfile.write(body)

  def _send_wire(self, wire: bytes) -> None:
    self.send_response(200)
    self.send_header("Content-Type", "application/dns-message")
    self.send_header("Content-Length", str(len(wire)))
    self.end_headers()
    self.wfile.write(wire)

  def _handle_dns_query(self, wire: bytes) -> None:
    global _last_ecs
    try:
      query = dns.message.from_wire(wire)
    except Exception:
      self.send_response(400)
      self.end_headers()
      return
    with _lock:
      _last_ecs = _extract_ecs(query)
    self._send_wire(_synthetic_response(query))

  def do_POST(self):
    if self.path != "/dns-query":
      self.send_response(404)
      self.end_headers()
      return
    length = int(self.headers.get("Content-Length", 0))
    self._handle_dns_query(self.rfile.read(length))

  def do_GET(self):
    parsed = urllib.parse.urlparse(self.path)

    if parsed.path == "/dns-query":
      dns_param = urllib.parse.parse_qs(parsed.query).get("dns", [""])[0]
      if not dns_param:
        self.send_response(400)
        self.end_headers()
        return
      try:
        wire = base64.urlsafe_b64decode(dns_param + "=" * (-len(dns_param) % 4))
      except Exception:
        self.send_response(400)
        self.end_headers()
        return
      self._handle_dns_query(wire)
      return

    if parsed.path != "/last-ecs":
      self.send_response(404)
      self.end_headers()
      return

    with _lock:
      data = _last_ecs
    self._send_json(data)

  def do_DELETE(self):
    global _last_ecs
    if self.path != "/last-ecs":
      self.send_response(404)
      self.end_headers()
      return
    with _lock:
      _last_ecs = None
    self.send_response(204)
    self.end_headers()


if __name__ == "__main__":
  logging.basicConfig(level=logging.INFO)
  server = HTTPServer(("0.0.0.0", 8080), _Handler)
  logging.info("Mock DoH server listening on :8080")
  server.serve_forever()
