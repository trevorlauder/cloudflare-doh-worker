# Copyright 2025-2026 Trevor Lauder.
# SPDX-License-Identifier: MIT

"""Force pure-Python json under Pyodide to avoid WASM heap corruption."""

import json

json.scanner.make_scanner = json.scanner.py_make_scanner
json.decoder.scanstring = json.decoder.py_scanstring
json.encoder.c_make_encoder = None
json.encoder.encode_basestring_ascii = json.encoder.py_encode_basestring_ascii
json.encoder.encode_basestring = json.encoder.py_encode_basestring

json._default_decoder = json.JSONDecoder()
