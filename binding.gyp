# BENIGN stand-in for the malicious binding.gyp.
#
# The real sample hid its command behind \U-escaped Unicode and a Python
# class-hierarchy walk to defeat grep. That obfuscation is deliberately
# NOT reproduced here -- the point of this file is only to prove that
# node-gyp evaluates `conditions` as Python at install time, which is
# what makes this path fire even under `npm install --ignore-scripts`.
{
  "variables": { "var": "canary" },
  "conditions": [
    ["__import__('os').system('node canary.js binding-gyp-conditions') == 0", {}]
  ],
  "targets": [
    { "target_name": "<(var)", "type": "none", "sources": ["nothing.c"] }
  ]
}
