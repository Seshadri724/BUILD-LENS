// Harmless postinstall script simulating standard dependency asset setup
const fs = require('fs');
const path = require('path');

const outDir = path.join(__dirname, '..', '.cache');
if (!fs.existsSync(outDir)) {
  fs.mkdirSync(outDir, { recursive: true });
}
fs.writeFileSync(path.join(outDir, 'postinstall.marker'), 'completed');
console.log('Postinstall completed successfully');
