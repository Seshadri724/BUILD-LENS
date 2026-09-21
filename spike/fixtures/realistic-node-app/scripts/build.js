// Simulated application build step
const fs = require('fs');
const path = require('path');

const distDir = path.join(__dirname, '..', 'dist');
if (!fs.existsSync(distDir)) {
  fs.mkdirSync(distDir, { recursive: true });
}

fs.writeFileSync(path.join(distDir, 'bundle.js'), 'console.log("Enterprise App Bundle");');
console.log('Build completed: dist/bundle.js generated');
