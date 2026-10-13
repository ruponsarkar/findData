const path = require('node:path');

module.exports = {
  apps: [{
    name: 'findData',
    cwd: __dirname,
    script: path.join(__dirname, '.venv', 'bin', 'python'),
    interpreter: 'none',
    args: ['-m', 'uvicorn', 'app:app', '--host', '0.0.0.0', '--port', '8008', '--workers', '1'],
    exec_mode: 'fork',
    instances: 1,
    watch: false,
    autorestart: true,
    restart_delay: 3000,
    kill_timeout: 30000,
    time: true,
    env: {
      PYTHONUNBUFFERED: '1',
    },
  }],
};
