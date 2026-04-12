#!/usr/bin/env node

const { spawn } = require('child_process');
const { spawnSync } = require('child_process');
const path = require('path');

const serverPath = path.join(__dirname, '..', 'server.py');

function resolvePythonCommand() {
    const candidates = [];
    if (process.env.PYTHON && process.env.PYTHON.trim()) {
        candidates.push({ cmd: process.env.PYTHON.trim(), versionArgs: ['--version'], runPrefix: [] });
    }
    candidates.push({ cmd: 'python3', versionArgs: ['--version'], runPrefix: [] });
    candidates.push({ cmd: 'python', versionArgs: ['--version'], runPrefix: [] });
    candidates.push({ cmd: 'py', versionArgs: ['-3', '--version'], runPrefix: ['-3'] });

    for (const candidate of candidates) {
        try {
            const probe = spawnSync(candidate.cmd, candidate.versionArgs, {
                stdio: 'ignore',
                shell: false,
            });
            if (probe.status === 0) {
                return candidate;
            }
        } catch (_err) {
            // Continue to next candidate.
        }
    }
    return null;
}

const pythonRuntime = resolvePythonCommand();
if (!pythonRuntime) {
    console.error('Error: Python not found. Please install Python 3.12 or later.');
    process.exit(1);
}

const args = [...pythonRuntime.runPrefix, serverPath, ...process.argv.slice(2)];
const pythonProcess = spawn(pythonRuntime.cmd, args, {
    stdio: 'inherit',
    env: process.env,
    shell: false,
});

pythonProcess.on('close', (code) => {
    process.exit(code);
});

pythonProcess.on('error', (err) => {
    console.error(`Failed to start python process: ${err.message}`);
    process.exit(1);
});
