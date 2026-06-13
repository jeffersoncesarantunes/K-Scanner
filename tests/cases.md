# K-Scanner Test Cases

## Test 1: Basic Execution
Run `./kscanner` and you should see the TUI dashboard pop up with a list of running processes.

## Test 2: Help output
Run `./kscanner --help` — it should print usage information to stdout.

## Test 3: JSON export
Run `./kscanner --json` and it should dump process data as a JSON array.

## Test 4: CSV export
Run `./kscanner --csv` and it should output process data in CSV format.

## Test 5: Live regex scan (manual)
Run `sudo ./kscanner --live <pid> <pattern>` and it should search the target process's memory for whatever regex pattern you give it.

> **Note:** Tests 1–4 are automated via `make test`. Test 5 requires manual execution with `sudo` and a running process.
