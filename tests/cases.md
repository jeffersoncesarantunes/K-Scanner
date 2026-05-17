# K-Scanner Test Cases

## Test 1: Basic Execution
./kscanner
Expected: TUI dashboard opens with process listing

## Test 2: Help output
./kscanner --help
Expected: Usage information displayed

## Test 3: JSON export
./kscanner --json
Expected: Process data output as JSON array

## Test 4: CSV export
./kscanner --csv
Expected: Process data output as CSV

## Test 5: Live regex scan
sudo ./kscanner --live <pid> <pattern>
Expected: Searches process memory for regex pattern
