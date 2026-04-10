# logarchive_info

Python script to create the `Info.plist` file in an Apple Unified Logs `.logarchive` package.
More info: https://digital-forensics.polewczyk.fr/apple/unified-logs/info-plist/

## Requirements

- Python 3.9+ (recommended)
- macOS (the script is intended for working with Apple Unified Logs)

## Install

Clone the repository:

```bash
git clone https://github.com/Johann-PLW/logarchive_info.git
cd logarchive_info
```

This script only uses Python Standard Library.

## Usage

Run the script and point it to a `.logarchive` package:

```bash
python3 logarchive_info.py /path/to/<package_name>.logarchive
```

## Examples

Generate `Info.plist` for a logarchive on your Desktop:

```bash
python3 logarchive_info.py ~/Desktop/system.logarchive
```

## Output

- Writes an `Info.plist` file into the target `.logarchive` package.
