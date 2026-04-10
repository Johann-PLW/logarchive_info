# logarchive_info

Python script to create the `Info.plist` file in an Apple Unified Logs `.logarchive` package.

## Requirements

- Python 3.9+ (recommended)
- macOS (the script is intended for working with Apple Unified Logs)

## Install

Clone the repository:

```bash
git clone https://github.com/Johann-PLW/logarchive_info.git
cd logarchive_info
```

(Optional) Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies (if any are added later):

```bash
python3 -m pip install -r requirements.txt
```

> If this repository does not include a `requirements.txt`, you can skip the dependency installation step.

## Usage

Run the script and point it at a `.logarchive` package:

```bash
python3 logarchive_info.py /path/to/some.logarchive
```

## Examples

Generate `Info.plist` for a logarchive on your Desktop:

```bash
python3 logarchive_info.py ~/Desktop/system.logarchive
```

## Output

- Writes an `Info.plist` file into the target `.logarchive` package.
- Prints basic status information to stdout (depending on script implementation).