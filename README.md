 # Scan Before Install

This tool scans JavaScript projects for potentially dangerous libraries. It helps freelancers and developers identify and mitigate security risks in their projects.

## Features

- **Dependency Check:** Scans `package.json` files in the specified project folder for dependencies, checking against a database of potentially dangerous libraries.

- **Code Scanner:** Searches project source code for potentially dangerous libraries using regular expressions to identify import statements or require calls.

- **NPM Audit:** Runs `npm audit` on the project, providing detailed information about vulnerabilities in project dependencies.

## Usage

### Installation

```bash
git clone https://github.com/mahmut-ozdemir/scan-before-install
cd project-security-scanner
```

## Running the Scanner

Execute the following command:

```
python security_scanner.py -p /path/to/your/project
```
```
Options:
-sc or --scan_code: Search for malicious libraries in the project code.
-a or --audit: Run npm audit.
-p or --project_folder: Path to the project folder.
```

## Configuration

The tool uses a predefined list of potentially dangerous libraries stored in potentially-dangerous-libraries.json. You can update this file with additional information or libraries as needed.

## Contributing

Contributions are welcome! Feel free to open an issue or submit a pull request.
