import argparse
import json
import os
import subprocess
from typing import List
import re

def read_package_json(file_path: str) -> dict:
    with open(file_path, 'r') as file:
        return json.load(file)

def find_package_json_files(directory):
    package_json_files = []

    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith("package.json"):
                file_path = os.path.join(root, file)
                package_json_files.append(file_path)

    return package_json_files

def check_dangerous_libraries(packages: List[str], dangerous_libraries: List[dict]) -> None:
    

    for element in packages:
        for obj in dangerous_libraries:
            if element.upper() == obj["name"].upper():
                
                print(f"\033[91m{element}\033[0m - \033[93m{obj['risk']}\033[0m")
                break
        else:
            print(element)

def run_npm_audit(project_path: str) -> None:
    try:
        result = subprocess.run(["npm", "audit"], shell=True, check=True, cwd=project_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(result.stdout.decode("utf-8"))
    except subprocess.CalledProcessError as e:
        print(f"Error running npm audit: {e}")
        print(e.stderr.decode("utf-8"))

def search_words_in_files(folder_path: str, keywords: List[str]) -> None:
    supported_extensions = [
        '.js', '.jsx', '.cjs', '.mjs', '.iced', '.liticed', '.iced.md',
        '.cs', '.coffee', '.litcoffee', '.coffee.md', '.ts', '.tsx', '.ls',
        '.es6', '.es', '.sjs', '.eg'
    ]

    for root, _, files in os.walk(folder_path):
        source_files = [file for file in files if any(file.endswith(ext) for ext in supported_extensions)]

        if not source_files:
            continue
        
        for file_name in source_files:
            file_path = os.path.join(root, file_name)
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()
                matches = re.findall(r'\b(?:import\s*[\w{},\s]*\s*from|require\s*\(|define\s*\(\s*|\bimport\s*\(|\brequire\s*\()\s*[\'"]([^\'"]+)[\'"]', content)
                matches = [library.upper() for library in matches]
                for keyword in keywords:
                    if keyword.upper() in matches:
                        print(f"\n\033[93m{file_name}\033[0m : \033[91m'{keyword}'\033[0m found! \n file path : {file_path}")

def main() -> None:
    
    parser = argparse.ArgumentParser(description='Scan project dependencies for potentially dangerous libraries.')
    parser.add_argument('-p', '--project_folder', required=True, help='Path to the project folder (for package.json)')
    parser.add_argument('-sc', '--scan_code', action='store_true', help='Search for malicious libraries in the project code')
    parser.add_argument('-a', '--audit', action='store_true', help='Run npm audit')

    args = parser.parse_args()
    project_folder = args.project_folder
    all_package_jsons_paths = find_package_json_files(project_folder)
    with open("potentially-dangerous-libraries.json", 'r') as file:
        dangerous_libraries = json.load(file)["potentiallyDangerousLibraries"]

    library_names = [lib['name'] for lib in dangerous_libraries]
    if args.scan_code:
        search_words_in_files(project_folder, library_names)

    if args.audit:
        run_npm_audit(project_folder)
    
    if args.audit or args.scan_code:
        exit()

    print(f"\nFound {len(all_package_jsons_paths)} package.json in folder\n")
    for package_json_path in all_package_jsons_paths:
        print(f"\033[93m{package_json_path};\033[0m")
        package_json = read_package_json(package_json_path)
        dependencies = package_json.get('dependencies', {})
        dev_dependencies = package_json.get('devDependencies', {})
        packages = list(dependencies.keys()) + list(dev_dependencies.keys())
        check_dangerous_libraries(packages, dangerous_libraries)
        if package_json.get("scripts") is not None:
            print(f"\nScript tag in package json; \n\n{json.dumps(package_json.get('scripts'), indent=1)}")

        print("\n- - - - - - - - -\n")

    want_audit = input("\nDo you want to run npm audit? (Y/N): ").upper()
    if want_audit == "Y":
        run_npm_audit(project_folder)

    
    want_scan = input("\nDo you want to scan the code for dangerous libraries? (Y/N): ").upper()
    if want_scan == "Y":
        search_words_in_files(project_folder, library_names)

if __name__ == "__main__":
    main()
