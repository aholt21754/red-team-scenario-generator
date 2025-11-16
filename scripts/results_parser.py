#!/usr/bin/env python3
"""
Red Team Scenario JSON Processor
Processes JSON files containing red team scenario outputs and evaluations.
Generates CSV files for analysis and HTML files for scenario content.
"""

import json
import csv
import sys
from pathlib import Path
from typing import Dict, List, Any

import markdown


def process_json_file(json_path: Path) -> Dict[str, Any]:
    """
    Load and parse a JSON file.
    
    Args:
        json_path: Path to the JSON file
        
    Returns:
        Parsed JSON data as dictionary
    """
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error parsing {json_path.name}: {e}")
        return None
    except Exception as e:
        print(f"Error reading {json_path.name}: {e}")
        return None


def create_html_from_chatbot_output(chatbot_output: str, output_path: Path):
    """
    Convert chatbot output to HTML file with proper line breaks.
    
    Args:
        chatbot_output: The chatbot output text
        output_path: Path where HTML file should be saved
    """

    # Replace \n with actual newlines
    formatted_text = chatbot_output.replace('\\n', '\n')

    # Convert to HTML
    html = markdown.markdown(formatted_text)

    # Convert markdown-style content to HTML
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Red Team Scenario - {output_path.stem}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            max-width: 900px;
            margin: 40px auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #34495e;
            margin-top: 30px;
            border-bottom: 2px solid #ecf0f1;
            padding-bottom: 8px;
        }}
        h3 {{
            color: #555;
            margin-top: 20px;
        }}
        pre {{
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid #3498db;
            overflow-x: auto;
        }}
        code {{
            background-color: #f8f9fa;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }}
        ul, ol {{
            margin-left: 20px;
        }}
        li {{
            margin-bottom: 8px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <pre>{html}</pre>f
    </div>
</body>
</html>
"""
    
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print(f"  Created HTML: {output_path.name}")
    except Exception as e:
        print(f"  Error creating HTML {output_path.name}: {e}")


def process_folder(folder_path: str):
    """
    Process all JSON files in the specified folder.
    
    Args:
        folder_path: Path to the folder containing JSON files
    """
    folder = Path(folder_path)
    
    if not folder.exists():
        print(f"Error: Folder '{folder_path}' does not exist.")
        sys.exit(1)
    
    if not folder.is_dir():
        print(f"Error: '{folder_path}' is not a directory.")
        sys.exit(1)
    
    # Find all JSON files
    json_files = list(folder.glob("*.json"))
    
    if not json_files:
        print(f"No JSON files found in '{folder_path}'")
        sys.exit(1)
    
    print(f"Found {len(json_files)} JSON file(s) to process.\n")
    
    # Prepare CSV files
    strengths_csv = folder / "strengths_evaluation.csv"
    improvements_csv = folder / "improvements_evaluation.csv"
    justifications_csv = folder / "justifications_evaluation.csv"
    
    # Open CSV files for writing
    with open(strengths_csv, 'w', newline='', encoding='utf-8') as strengths_file, \
         open(improvements_csv, 'w', newline='', encoding='utf-8') as improvements_file, \
         open(justifications_csv, 'w', newline='', encoding='utf-8') as justifications_file:
        
        # Create CSV writers
        strengths_writer = csv.writer(strengths_file)
        improvements_writer = csv.writer(improvements_file)
        justifications_writer = csv.writer(justifications_file)
        
        # Write headers
        strengths_writer.writerow(['Filename', 'Strength'])
        improvements_writer.writerow(['Filename', 'Improvement'])
        justifications_writer.writerow(['Filename', 'Justification'])
        
        # Process each JSON file
        for json_file in json_files:
            print(f"Processing: {json_file.name}")
            
            # Load JSON data
            data = process_json_file(json_file)
            if data is None:
                print(f"  Skipped due to errors.\n")
                continue
            
            # Extract chatbot output and create HTML
            chatbot_output = data.get('chatbot_output', '')
            if chatbot_output:
                html_path = folder / f"{json_file.stem}.html"
                create_html_from_chatbot_output(chatbot_output, html_path)
            else:
                print(f"  Warning: No chatbot_output found in {json_file.name}")
            
            # Extract evaluation results
            eval_results = data.get('evaluation_results', {})
            
            # Process strengths
            strengths = eval_results.get('strengths', [])
            if strengths:
                for strength in strengths:
                    strengths_writer.writerow([json_file.name, strength])
                print(f"  Added {len(strengths)} strength(s) to CSV")
            else:
                print(f"  Warning: No strengths found in {json_file.name}")
            
            # Process improvements
            improvements = eval_results.get('improvements', [])
            if improvements:
                for improvement in improvements:
                    improvements_writer.writerow([json_file.name, improvement])
                print(f"  Added {len(improvements)} improvement(s) to CSV")
            else:
                print(f"  Warning: No improvements found in {json_file.name}")
            
            # Process justification
            justification = eval_results.get('justification', '')
            if justification:
                justifications_writer.writerow([json_file.name, justification])
                print(f"  Added justification to CSV")
            else:
                print(f"  Warning: No justification found in {json_file.name}")
            
            print()  # Blank line between files
    
    # Summary
    print("=" * 60)
    print("Processing Complete!")
    print("=" * 60)
    print(f"CSV files created:")
    print(f"  - {strengths_csv.name}")
    print(f"  - {improvements_csv.name}")
    print(f"  - {justifications_csv.name}")
    print(f"\nHTML files created: {len(json_files)}")
    print(f"\nAll files saved to: {folder.absolute()}")


def main():
    """Main entry point for the script."""
    if len(sys.argv) < 2:
        print("Usage: python process_redteam_json.py <folder_path>")
        print("\nExample:")
        print("  python process_redteam_json.py ./redteam_outputs")
        sys.exit(1)
    
    folder_path = sys.argv[1]
    process_folder(folder_path)


if __name__ == "__main__":
    main()