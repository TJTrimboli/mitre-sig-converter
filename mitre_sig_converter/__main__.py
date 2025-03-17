#!/usr/bin/env python3
"""
Main entry point for the MITRE ATT&CK Signature Converter.
"""

import os
import sys
import click
from tabulate import tabulate
from tqdm import tqdm

from mitre_sig_converter.utils.logger import setup_logger
from mitre_sig_converter.utils.config_handler import ConfigHandler
from mitre_sig_converter.api.mitre_api import MitreApi
from mitre_sig_converter.converter.yara_converter import YaraConverter
from mitre_sig_converter.converter.sigma_converter import SigmaConverter
from mitre_sig_converter.converter.kql_converter import KqlConverter
from mitre_sig_converter.database.db_handler import DatabaseHandler
from mitre_sig_converter.utils.file_handler import FileHandler

# Set up the logger
logger = setup_logger()
config = ConfigHandler()

@click.group()
def cli():
    """MITRE ATT&CK Signature Converter - Convert techniques to various signature formats."""
    pass

@cli.command()
@click.option("--all", is_flag=True, help="Convert all techniques")
@click.option("--technique", help="Convert a specific technique ID (e.g., T1055)")
@click.option("--tactic", help="Convert techniques for a specific tactic (e.g., defense-evasion)")
@click.option("--format", type=click.Choice(["yara", "sigma", "kql", "all"]), default="all",
              help="Signature format to convert to")
def convert(all, technique, tactic, format):
    """Convert MITRE ATT&CK techniques to signature formats."""
    mitre_api = MitreApi()
    db_handler = DatabaseHandler()
    file_handler = FileHandler()
    
    converters = {
        "yara": YaraConverter(),
        "sigma": SigmaConverter(),
        "kql": KqlConverter()
    }
    
    techniques_to_convert = []
    
    if all:
        logger.info("Converting all techniques")
        techniques_to_convert = mitre_api.get_all_techniques()
    elif technique:
        logger.info(f"Converting technique {technique}")
        tech = mitre_api.get_technique_by_id(technique)
        if tech:
            techniques_to_convert = [tech]
        else:
            logger.error(f"Technique {technique} not found")
            sys.exit(1)
    elif tactic:
        logger.info(f"Converting techniques for tactic {tactic}")
        techniques_to_convert = mitre_api.get_techniques_by_tactic(tactic)
        if not techniques_to_convert:
            logger.error(f"No techniques found for tactic {tactic}")
            sys.exit(1)
    else:
        logger.error("Please specify --all, --technique, or --tactic")
        sys.exit(1)
    
    results = []
    for tech in tqdm(techniques_to_convert, desc="Converting techniques"):
        result_row = {"Technique ID": tech.id, "Name": tech.name}
        
        if format == "all" or format == "yara":
            yara_rule = converters["yara"].convert(tech)
            db_handler.save_signature(tech.id, "yara", yara_rule)
            result_row["YARA"] = "✓"
        
        if format == "all" or format == "sigma":
            sigma_rule = converters["sigma"].convert(tech)
            db_handler.save_signature(tech.id, "sigma", sigma_rule)
            result_row["Sigma"] = "✓"
        
        if format == "all" or format == "kql":
            kql_query = converters["kql"].convert(tech)
            db_handler.save_signature(tech.id, "kql", kql_query)
            result_row["KQL"] = "✓"
        
        results.append(result_row)
    
    click.echo(tabulate(results, headers="keys", tablefmt="pretty"))
    click.echo(f"Converted {len(results)} techniques")

@cli.command()
@click.option("--output", required=True, help="Output directory for exported signatures")
@click.option("--format", type=click.Choice(["yara", "sigma", "kql", "all"]), default="all",
              help="Signature format to export")
def export(output, format):
    """Export signatures to files."""
    db_handler = DatabaseHandler()
    file_handler = FileHandler()
    
    # Ensure output directory exists
    os.makedirs(output, exist_ok=True)
    
    if format == "all" or format == "yara":
        yara_dir = os.path.join(output, "yara")
        os.makedirs(yara_dir, exist_ok=True)
        signatures = db_handler.get_all_signatures("yara")
        for sig in tqdm(signatures, desc="Exporting YARA rules"):
            file_handler.write_signature(
                os.path.join(yara_dir, f"{sig['technique_id'].lower()}.yar"),
                sig["content"]
            )
    
    if format == "all" or format == "sigma":
        sigma_dir = os.path.join(output, "sigma")
        os.makedirs(sigma_dir, exist_ok=True)
        signatures = db_handler.get_all_signatures("sigma")
        for sig in tqdm(signatures, desc="Exporting Sigma rules"):
            file_handler.write_signature(
                os.path.join(sigma_dir, f"{sig['technique_id'].lower()}.yml"),
                sig["content"]
            )
    
    if format == "all" or format == "kql":
        kql_dir = os.path.join(output, "kql")
        os.makedirs(kql_dir, exist_ok=True)
        signatures = db_handler.get_all_signatures("kql")
        for sig in tqdm(signatures, desc="Exporting KQL queries"):
            file_handler.write_signature(
                os.path.join(kql_dir, f"{sig['technique_id'].lower()}.kql"),
                sig["content"]
            )
    
    click.echo(f"Signatures exported to {output}")

@cli.command()
def list():
    """List all techniques in the database."""
    db_handler = DatabaseHandler()
    techniques = db_handler.get_all_techniques()
    
    table_data = []
    for tech in techniques:
        signatures = db_handler.get_signatures_by_technique(tech["id"])
        formats = [sig["format"] for sig in signatures]
        table_data.append({
            "ID": tech["id"],
            "Name": tech["name"],
            "YARA": "✓" if "yara" in formats else "✗",
            "Sigma": "✓" if "sigma" in formats else "✗",
            "KQL": "✓" if "kql" in formats else "✗"
        })
    
    click.echo(tabulate(table_data, headers="keys", tablefmt="pretty"))

@cli.command()
def update():
    """Update the MITRE ATT&CK data."""
    from scripts.download_mitre import download_enterprise_attack
    download_enterprise_attack()
    click.echo("MITRE ATT&CK data updated")

def main():
    """Main entry point."""
    try:
# Create necessary directories
        os.makedirs(os.path.dirname(config.get('LOGGING', 'file')), exist_ok=True)
        cli()
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
        