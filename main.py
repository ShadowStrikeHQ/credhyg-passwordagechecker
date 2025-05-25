#!/usr/bin/env python3

import argparse
import datetime
import logging
import os
import sys
import csv

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Checks the age of passwords in a CSV file and alerts if any exceed a specified threshold.")
    parser.add_argument("file_path", help="Path to the CSV file containing password data (format: name,username,password,url,creation_date)")
    parser.add_argument("--max_age", type=int, default=90, help="Maximum password age in days before an alert is triggered (default: 90)")
    parser.add_argument("--date_format", type=str, default="%Y-%m-%d", help="Date format in the CSV file (default: %Y-%m-%d)")
    parser.add_argument("--log_level", type=str, default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], help="Set the logging level (default: INFO)")
    return parser

def is_valid_date_format(date_format):
  """
  Validates the given date format string.
  """
  try:
    datetime.datetime.strptime("2024-01-01", date_format)
    return True
  except ValueError:
    return False

def process_password_file(file_path, max_age, date_format):
    """
    Processes the password file, checks password ages, and logs alerts.

    Args:
        file_path (str): Path to the CSV file.
        max_age (int): Maximum allowed password age in days.
        date_format (str): The format of the dates in the CSV.

    Returns:
        int: The number of passwords exceeding the maximum age.
    """

    if not os.path.exists(file_path):
        logging.error(f"File not found: {file_path}")
        return -1

    expired_count = 0
    try:
        with open(file_path, 'r', encoding='utf-8') as csvfile:
            reader = csv.reader(csvfile)
            next(reader, None)  # Skip the header row if it exists

            for row in reader:
                if len(row) < 5:
                    logging.warning(f"Skipping row due to insufficient data: {row}")
                    continue

                name, username, password, url, creation_date_str = row

                try:
                    creation_date = datetime.datetime.strptime(creation_date_str, date_format).date()
                    age = (datetime.date.today() - creation_date).days

                    if age > max_age:
                        logging.warning(f"Password for {name} (username: {username}, URL: {url}) is {age} days old, exceeding the maximum age of {max_age} days.")
                        expired_count += 1

                except ValueError as e:
                    logging.error(f"Invalid date format or value in row: {row}. Error: {e}")

    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        return -1
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return -1

    return expired_count

def main():
    """
    Main function to parse arguments and process the password file.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Set the logging level based on the command-line argument
    logging.getLogger().setLevel(args.log_level)
    
    # Input validation for file path
    if not isinstance(args.file_path, str):
        logging.error("File path must be a string.")
        sys.exit(1)
        
    # Input validation for max_age
    if not isinstance(args.max_age, int) or args.max_age <= 0:
        logging.error("Max age must be a positive integer.")
        sys.exit(1)

    # Input validation for date_format
    if not isinstance(args.date_format, str):
        logging.error("Date format must be a string.")
        sys.exit(1)

    if not is_valid_date_format(args.date_format):
        logging.error(f"Invalid date format: {args.date_format}. Please use a format compatible with datetime.strptime.")
        sys.exit(1)
    
    expired_passwords = process_password_file(args.file_path, args.max_age, args.date_format)

    if expired_passwords == -1:
        sys.exit(1)  # Exit if there was an error processing the file

    if expired_passwords > 0:
        logging.info(f"Found {expired_passwords} passwords exceeding the maximum age.")
    else:
        logging.info("No passwords exceeding the maximum age found.")

if __name__ == "__main__":
    main()

# Usage Examples:
# 1. Check passwords in passwords.csv, alert if older than 90 days (default):
#    python password_age_checker.py passwords.csv

# 2. Check passwords, alert if older than 180 days:
#    python password_age_checker.py passwords.csv --max_age 180

# 3. Specify a different date format:
#    python password_age_checker.py passwords.csv --date_format "%m/%d/%Y"

# 4. Set the logging level to DEBUG:
#    python password_age_checker.py passwords.csv --log_level DEBUG