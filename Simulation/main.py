import re
from random import random
import yaml
import subprocess
import time
import sys
from datetime import datetime
import os

import vulnerables

# Global vars
config_data = {}
techniques_data = {}
timestamp = datetime.now()
new_log = timestamp.strftime("Log-%m-%d-%Y-%H-%M-%S")
vulnerable_files = vulnerables.store_vulnerabilities('analyzer_files/windows-vulnerabilities.txt')


# CLI execution
def execute_cli_command(command):
    try:
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()
        exit_code = process.wait()
        if exit_code != 0:
            raise Exception(f"Error executing command: {error.decode('utf-8')}")
        print("Command executed successfully")
    except Exception as e:
        print(f"An error occurred: {str(e)}")


# Powershell execution
def execute_powershell_command(command):
    try:
        process = subprocess.Popen(['powershell.exe', command], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   stdin=subprocess.PIPE)
        output, error = process.communicate()
        exit_code = process.wait()
        if exit_code != 0:
            raise Exception(f"Error executing command: {error.decode('utf-8')}")
        print("Command executed successfully")
    except Exception as e:
        print(f"An error occurred: {str(e)}")


# Console progress bar in sequenced attack

def wait_with_progress(minutes):
    wait_time = minutes * 60
    update_interval = 0.2
    start_time = time.monotonic()
    bar_length = 30

    try:
        while True:
            elapsed_time = time.monotonic() - start_time
            progress_percent = elapsed_time / wait_time
            completed_segments = int(bar_length * progress_percent)
            remaining_segments = bar_length - completed_segments
            bar = "[" + "=" * completed_segments + " " * remaining_segments + "]"
            sys.stdout.write(f"\rLoading {bar} {int(progress_percent * 100)}%")
            sys.stdout.flush()
            if elapsed_time >= wait_time:
                break
            time.sleep(update_interval)
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        print()


# Load main configuration file into the dictionary

def load_config():
    global config_data

    print("Select config file your path starts with: Configs/[config name].YAML:")
    print()
    path = "Configs/APT3.YAML"
    input_config = input()
    if input_config != "":
        path = "Configs/" + input_config + ".YAML"

    try:
        with open(path, 'r') as file:
            config = yaml.safe_load(file)
            print(f"Loaded configuration file from '{path}'.")
    except FileNotFoundError:
        print(f"Error: could not open file '{path}'. Using default config file instead.")
        with open('Configs/APT3.YAML', 'r') as file:
            config = yaml.safe_load(file)

    techniques = {}
    technique_count = config['technique_count']
    for i in range(1, technique_count + 1):
        technique_name = f'technique{i}'
        technique_data = config['techniques'][technique_name]
        technique = {
            'description': technique_data['description'],
            'name': technique_data['name'],
            'path': technique_data['path'],
            'option': technique_data['option'],
        }
        if 'run' in technique_data:
            technique['run'] = technique_data['run']
        if 'sequence_time_before' in technique_data:
            technique['sequence_time_before'] = technique_data['sequence_time_before']
        if 'sequence_time_after' in technique_data:
            technique['sequence_time_after'] = technique_data['sequence_time_after']
        techniques[technique_name] = technique

    config_data = {
        'title': config['title'],
        'technique_count': technique_count,
        'sequenced': config['sequenced'],
        'techniques': techniques,
    }


def print_config():
    print('Path:', config_data['path'])
    print('Title:', config_data['title'])
    print('Technique count:', config_data['technique_count'])
    print('Sequenced:', config_data['sequenced'])
    print('Techniques:')
    for technique_name, technique_data in config_data['techniques'].items():
        print(f"  Technique {technique_name}:")
        print(f"    Description: {technique_data['description']}")
        print(f"    Name: {technique_data['name']}")
        print(f"    Path: {technique_data['path']}")
        print(f"    Option: {technique_data['option']}")
        if 'run' in technique_data:
            print(f"    Run: {technique_data['run']}")
        if 'sequence_time_before' in technique_data:
            print(f"    Sequence time before: {technique_data['sequence_time_before']}")
        if 'sequence_time_after' in technique_data:
            print(f"    Sequence time after: {technique_data['sequence_time_after']}")


# Load data from techniques into dictionary

def load_technique_data():
    global config_data
    global techniques_data

    techniques = config_data['techniques']
    for technique in techniques.values():
        with open(technique['path']) as f:
            technique_data = yaml.safe_load(f)
        technique_name = technique['name']
        techniques_data[technique_name] = {
            'count': technique_data['count'],
            'options': technique_data['options'],
            'defaultoutputfile': technique_data['defaultoutputfile']
        }


# create log file and concat the comand with output file

def log_output(technique_details, technique_identifier):
    global techniques_data
    global new_log

    if not os.path.exists(new_log):
        os.mkdir(new_log)

    if 'outfile' in technique_details and technique_details['outfile'] != "":
        if technique_details['outfile'] == "default":
            return technique_details['write'] + " >> " \
                + new_log + "/" + techniques_data[technique_identifier]['defaultoutputfile']
        else:
            return technique_details['write'] + " >> " \
                + new_log + "/" + technique_details['outfile']
    return technique_details['write']


def run_techniques():
    global config_data, techniques_data
    technique_count = config_data.get("technique_count")
    if not technique_count:
        print("No technique count specified in config file")
        return

    print(config_data.get("title"))
    if technique_count == 1:
        print(f"Running technique count: {technique_count} technique")
    else:
        print(f"Running count: {technique_count} techniques")
    print("-------------------------------------")
    print()

    # Loop over specified technique count
    for i in range(1, config_data['technique_count'] + 1):
        # Get technique details
        technique_index = f"technique{i}"
        technique = config_data['techniques'][technique_index]
        technique_identifier = technique['name']
        technique_description = technique['description']
        technique_sequence_time_before = technique.get('sequence_time_before', 0)
        technique_sequence_time_after = technique.get('sequence_time_after', 0)

        if not technique['run']:
            print(f"{technique_index} was not run.")
            continue

        if technique_index not in config_data['techniques']:
            continue

        # Load technique commands from YAML file
        chosen_option = technique['option']
        if chosen_option == 0:
            print(f"No attack option specified for {technique_index}")
            continue

        # get the correct attack option based on the first file
        chosen_attack = f'attack{chosen_option}'
        valid_option = None
        available_options = techniques_data[technique_identifier]['options']
        for option_key in available_options.keys():
            if chosen_attack in option_key:
                valid_option = option_key
                break

        if valid_option is None:
            print(f"Invalid attack option specified for {technique_index}")
            continue

        technique_commands = available_options.get(valid_option)

        # Wait for sequence time before executing commands if attack is sequenced
        if config_data['sequenced']:

            if technique_sequence_time_before == "random":
                time.sleep(random.randint(60, 3600))

            elif technique_sequence_time_before > 0:
                print(f"Waiting {technique_sequence_time_before} minutes before executing "f"{technique_identifier}...")
                wait_with_progress(technique_sequence_time_before)

        # Execute technique commands
        print(f"Executing {technique_index} {technique_identifier} ({valid_option})")
        print(technique_description)
        print()
        for current_technique, details in technique_commands.items():

            print(f"Executing: {current_technique}")
            if 'description' in details:
                print("Details:", details['description'])
            else:
                print("No description provided")
            command_type = details['type']

            if command_type == 'CLI':
                execute_cli_command(log_output(details, technique_identifier))
            elif command_type == 'PS':
                execute_powershell_command(log_output(details, technique_identifier))
            print("-------------------------------------")

        # Wait for sequence time after executing commands if attack is sequenced
        if config_data['sequenced']:

            if technique_sequence_time_after == "random":
                time.sleep(random.randint(60, 3600))

            elif technique_sequence_time_after > 0:
                print(f"Waiting {technique_sequence_time_after} minutes after executing "f"{technique_identifier}...")
                wait_with_progress(technique_sequence_time_after)
        print("Execution finished")


def print_techniques():
    global techniques_data

    for technique_name, technique_data in techniques_data.items():
        print(f"Technique: {technique_name}")
        print(f"Count: {technique_data['count']}")
        print("Options:")
        for option_name, option_data in technique_data['options'].items():
            print(f"\tOption: {option_name}")
            for command_name, command_data in option_data.items():
                print(f"\t\tCommand: {command_name}")
                print(f"\t\tType: {command_data['type']}")
                print(f"\t\tWrite: {command_data['write']}")


def analyze_techniques():
    print("Enter the log file name or timestamp")
    try:
        log_file = input()
        os.chdir(log_file)
        file_names = os.listdir()
        print("analyzing log ", log_file)
    except Exception as file_error:
        print(f"Error choosing file : {file_error}")
        return
    start_time = time.time()
    vulnerable_files_results = []
    #Go through each file in the directory
    for file_name in file_names:
        regex_results = {}
        print(f"Analyzing {file_name}...")
        print("analyzing technique")
        # Go through each line in the file and check for known vulnerabilities
        with open(file_name, 'r') as file:
            # check known vulnerabilities
            for line in file:
                line = line.replace('\n', '').replace(' ', '').lower()
                for vulnerability in vulnerable_files:
                    if vulnerability['path'].lower().replace(' ', '') in line:
                        vulnerable_files_results.append({
                            'path': line,
                            'severity': vulnerability['severity'],
                            'description': vulnerability['description']
                        })

        # check regex patterns in log file
        with open(file_name, 'r') as file2:
            # read the file contents and open file once more cuz python
            log_contents = file2.read()
            for pattern_name, pattern in vulnerables.patterns.items():
                regex_matches = re.findall(pattern, log_contents)
                regex_results[pattern_name] = regex_matches

        print(f"Finished analyzing {file_name}")

        # for loop to delete duplicate entries in regex_results
        for pattern_name, matches in regex_results.items():
            if matches:
                regex_results[pattern_name] = list(set(matches))

        # for loop to delete duplicate entries in vulnerable_files_results
        #for entry in vulnerable_files_results:
        #    if entry in vulnerable_files_results:
        #        vulnerable_files_results = list(set(vulnerable_files_results))

        # Write results to file
        with open('../analyzer.txt', 'a') as output:
            output.write("*** File " + file_name + " analyzed ***\n")
            for entry in vulnerable_files_results:
                output.write("File: " + entry['path'] + "\n")
                output.write("Severity: " + entry['severity'] + "\n")
                output.write("Description: " + entry['description'] + "\n")
            output.write("*** Regex specified information ***\n")
            for pattern_name, matches in regex_results.items():
                if matches:
                    output.write(f"{pattern_name}:\n")
                    for match in matches:
                        output.write(f"  {match}\n")
    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"Elapsed time of {elapsed_time} seconds")

if __name__ == "__main__":
    user_input = ""
    print("Press 1 to load config\nPress 2 to analyze log")
    user_input = input()
    if user_input == "1":
        load_config()
        load_technique_data()
        run_techniques()
        print("Attack successfully executed")
        time.sleep(10)
    elif user_input == "2":
        # for index, item in enumerate(vulnerable_files, start=1):
        #   print(f"Line {index}.")
        #    print(f"Path: {item['path']}")
        #    print(f"Severity: {item['severity']}")
        #    print(f"Description: {item['description']}")
        #    print()
        analyze_techniques()
        print("Analysis finished")
    else:
        print("invalid input")

