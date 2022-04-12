import gensim
import os
from tabulate import tabulate


# Preprocesses the description of the CVE
# TODO Need to improve the logic
# TODO search for function in files
def preprocess(text):
    result = []
    progs = ["()", ".c", ".C", ".java", ".JAVA", "_"]
    for word in text.split():
        if word not in gensim.parsing.preprocessing.STOPWORDS and len(word) > 3:
            if any(prog in word for prog in progs):
                result.append(word)
    return result


# Opens and reads a text file
def read_text_file(file_path):
    with open(file_path, 'r') as f:
        return f.read()


# Check if the search string is in the file or not
# TODO Need to improve the search feature
def is_vulnerable(path, search_string):
    table = [['Service', 'Search String', 'Found']]
    os.chdir(path)
    is_found = False
    # iterate through all file
    for f in os.listdir():
        row = []
        # Check whether file is in text format or not
        if f.endswith(".txt"):
            file_path = f"{path}\{f}"
            # call read text file function
            base = os.path.basename(file_path)
            service = os.path.splitext(base)[0]
            content = read_text_file(file_path)
            # TODO Check if the exact word in present in the file or not
            if search_string in content:
                row = [service, search_string, "Yes"]
                is_found = True
                # print(Fore.RED+"[+] Found " + search_string + " in Service " + str(service))
            else:
                row = [service, search_string, "No"]
                # print(Fore.GREEN+"[+] Not Found " + search_string + " in Service " + str(service))
        table.append(row)
    if is_found:
        print(tabulate(table, headers='firstrow', tablefmt='fancy_grid'))
    return is_found


# Check if the search string is in the file or not
# TODO Need to improve the search feature
def is_vulnerable_trim(path, search_string):
    table = [['Service', 'Search String', 'Trimmed']]
    os.chdir(path)
    is_trimmed = False
    # iterate through all file
    for f in os.listdir():
        row = []
        # Check whether file is in text format or not
        if f.endswith(".txt"):
            file_path = f"{path}\{f}"
            # call read text file function
            base = os.path.basename(file_path)
            service = os.path.splitext(base)[0]
            content = read_text_file(file_path)
            if search_string in content:
                row = [service, search_string, "Yes"]
                is_trimmed = True
            else:
                row = [service, search_string, "No"]
        table.append(row)

    if is_trimmed:
        print(tabulate(table, headers='firstrow', tablefmt='fancy_grid'))
    return is_trimmed


def running_on(voa, vendor, soup):
    if not (voa[0] == vendor and voa[1] == soup):
        return True
