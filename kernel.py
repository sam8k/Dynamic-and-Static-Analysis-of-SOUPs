from cve import cve_details
from util import preprocess
from util import running_on
from summary import summary_ker
from tabulate import tabulate


def is_kernel_vul(allcve, vendor, soup):
    cmd = "trace-cmd record -p function"
    table = [['CVE', 'Vulnerable Function']]
    running_on_count = 0
    for cve in allcve:
        details = cve_details(cve, vendor, soup)
        cve_id = details[0]
        desc = details[1]
        voa = details[2]

        if running_on(voa, vendor, soup):
            running_on_count = running_on_count + 1
            continue

        words = preprocess(desc)
        if not words:
            continue
        for word in words:
            if "()" in word:
                word = word.replace("()", "")
            with open("linux_func_list.txt", "r") as f:
                lines = f.readlines()
                # print(lines)
                for line in lines:
                    line = line.strip()
                    if word == line:
                        row = [cve_id, line]
                        cmd = cmd + " -l " + line
                        # print("/bin/echo " + line + " >> /sys/kernel/tracing/set_ftrace_filter")
                        table.append(row)
                        break

    # print(tabulate(table, headers='firstrow', tablefmt='fancy_grid'))
    print("[+] To trace vulnerable functions run:\n" + cmd)
    print("\n\n[+] To generate the report run:\ntrace-cmd report\n\n")


def report_analysis(allcve, vendor, soup):
    file_linux_func = "..\\logs-ftrace\\ftrace-out.txt"
    table = [['CVE', 'Vulnerable Function', 'isTriggered']]
    cve_funcs = []
    running_on_count = 0
    is_not_triggered_count = 0
    cve_with_func_count = 0
    for cve in allcve:
        details = cve_details(cve, vendor, soup)
        cve_id = details[0]
        desc = details[1]
        voa = details[2]

        if running_on(voa, vendor, soup):
            running_on_count = running_on_count + 1
            continue

        words = preprocess(desc)

        if not words:
            continue
        for word in words:
            if "()" in word:
                word = word.replace("()", "")
            with open("linux_func_list.txt", "r") as f:
                lines = f.readlines()
                # print(lines)
                for line in lines:
                    line = line.strip()
                    if word == line:
                        cve_with_func_count = cve_with_func_count + 1
                        map = [cve_id, line]
                        cve_funcs.append(map)
                        break

    for cve_func in cve_funcs:
        isTriggered = False
        with open(file_linux_func, "r") as f:
            lines = f.readlines()
            for line in lines:
                line = line.strip()
                if cve_func[1] in line:
                    isTriggered = True
                    break
            if isTriggered:
                row = [cve_func[0], cve_func[1], "Yes"]
                table.append(row)
            else:
                row = [cve_func[0], cve_func[1], "No"]
                table.append(row)
                is_not_triggered_count = is_not_triggered_count + 1

    print("[+] CVEs With Function ", cve_with_func_count)
    print("[+] isTriggerd Functions", cve_with_func_count-is_not_triggered_count)
    print("[+] isNotTriggered Functions", is_not_triggered_count)
    print(tabulate(table, headers='firstrow', tablefmt='fancy_grid'))
    summary_ker(len(allcve), running_on_count, is_not_triggered_count)
