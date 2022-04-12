import sys
from util import is_vulnerable
from util import is_vulnerable_trim
from cve import get_results
from cve import cve_details
from util import preprocess
from util import running_on
from kernel import is_kernel_vul
from kernel import report_analysis
from summary import summary


if __name__ == "__main__":
    mode = input("Enter the mode of operation\n"
                 "1. RAW\n"
                 "2. CMD\n"
                 "3. Linux-OS\n"
                 "0. EXIT\n"
                 ">> ")

    print("\n")
    file_static = "logs-static"
    file_trim = "logs-trim"
    file_dynamic = "logs-dynamic"

    if mode == "1":
        raw = input("Enter the search string:")
        print("Trim Database")
        is_found = is_vulnerable_trim(file_trim, raw)
        if not is_found:
            print("[-] Not Found")
        print("\n")

        print("Static Database")
        is_found = is_vulnerable(file_static, raw)
        if not is_found:
            print("[-] Not Found")
        print("\n")

        print("Dynamic Database")
        is_found = is_vulnerable(file_dynamic, raw)
        if not is_found:
            print("[-] Not Found")
        print("\n")

    if mode == "2":
        vendor = input("Enter the Vendor Name:")
        if vendor == "linux":
            print("\n[!] For linux please use option 3 from main menu\n")
            sys.exit()
        soup = input("Enter the SOUP Name:")
        version = input("Enter the Version:")
        allcves = get_results(vendor, soup, version)
        allcves = allcves['result']['CVE_Items']
        running_on_count = 0
        num_func_count = 0
        found_count = 0

        for cve in allcves:
            is_found = False
            details = cve_details(cve, vendor, soup)
            cve_id = details[0]
            desc = details[1]
            voa = details[2]
            if running_on(voa, vendor, soup):
                running_on_count = running_on_count + 1
                continue

            words = preprocess(desc)

            if not words:
                num_func_count = num_func_count + 1
                continue
            else:
                print(cve_id + " : Search String:" + str(words))
                # print("Search String:" + str(words))

            for word in words:
                raw = word
                if "()" in word:
                    raw = word.replace("()", "")
                # print("Trim Database")
                # is_not_found_in_trim = is_vulnerable_trim(file_trim, raw)
                # print("Static Database")
                is_found_in_static = is_vulnerable(file_static, raw)
                # print("Dynamic Database")
                is_found_in_dynamic = is_vulnerable(file_dynamic, raw)

                if is_found_in_static or is_found_in_dynamic:
                    is_found = True

            if is_found:
                found_count = found_count + 1

        summary(len(allcves), running_on_count, found_count, num_func_count)

    if mode == "3":
        isReportAnalysis = input("Report Analysis (Y/N):")
        if isReportAnalysis == "Y" or isReportAnalysis == "y":
            isFilePresent = input("Is trace-cmd report in /logs-ftrace (Y/N):")
            if isFilePresent == "Y" or isFilePresent == "y":
                vendor = "linux"
                print("Vendor: " + vendor)
                soup = "linux_kernel"
                print("SOUP: " + soup)
                version = input("Enter the version: ")
                print("\n")
                allcves = get_results(vendor, soup, version)
                allcves = allcves['result']['CVE_Items']
                report_analysis(allcves, vendor, soup)
            else:
                print("Please update the required log file\n")
        elif isReportAnalysis == "N" or isReportAnalysis == "n":
            vendor = "linux"
            print("Vendor: " + vendor)
            soup = "linux_kernel"
            print("SOUP: " + soup)
            version = input("Enter the version: ")
            allcves = get_results(vendor, soup, version)
            allcves = allcves['result']['CVE_Items']
            is_kernel_vul(allcves, vendor, soup)
        else:
            print("[-] Invalid input")
            sys.exit()

    if mode == "0":
        sys.exit()


