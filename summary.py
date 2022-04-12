def summary(total_cves, running_on_cves, found_count, num_func_count):
    print("\n\n")
    print("[+] Running On CVEs\t\t\t" + str(running_on_cves))
    print("[+] Remaining CVEs\t\t\t"+str(total_cves-running_on_cves))
    print("    " + str(num_func_count) + " CVEs With No Function Name")
    not_found_count = total_cves - running_on_cves - num_func_count - found_count
    if not (total_cves-running_on_cves == num_func_count):
        print("    " + str(not_found_count) + " CVEs With Function Name")
        print("      " + str(found_count) + " Function Found In Logs")
        # print("      " + str(total_cves-running_on_cves-num_func_count-found_count) + " Function Not Found In Logs")
    print("-"*50)
    print("[+] Total CVEs\t\t\t\t" + str(total_cves))
    print("\n")


def summary_ker(total_cves, running_on_cves, is_not_triggered_count):
    print("\n\n")
    print("[+] Running On CVEs\t\t" + str(running_on_cves))
    print("[+] Remaining CVEs\t\t"+str(total_cves-running_on_cves))
    print("    " + str(total_cves-running_on_cves-is_not_triggered_count) + " CVEs Require Analysis")
    print("    " + str(is_not_triggered_count) + " CVEs Not Triggered")
    print("-"*50)
    print("[+] Total CVEs\t\t\t" + str(total_cves))
    print("\n")
