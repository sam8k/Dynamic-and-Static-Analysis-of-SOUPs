# Dynamic and Static Analysis of SOUPs

Performs raw search of the given function name from the static and dynamic function trace database.

Automates the function name extraction from the list of CVEs of a given SOUP and perform search operation against the static and dynamic function trace database.


## Installation

Sync the repo and run

```bash
python run.py
```

## Usage
### How does this tool works?
There are 3 mode of operation RAW mode, CMD mode and Linux CVE analysis mode

### RAW mode
This is a simple search feature that takes an input (search string or function name) from the user and check if that string is present in the static and dynamic function trace database.

```python
> python .\run.py
Enter the mode of operation
1. RAW
2. CMD
3. Linux-OS
0. EXIT
>> 1


Enter the search string:test123
Trim Database
[-] Not Found


Static Database
[-] Not Found


Dynamic Database
[-] Not Found
```



### CMD mode
In this mode of operation, the programs accept soup, vendor, and version as an input from the user and using the NVD APIs fetches all the CVEs for the given SOUP.

The program checks if the CVE is applicable to the given SOUP, or it was reported for the application running on the given SOUP. It discards such CVEs.

From the description of the remaining CVEs the program extracts the function name and uses that data to compare against the static and dynamic database function trace database.

The program also generates a summary of its finding.

```python
> python .\run.py
Enter the mode of operation
1. RAW
2. CMD
3. Linux-OS
0. EXIT
>> 2


Enter the Vendor Name:apache
Enter the SOUP Name:struts
Enter the Version:1.1

[+] No Of CVEs 9
[+] Retrieving CVEs From The NVD Database
[+] Finished Retrieving


CVE-2016-1182 : Search String:['ActionServlet.java']
CVE-2016-1181 : Search String:['ActionServlet.java']
CVE-2006-1546 : Search String:["'org.apache.struts.taglib.html.Constants.CANCEL'"]



[+] Running On CVEs                     1
[+] Remaining CVEs                      8
    5 CVEs With No Function Name
    3 CVEs With Function Name
      0 Function Found In Logs
--------------------------------------------------
[+] Total CVEs                          9
```


### Linux CVE analysis mode
This mode of operation has two functions 

* CMD generation function 

Generates the trace-cmd command for the user which can be directly used in the trace environment to generate the call graph.

```python
> python .\run.py
Enter the mode of operation
1. RAW
2. CMD
3. Linux-OS
0. EXIT
>> 3


Report Analysis (Y/N):n
Vendor: linux
SOUP: linux_kernel
Enter the version: 4.4.0

[+] No Of CVEs 1780
[+] Retrieving CVEs From The NVD Database
[+] Finished Retrieving


[+] To trace vulnerable functions run:
trace-cmd record -p function -l scsi_ioctl -l sock_getsockopt -l vgacon_scrolldelta -l ext4_write_inline_data_end -l add_partition -l device_add -l block_invalidatepage -l cgroup_release_agent_write -l fget -l packet_set_ring -l fuse_do_getattr -l make_bad_inode -l get_user_pages -l vt_ioctl -l bpf_map_update_elem -l relay_open -l k_ascii -l kmem_cache_alloc_bulk -l debugfs_remove -l ptrace_may_access -l ptrace_may_access  -l fsnotify_put_mark


[+] To generate the report run:
trace-cmd report
```

* Call graph to CVE mapping mode 

In this mode of operation, the programs accept the linux version as an input from the user and using the NVD APIs it fetches all the CVEs for the given SOUP. 
The program checks if the CVE is applicable to the given SOUP, or it was reported for the application running on the given SOUP. It discards such CVEs. From the description of the remaining CVEs the program extracts the function name and uses that data to compare against ftrace logs.The program also generates a summary of its finding.



## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.