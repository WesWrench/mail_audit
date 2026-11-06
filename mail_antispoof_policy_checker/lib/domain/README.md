Download `hybridwhois`, `whoisit` and `whoisitlegacy` from  
<https://dev.azure.com/deloittefranceosc/Cyber%20OSC%20-%20GIT/_git/OSINT?path=/Scripts/Utils/Whois>

You should now have three existing Python modules/directories:

- `domain_availability_checker`
- `domain_availability_service_checker`
- `tld_enumerator`

To use them properly, download the three additional modules:

- `hybridwhois`
- `whoisit`
- `whoisitlegacy`

Then place these three new directories at the **same level** in the filesystem as the existing ones (i.e. in the same parent folder).

The resulting structure should look like:

```text
project_root/
├── domain_availability_checker/
├── domain_availability_service_checker/
├── tld_enumerator/
├── hybridwhois/
├── whoisit/
└── whoisitlegacy/
```