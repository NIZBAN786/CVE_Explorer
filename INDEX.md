```
import requests
from bs4 import BeautifulSoup
import random
import nvdlib as nvdlib 

# Fetch the page content
url = "https://www.tenable.com/cve"
response = requests.get(url)
soup = BeautifulSoup(response.content, "html.parser")

# Find all CVE links on the page
cve_links = soup.find_all("a", href=True)
cve_ids = [link['href'].split('/')[-1] for link in cve_links if 'CVE-' in link['href']]

# Randomly select three CVE IDs
random_cve_ids = random.sample(cve_ids, 3)
print(random_cve_ids)
for i in random_cve_ids:
    cve_ids = nvdlib.searchCVE(cveId=i)
    # print(cve_ids)
    nvd_output = ""

    if cve_ids:
        cve = cve_ids[0]  # First matching result
        nvd_output += f"\n🔍 CVE Details (From NVD):\n"
        nvd_output += f"🆔 CVE ID: {cve.id}\n"
        nvd_output += f"📅 Published Date: {cve.published}\n"
        nvd_output += f"📅 Last Modified Date: {cve.lastModified}\n"
        nvd_output += f"📝 Description: {cve.descriptions[0].value}\n"
        nvd_output += f"🔗 Reference Links:\n"
        for ref in cve.references:
            nvd_output += f"   - {ref.url}\n"

        # Display CVSS v3.1 Scores
        if hasattr(cve, 'v31score') and cve.v31score:
            nvd_output += f"⚠️ Severity: N/A\n"  # Severity as N/A (no baseSeverity attribute)
            nvd_output += f"📊 Base Score: {cve.v31score}\n"
        else:
            nvd_output += f"⚠️ Severity: N/A\n"
            nvd_output += f"📊 Base Score: N/A\n"
    else:
        nvd_output = "\n❌ No details found for the provided CVE ID in NVD."
        
    print(nvd_output)
```
