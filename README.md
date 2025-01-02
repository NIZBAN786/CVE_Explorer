# CVE_Explorer

```
import gradio as gr # type: ignore
import requests # type: ignore
import nvdlib # type: ignore

def fetch_from_nvd(cve_id):
    result = nvdlib.searchCVE(cveId=cve_id)
    nvd_output = ""

    if result:
        cve = result[0]  # First matching result
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

    return nvd_output


def fetch_from_cna(cve_id):
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    response = requests.get(url)
    cna_output = ""

    if response.status_code == 200:
        data = response.json()
        cna_output += f"\n🔍 CVE Details (From CNA API):\n"
        cna_output += f"🆔 CVE ID: {data['cveMetadata']['cveId']}\n"
        cna_output += f"📅 Published Date: {data['cveMetadata']['datePublished']}\n"
        cna_output += f"📝 Description: {data['containers']['cna']['descriptions'][0]['value']}\n"

        # Display CVSS v3.1 Scores
        if 'metrics' in data['containers']['cna'] and len(data['containers']['cna']['metrics']) > 0:
            cvss = data['containers']['cna']['metrics'][0]['cvssV3_1']
            cna_output += f"⚠️ Severity: {cvss['baseSeverity']}\n"
            cna_output += f"📊 Base Score: {cvss['baseScore']}\n"
        else:
            cna_output += f"⚠️ Severity: N/A\n"
            cna_output += f"📊 Base Score: N/A\n"

        cna_output += f"🔗 Reference Links:\n"
        for ref in data['containers']['cna']['references']:
            cna_output += f"   - {ref['url']}\n"
    else:
        cna_output = "\n❌ No details found in CNA API or invalid CVE ID."

    return cna_output


def get_cve_info(cve_id):
    nvd_details = fetch_from_nvd(cve_id)
    cna_details = fetch_from_cna(cve_id)
    return nvd_details, cna_details


# Create Gradio Interface
interface = gr.Interface(
    fn=get_cve_info,
    inputs=gr.Textbox(label="Enter CVE ID (e.g., CVE-2024-32881)"),
    outputs=[gr.Textbox(label="NVD Details", interactive=False), gr.Textbox(label="CNA Details", interactive=False)],
    title="CVE Information Finder",
    description="Enter a CVE ID to get detailed information from the NVD and CNA ."
)

if __name__ == "__main__":
    interface.launch(share=True)

```


\include{INDEX.md}
