import gradio as gr
import requests
from bs4 import BeautifulSoup
import random
import nvdlib
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
import asyncio
import aiohttp
import csv
from typing import List, Tuple

# Cache for NVD and CNA responses
@lru_cache(maxsize=100)
def fetch_from_nvd(cve_id: str) -> str:
    result = nvdlib.searchCVE(cveId=cve_id)
    if not result:
        return "\n❌ No details found for the provided CVE ID in NVD."
    
    cve = result[0]
    return f"\n🔍 CVE Details (From NVD):\n" + \
           f"🆔 CVE ID: {cve.id}\n\n" + \
           f"📅 Published Date: {cve.published}\n\n" + \
           f"📅 Last Modified Date: {cve.lastModified}\n\n" + \
           f"📝 Description: {cve.descriptions[0].value}\n\n" + \
           f"🔗 Reference Links:\n\n" + \
           "".join(f"   - {ref.url}\n" for ref in cve.references)

async def fetch_from_cna_async(cve_id: str, session: aiohttp.ClientSession) -> str:
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    try:
        async with session.get(url) as response:
            if response.status != 200:
                return "\n❌ No details found in CNA API or invalid CVE ID."
            
            data = await response.json()
            output = [
                f"\n🔍 CVE Details (From CNA API):",
                f"🆔 CVE ID: {data['cveMetadata']['cveId']}",
                f"📅 Published Date: {data['cveMetadata']['datePublished']}",
                f"📝 Description: {data['containers']['cna']['descriptions'][0]['value']}"
            ]
            
            if 'metrics' in data['containers']['cna']:
                cvss = data['containers']['cna']['metrics'][0]['cvssV3_1']
                output.extend([f"⚠️ Severity: {cvss['baseSeverity']}", f"📊 Base Score: {cvss['baseScore']}"])
            
            output.append("🔗 Reference Links:")
            output.extend(f"   - {ref['url']}" for ref in data['containers']['cna']['references'])
            
            return "\n".join(output)
    except Exception:
        return "\n❌ Error fetching data from CNA API."

async def get_cve_info_async(cve_id: str) -> Tuple[str, str]:
    async with aiohttp.ClientSession() as session:
        nvd_future = asyncio.get_event_loop().run_in_executor(None, fetch_from_nvd, cve_id)
        cna_future = fetch_from_cna_async(cve_id, session)
        nvd_details, cna_details = await asyncio.gather(nvd_future, cna_future)
        return nvd_details, cna_details

def get_cve_info(cve_id: str) -> Tuple[str, str]:
    return asyncio.run(get_cve_info_async(cve_id))

async def fetch_random_cves_async() -> str:
    async with aiohttp.ClientSession() as session:
        async with session.get("https://www.tenable.com/cve") as response:
            soup = BeautifulSoup(await response.text(), "html.parser")
            cve_links = soup.find_all("a", href=True)
            cve_ids = [link['href'].split('/')[-1] for link in cve_links if 'CVE-' in link['href']]
            random_cve_ids = random.sample(cve_ids, min(3, len(cve_ids)))

            tasks = [get_cve_info_async(cve_id) for cve_id in random_cve_ids]
            results = await asyncio.gather(*tasks)
            
            output = ["**🔍 Random CVEs :**"]
            for nvd_details, _ in results:
                output.extend(["\n---", nvd_details])
            
            return "\n".join(output)

def fetch_random_cves() -> str:
    return asyncio.run(fetch_random_cves_async())

# Function to save the CVE details to a CSV file with error handling
def save_to_csv(nvd_details: str, cna_details: str, cve_id: str) -> None:
    file_name = f"CVE_{cve_id}.csv"
    
    # Split details safely
    nvd_details_lines = nvd_details.split("\n") if nvd_details else []
    cna_details_lines = cna_details.split("\n") if cna_details else []

    # Safely extract the description and references
    nvd_description = nvd_details_lines[3] if len(nvd_details_lines) > 3 else "Description not available"
    nvd_references = "\n".join([line.strip() for line in nvd_details_lines[7:]]) if len(nvd_details_lines) > 7 else "References not available"
    
    cna_description = cna_details_lines[3] if len(cna_details_lines) > 3 else "Description not available"
    cna_references = "\n".join([line.strip() for line in cna_details_lines[6:]]) if len(cna_details_lines) > 6 else "References not available"
    
    # Open the file in write mode
    with open(file_name, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(["Source", "CVE ID", "Published Date", "Description", "Reference Links"])

        # Write NVD details
        writer.writerow(["NVD", cve_id, "N/A", nvd_description, nvd_references])

        # Write CNA details
        writer.writerow(["CNA", cve_id, "N/A", cna_description, cna_references])

# Gradio Interface
with gr.Blocks() as demo:
    random_cve_box = gr.Markdown(fetch_random_cves())
    
    with gr.Row():
        cve_input = gr.Textbox(label="Enter CVE ID (e.g., CVE-2024-32881)")
        nvd_output = gr.Textbox(label="NVD Details", interactive=False)
        cna_output = gr.Textbox(label="CNA Details", interactive=False)
        submit_btn = gr.Button("Get CVE Info")
    
    def on_submit(cve_id: str):
        nvd_details, cna_details = get_cve_info(cve_id)
        save_to_csv(nvd_details, cna_details, cve_id)  # Save the details into the CSV
        return nvd_details, cna_details
    
    submit_btn.click(on_submit, inputs=cve_input, outputs=[nvd_output, cna_output])
    demo.load(fetch_random_cves, inputs=None, outputs=random_cve_box)

if __name__ == "__main__":
    demo.launch(share=True)
