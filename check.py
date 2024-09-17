from fastapi import FastAPI, HTTPException, Depends, Security, Request, Form
from fastapi.security.api_key import APIKeyHeader
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import List
import os
from dotenv import load_dotenv
import json
from langchain_openai import OpenAI
from langchain.prompts import PromptTemplate
from langchain_community.tools import DuckDuckGoSearchRun
from ipwhois import IPWhois

load_dotenv()

app = FastAPI()
templates = Jinja2Templates(directory="templates")

API_KEY = os.getenv("API_KEY")
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

async def get_api_key(api_key_header: str = Security(api_key_header)):
    if api_key_header == API_KEY:
        return api_key_header
    raise HTTPException(status_code=403, detail="Could not validate credentials")

class IPInput(BaseModel):
    ip_addresses: List[str]

class IPAnalysisResult(BaseModel):
    ip: str
    asn_description: str
    org_name: str
    is_vpn: bool
    vpn_analysis: str

class AnalysisResponse(BaseModel):
    results: List[IPAnalysisResult]

def get_whois_data(ip):
    obj = IPWhois(ip)
    result = obj.lookup_rdap()
    org_entity = next((obj for obj in result.get('objects', {}).values() if 'registrant' in obj.get('roles', [])), {})
    return {
        'ip': ip,
        'asn_description': result.get('asn_description', 'N/A'),
        'org_name': org_entity.get('contact', {}).get('name', 'N/A'),
    }

def analyze_ip(llm, search, whois_data):
    search_query = f"{whois_data['org_name']} VPN service"
    search_result = search.run(search_query)

    prompt = PromptTemplate(
        input_variables=["org_name", "asn_description", "search_result"],
        template="""
Analyze if the following organization is definitively a VPN service provider:

Organization Name: {org_name}
ASN Description: {asn_description}

Search Results:
{search_result}

Determine if this organization is a VPN provider based on these strict criteria:
1. The organization explicitly markets itself as a VPN, private relay, or CDN service.
2. The organization is a well-known, established VPN, private relay, or CDN service provider (e.g., NordVPN, ExpressVPN).
3. There is clear evidence that the organization's primary business is providing VPN, private relay, or CDN services.

Do NOT classify as a VPN if:
- It's a general telecom or internet service provider.
- It's a hosting service or cloud provider.
- There's any ambiguity or lack of clear evidence about VPN services.

Respond in JSON format:
{{
    "is_vpn": true/false,
    "explanation": "Your very brief explanation here"
}}
Set "is_vpn" to true ONLY if you are absolutely certain based on the criteria above.
"""
    )

    response = llm.invoke(prompt.format(
        org_name=whois_data['org_name'],
        asn_description=whois_data['asn_description'],
        search_result=search_result
    ))

    try:
        return json.loads(response)
    except json.JSONDecodeError:
        return {"is_vpn": False, "explanation": "Error parsing result. Assuming not a VPN due to uncertainty."}

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/analyze", response_class=HTMLResponse)
async def analyze_form(request: Request, api_key: str = Form(...), ip_addresses: str = Form(...)):
    if api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API Key")
    
    ip_list = [ip.strip() for ip in ip_addresses.replace(',', '\n').split('\n') if ip.strip()]
    
    llm = OpenAI(temperature=0)
    search = DuckDuckGoSearchRun()
    results = []

    for ip in ip_list:
        try:
            whois_data = get_whois_data(ip)
            vpn_analysis = analyze_ip(llm, search, whois_data)
            
            result = IPAnalysisResult(
                ip=whois_data['ip'],
                asn_description=whois_data['asn_description'],
                org_name=whois_data['org_name'],
                is_vpn=vpn_analysis['is_vpn'],
                vpn_analysis=vpn_analysis['explanation']
            )
            
            results.append(result)
            
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error processing IP {ip}: {str(e)}")
    
    json_results = json.dumps([result.dict() for result in results], indent=4)

    return templates.TemplateResponse("index.html", {
        "request": request, 
        "results": results, 
        "json_results": json_results
    })


@app.post("/analyze_ips", response_model=AnalysisResponse)
async def analyze_ips(ip_input: IPInput, api_key: str = Depends(get_api_key)):
    llm = OpenAI(temperature=0)
    search = DuckDuckGoSearchRun()
    results = []

    for ip in ip_input.ip_addresses:
        try:
            whois_data = get_whois_data(ip)
            vpn_analysis = analyze_ip(llm, search, whois_data)
            
            result = IPAnalysisResult(
                ip=whois_data['ip'],
                asn_description=whois_data['asn_description'],
                org_name=whois_data['org_name'],
                is_vpn=vpn_analysis['is_vpn'],
                vpn_analysis=vpn_analysis['explanation']
            )
            
            results.append(result)
            
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error processing IP {ip}: {str(e)}")

    return AnalysisResponse(results=results)
