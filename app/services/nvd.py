from __future__ import annotations
import requests
import time
from typing import Optional, Dict, Any

from ..config import settings
from ..models import VulnerabilityFinding
from ..utils import get_logger

logger = get_logger(__name__)

class NVDService:
    def __init__(self):
        self.base_url = settings.nvd_base_url
        self.api_key = settings.nvd_api_key
        self.session = requests.Session()
        if self.api_key:
            self.session.headers.update({"apiKey": self.api_key})
    
    def _make_request(self, endpoint: str, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Make a request to NVD API with rate limiting and error handling"""
        try:
            url = f"{self.base_url}/{endpoint}"
            response = self.session.get(url, params=params, timeout=30)
            response.raise_for_status()
            
            # NVD rate limiting: 5 requests per 30 seconds without API key
            # 50 requests per 30 seconds with API key
            if not self.api_key:
                time.sleep(6)  # Wait 6 seconds between requests without API key
            else:
                time.sleep(0.6)  # Wait 0.6 seconds between requests with API key
                
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"NVD API request failed: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error in NVD API request: {e}")
            return None
    
    def get_cve_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed CVE information from NVD"""
        if not cve_id:
            return None
            
        params = {
            "cveId": cve_id,
            "resultsPerPage": 1
        }
        
        response = self._make_request("cves/2.0", params)
        if response and "vulnerabilities" in response:
            vulnerabilities = response["vulnerabilities"]
            if vulnerabilities:
                return vulnerabilities[0]
        return None
    
    def search_cves_by_keyword(self, keyword: str, limit: int = 5) -> list[Dict[str, Any]]:
        """Search CVEs by keyword (package name, vulnerability name, etc.)"""
        if not keyword:
            return []
            
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": min(limit, 20)  # NVD max is 20 per request
        }
        
        response = self._make_request("cves/2.0", params)
        if response and "vulnerabilities" in response:
            return response["vulnerabilities"]
        return []
    
    def enrich_vulnerability(self, vuln: VulnerabilityFinding) -> VulnerabilityFinding:
        """Enrich ECR vulnerability with NVD data"""
        try:
            # Try to find CVE by name or package
            search_terms = [vuln.name]
            if vuln.package_name:
                search_terms.append(vuln.package_name)
            
            nvd_data = None
            for term in search_terms:
                if not term:
                    continue
                    
                # Search for CVE by keyword
                cves = self.search_cves_by_keyword(term, limit=3)
                if cves:
                    # Get the most relevant CVE (first result)
                    cve_id = cves[0].get("cve", {}).get("id")
                    if cve_id:
                        nvd_data = self.get_cve_details(cve_id)
                        break
            
            if not nvd_data:
                return vuln
            
            # Extract CVE information
            cve_info = nvd_data.get("cve", {})
            descriptions = cve_info.get("descriptions", [])
            nvd_description = None
            for desc in descriptions:
                if desc.get("lang") == "en":
                    nvd_description = desc.get("value")
                    break
            
            # Extract CVSS scores
            metrics = cve_info.get("metrics", {})
            cvss_v3_score = None
            cvss_v3_vector = None
            cvss_v2_score = None
            cvss_v2_vector = None
            
            if "cvssMetricV31" in metrics:
                cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
                cvss_v3_score = cvss_data.get("baseScore")
                cvss_v3_vector = cvss_data.get("vectorString")
            elif "cvssMetricV30" in metrics:
                cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
                cvss_v3_score = cvss_data.get("baseScore")
                cvss_v3_vector = cvss_data.get("vectorString")
            
            if "cvssMetricV2" in metrics:
                cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
                cvss_v2_score = cvss_data.get("baseScore")
                cvss_v2_vector = cvss_data.get("vectorString")
            
            # Extract vendor comments
            vendor_comments = None
            if "vendorComments" in cve_info:
                comments = cve_info["vendorComments"]
                if comments:
                    vendor_comments = comments[0].get("comment")
            
            # Extract references
            references = cve_info.get("references", [])
            ref_list = [ref.get("url") for ref in references if ref.get("url")]
            
            # Update vulnerability with NVD data
            vuln.cve_id = cve_info.get("id")
            vuln.nvd_description = nvd_description
            vuln.nvd_cvss_v3_score = cvss_v3_score
            vuln.nvd_cvss_v3_vector = cvss_v3_vector
            vuln.nvd_cvss_v2_score = cvss_v2_score
            vuln.nvd_cvss_v2_vector = cvss_v2_vector
            vuln.nvd_published_date = cve_info.get("published")
            vuln.nvd_last_modified = cve_info.get("lastModified")
            vuln.nvd_vendor_comments = vendor_comments
            vuln.nvd_references = ref_list
            
            return vuln
            
        except Exception as e:
            logger.error(f"Error enriching vulnerability {vuln.name}: {e}")
            return vuln

# Global NVD service instance
nvd_service = NVDService()
