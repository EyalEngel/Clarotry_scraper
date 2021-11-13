import json
import logging

import requests

from DataSources.simens.simens_advisory import SimensAdvisory
from DataSources.simens.simens_advisory_parser import SimensAdvisoryParser
from DataSources.simens.simens_scraper import SimensScraper

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

BASE_URL = "https://new.siemens.com/global/en/products/services/cert.html"


# TODO: lint and look at folder name casing.

class AltSimensScraper(SimensScraper):
    def __init__(self):
        self.base_url = BASE_URL
        self.curr_page = 1
        self.curr_adv_soup = None
        self.curr_page_soup = None

    def get_advisories_data(self, limit):
        # only gets one-page
        advisories_source_link = "https://cert-portal.siemens.com/productcert/json/advisories.json"
        req = requests.get(advisories_source_link)
        advisories_generator = (adv for adv in json.loads(req.content))
        all_advisories = []
        while len(all_advisories) < limit:
            try:
                advisory = next(advisories_generator)
                parameters = self.get_advisory_parameters(advisory)
                advisory = SimensAdvisory(*parameters)
                logger.info(f"created advisory: {advisory.adv_id}")
                all_advisories.append(advisory)
            except Exception:
                logger.error(f"failed to parse Advisory {advisory['id']} at {advisory['txt_url']}")
        return all_advisories

    def get_advisory_parameters(self, advisory_dict):
        full_text_link = advisory_dict['txt_url']
        full_text = requests.get(full_text_link)
        parser = SimensAdvisoryParser(full_text)

        adv_id = advisory_dict['id']
        adv_title = advisory_dict['title']
        adv_date = advisory_dict['last_update']
        cvss_score = advisory_dict.get('cvss_score')
        if "ACKNOWLEDGMENTS" in parser.page_dict:
            researcher_info = parser._get_adv_researcher_info(parser.page_dict["ACKNOWLEDGMENTS"])
        else:
            researcher_info = None

        cve_dict = parser.get_adv_cve_dict()
        cve_ids = advisory_dict['cve-ids']
        cvss_vectors = [_dict["vector"] for _dict in cve_dict.values()]
        disclosure_links = [_dict["vector"] for _dict in cve_dict.values()]

        return adv_id, adv_title, adv_date, cvss_score, researcher_info, cve_ids, cvss_vectors, disclosure_links
