import logging
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

from DataSources.basic.base_scraper import BaseScraper
from DataSources.ics_cert.ics_advisory import ICSAdvisory
from DataSources.ics_cert.ics_advisory_parser import IcsCertAdvisoryParser

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

BASE_URL = "https://us-cert.cisa.gov/ics/advisories"


# TODO: lint and look at folder name casing.

class IcsCertScraper(BaseScraper):
    def __init__(self):
        self.base_url = BASE_URL
        self.curr_page = 1
        self.curr_adv_soup = None
        self.curr_page_soup = None
        self.cve_dict = {}

    def get_advisories_from_page(self):
        advisories_in_page = []
        items = self.curr_page_soup.find_all("div", {"class": "item-list"})[0]
        adv_link_tags = items.find_all("span", class_="views-field-title")
        adv_links = [tag.find('a')['href'] for tag in adv_link_tags]

        for link in adv_links:
            url = urljoin(BASE_URL, link)
            adv_page = requests.get(url)
            if adv_page.status_code == 200:
                try:
                    parameters = self.get_advisory_parameters(adv_page)
                    advisory = ICSAdvisory(*parameters)
                    logger.info(f"created advisory: {advisory.adv_id}")
                    advisories_in_page.append(advisory)
                except AttributeError:
                    logger.error(f"failed to parse Advisory at {url}")
        return advisories_in_page

    def get_advisory_parameters(self, adv_page):
        return super().get_advisory_parameters(adv_page, parser_class=IcsCertAdvisoryParser)

    def get_page(self):
        params = {"items_per_page": 100, "page": self.curr_page}
        page = requests.get(self.base_url, params=params)
        if page.status_code == 200:
            html_soup = BeautifulSoup(page.content, 'html.parser')
            return html_soup
        return None

    def get_next_page(self):
        self.curr_page += 1
        return self.get_page()
