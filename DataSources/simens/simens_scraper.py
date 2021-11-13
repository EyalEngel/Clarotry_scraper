import logging
import re

import requests
from bs4 import BeautifulSoup
from requests_html import HTMLSession

from DataSources.basic.base_scraper import BaseScraper
from DataSources.simens.simens_advisory import SimensAdvisory
from DataSources.simens.simens_advisory_parser import SimensAdvisoryParser

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

BASE_URL = "https://new.siemens.com/global/en/products/services/cert.html"


# TODO: lint and look at folder name casing.

class SimensScraper(BaseScraper):
    def __init__(self):
        self.base_url = BASE_URL
        self.curr_page = 1
        self.curr_adv_soup = None
        self.curr_page_soup = None

    def get_advisories_from_page(self):
        advisories_in_page = []
        items = self.curr_page_soup.find("div", id="cert")
        adv_link_tags = items.find("div", class_="sups-table").find_all("a", href=re.compile('.*txt'))
        adv_links = list({tag['href'] for tag in adv_link_tags})

        for link in adv_links:
            adv_page = requests.get(link)
            if adv_page.status_code == 200:
                try:
                    parameters = self.get_advisory_parameters(adv_page)
                    advisory = SimensAdvisory(*parameters)
                    logger.info(f"created advisory: {advisory.adv_id}")
                    advisories_in_page.append(advisory)
                except AttributeError:
                    logger.error(f"failed to parse Advisory at {link}")
        return advisories_in_page

    def get_advisory_parameters(self, adv_page):
        return super().get_advisory_parameters(adv_page, parser_class=SimensAdvisoryParser)

    def get_page(self):
        session = HTMLSession()
        req = session.get(self.base_url)
        req.html.render(sleep=20)

        if req.status_code == 200:
            # TODO: choose.
            html_soup = BeautifulSoup(req.html.html, 'html.parser')
            return html_soup

    def get_next_page(self):
        self.curr_page += 1
        return self.get_page()
