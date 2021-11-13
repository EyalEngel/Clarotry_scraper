import re

from bs4 import BeautifulSoup

from DataSources.basic.base_advisory_parser import BaseAdvisoryParser, CVSS_REGEX, CVE_REGEX
from Utils.regex import regex_extractor


class IcsCertAdvisoryParser(BaseAdvisoryParser):
    adv_soup: BeautifulSoup = None

    def __init__(self, page):
        page = page.content.decode().replace("&nbsp;", ' ').encode('utf-8')
        self.adv_soup = BeautifulSoup(page, 'html.parser')

    def _get_adv_id(self):
        adv_id_txt = self.adv_soup.find("h1", {"id": "page-title"}).text
        adv_id = regex_extractor(".*\((.*)\)", adv_id_txt)
        return adv_id

    def _get_adv_title(self, *args, **kwargs):
        title = self.adv_soup.find("h2", {"id": "page-sub-title"}).text
        return title

    def _get_adv_publish_date(self, *args, **kwargs):
        date_txt = self.adv_soup.find("div", {"class": "submitted meta-text"}).text
        adv_date = regex_extractor('\srelease date:(.*)\W', date_txt)
        return adv_date

    def _get_adv_cvss_score(self, *args, **kwargs):
        cvss_score_txt = self.adv_soup.find('li', text=re.compile("CVSS")).text
        cvss_score = regex_extractor(CVSS_REGEX, cvss_score_txt)
        return cvss_score

    def _get_adv_researcher_info(self, *args, **kwargs):
        reseracher_headline = self.adv_soup.find("h3", text=re.compile("RESEARCHER"))
        reseracher_info = reseracher_headline.find_next().text
        return reseracher_info

    def _get_adv_cve_ids(self, cve_dict, *args, **kwargs):
        ids = [data_dict["id"] for data_dict in cve_dict.values()]
        return ids

    def _get_adv_cvss_vectors(self, cve_dict, *args, **kwargs):
        vectors = [data_dict["vector"] for data_dict in cve_dict.values()]
        return vectors

    def _get_adv_disclosure_links(self, cve_dict, *args, **kwargs):
        links = [data_dict["disclosure_link"] for data_dict in cve_dict.values()]
        return links

    def get_adv_cve_dict(self):
        cve_tags = self._get_cve_tags()
        cve_dict = {}
        for tag in cve_tags:
            cve_id = regex_extractor(CVE_REGEX, tag.text)
            cve_cvss_score = regex_extractor(CVSS_REGEX, tag.text)
            vector = regex_extractor('vector string is.*\((.*)\)', tag.text)
            disclosure_link = tag.find_previous_sibling('h4').find('a')['href']
            cve_dict[cve_id] = {"id": cve_id,  # we might want to save a json or etc.
                                "vector": vector,
                                "cvss_score": cve_cvss_score,
                                "disclosure_link": disclosure_link}
        return cve_dict

    def _get_cve_tags(self):
        cve_tags = []
        vulnerability_overview = self.adv_soup.find("h3", text=re.compile("VULNERABILITY OVERVIEW"))
        curr_tag = vulnerability_overview.find_next()
        while curr_tag.name != 'h3':
            if curr_tag.name == 'p':
                if re.match(CVE_REGEX, curr_tag.text):
                    cve_tags.append(curr_tag)

            curr_tag = curr_tag.find_next()
        return cve_tags
