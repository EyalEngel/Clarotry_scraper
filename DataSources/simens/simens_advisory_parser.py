from DataSources.basic.base_advisory_parser import BaseAdvisoryParser, CVSS_REGEX, CVE_REGEX
from Utils.regex import regex_extractor

CWE_BASE_URL = "https://cwe.mitre.org/data/definitions/{cwe_code}.html"


class SimensAdvisoryParser(BaseAdvisoryParser):
    page_text: str = None

    def __init__(self, page):
        page_text = page.text
        self.page_dict = self.parse_page_text(page_text)

    def parse_page_text(self, page_text):
        page_components_raw = page_text.split('=======')
        page_components = list(filter(None, page_components_raw))
        page_components = [component.strip('=') for component in page_components]

        page_dict = {}
        title = "META"
        for component in page_components:
            page_dict[title] = component
            next_comp_title = component.split('\r\n\r\n')[-1].strip().strip('=')

            title = next_comp_title
        return page_dict

    def _get_adv_id(self, txt=None):
        if not txt:
            txt = self.page_dict["META"]
        adv_id = regex_extractor("(SSA-\d+)", adv_id_txt)
        return adv_id

    def _get_adv_title(self, txt=None, *args, **kwargs):
        if not txt:
            txt = self.page_dict["META"]
        title = regex_extractor("SSA-\d+:\s(.*)\r\n", adv_title_text)
        return title

    def _get_adv_publish_date(self, txt=None, *args, **kwargs):
        if not txt:
            txt = self.page_dict["META"]
        adv_date = regex_extractor("Publication Date:\s*(\d+-\d+-\d+)\r", date_txt)
        return adv_date

    def _get_adv_cvss_score(self, cvss_score_txt=None, *args, **kwargs):
        if not cvss_score_txt:
            cvss_score_txt = self.page_dict["META"]
        cvss_score = regex_extractor(CVSS_REGEX, cvss_score_txt)
        return cvss_score

    def _get_adv_researcher_info(self, researcher_info_txt=None, *args, **kwargs):
        if not researcher_info_txt:
            if 'ACKNOWLEDGMENTS' not in self.page_dict:
                return []
            researcher_info_txt = self.page_dict["ACKNOWLEDGMENTS"]
        researcher_info = []
        researcher_info_list = researcher_info_txt.split('*')
        summary = researcher_info_list[0]
        for bullet in researcher_info_list[1:]:
            bullet_txt = bullet.strip()
            researcher_info.append(bullet_txt)

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
        cve_dict = {}
        txt = self.page_dict["VULNERABILITY CLASSIFICATION"]
        vulnerabilities = txt.split('*')
        summary = vulnerabilities[0]
        for bullet in vulnerabilities[1:]:
            cve_id = regex_extractor(CVE_REGEX, bullet)
            cve_cvss_score = regex_extractor(CVSS_REGEX, bullet)
            vector = regex_extractor('CVSS Vector:\s+CVSS:3.1(.*)\r\n', bullet)
            cwe_code = regex_extractor('CWE:\s+CWE-(\d+):', bullet)
            # idealy: check that assemlbed link makes sense/ returens 200 etc.
            disclosure_link = CWE_BASE_URL.format(cwe_code=cwe_code)
            cve_dict[cve_id] = {"id": cve_id,  # we might want to save a json or etc.
                                "vector": vector,
                                "cvss_score": cve_cvss_score,
                                "disclosure_link": disclosure_link}
        return cve_dict
