from abc import ABC

DEFAULT_LIMIT = 10


class BaseScraper(ABC):
    base_url: str = None

    def __init__(self, *args, **kwargs):
        pass

    def get_advisories_data(self, limit=DEFAULT_LIMIT, *args, **kwargs):
        all_advisories = []
        self.curr_page_soup = self.get_page()
        while len(all_advisories) < limit:
            advisories = self.get_advisories_from_page()
            all_advisories.extend(advisories)
            next_page = self.get_next_page()
            self.curr_page_soup = next_page

        # get all advisories from called pages and return requested amount.
        truncated = all_advisories[:limit]
        return all_advisories

    def get_advisory_parameters(self, adv_page, parser_class):
        parser = parser_class(adv_page)

        adv_id = parser._get_adv_id()
        adv_title = parser._get_adv_title()
        adv_date = parser._get_adv_publish_date()
        cvss_score = parser._get_adv_cvss_score()
        researcher_info = parser._get_adv_researcher_info()

        cve_dict = parser.get_adv_cve_dict()
        cve_ids = parser._get_adv_cve_ids(cve_dict)
        cvss_vectors = parser._get_adv_cvss_vectors(cve_dict)
        disclosure_links = parser._get_adv_disclosure_links(cve_dict)

        return adv_id, adv_title, adv_date, cvss_score, researcher_info, cve_ids, cvss_vectors, disclosure_links
