from abc import abstractmethod

CVE_REGEX = '(CVE-\d+-\d+)'
CVSS_REGEX = 'CVSS v3.*(\d\.\d)'


class BaseAdvisoryParser:
    @abstractmethod
    def _get_adv_id(self, *args, **kwargs):
        pass

    @abstractmethod
    def _get_adv_title(self, *args, **kwargs):
        pass

    @abstractmethod
    def _get_adv_cve_ids(self, *args, **kwargs):
        pass

    @abstractmethod
    def _get_adv_publish_date(self, *args, **kwargs):
        pass

    @abstractmethod
    def _get_adv_cvss_score(self, *args, **kwargs):
        pass

    @abstractmethod
    def _get_adv_cvss_vectors(self, *args, **kwargs):
        pass

    @abstractmethod
    def _get_adv_researcher_info(self, *args, **kwargs):
        pass

    @abstractmethod
    def _get_adv_disclosure_links(self, *args, **kwargs):
        pass
