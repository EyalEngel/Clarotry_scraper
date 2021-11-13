from dataclasses import dataclass, field
from typing import List


@dataclass
class BaseAdvisory:
    adv_id: str = None
    title: str = None
    publish_date: str = None
    cvss_score: str = None
    researcher_info: str = None
    cve_ids: List = field(default_factory=list)
    cvss_vectors: List = field(default_factory=list)
    disclosure_links: list = field(default_factory=list)
