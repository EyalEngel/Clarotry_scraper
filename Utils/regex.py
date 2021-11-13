import logging
import re

logger = logging.getLogger(__name__)


def regex_extractor(regx, txt):
    logger.debug(f"regx: {regx}\n text: {txt}")
    extracted = re.search(regx, txt).group(1)
    return extracted
