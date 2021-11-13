from DataSources.ics_cert.ics_cert_scraper import IcsCertScraper
from DataSources.simens.alt_simens_scraper import AltSimensScraper
from DataSources.simens.simens_scraper import SimensScraper

data_source = {'ics_cert': IcsCertScraper,
               'simens': SimensScraper,
               'alt_simens': AltSimensScraper}


def main():
    var_limit = 100
    var = 'alt_simens'
    scraper = data_source[var]()
    results = scraper.get_advisories_data(limit=var_limit)
    print('done.')


if __name__ == '__main__':
    main()
