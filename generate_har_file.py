#!/usr/bin/env python

"""Generate a HAR archive from a given URL.
"""

import os
import argparse
from argparse import RawDescriptionHelpFormatter
import json
import inspect
import io
from browsermobproxy import Server
from selenium import webdriver

def check_selenium_webdriver(selenium_web_driver):
    """Check of the given 'selenium_web_driver' string is a valid
    Selenium web-driver we recognize."""

    return selenium_web_driver in ["Chrome", "Firefox", "Ie"]


def create_selenium_webdriver(selenium_web_driver, selenium_proxy):
    """Create the Selenium web-driver requested, associated to the
    the selenium_proxy given."""

    driver = None

    if selenium_web_driver == "Chrome":
        # profile = webdriver.ChromeProfile()
        # profile.set_proxy(selenium_proxy)
        # driver = webdriver.Chrome(chrome_profile=profile)
        pass
    elif selenium_web_driver == "Firefox":
        profile = webdriver.FirefoxProfile()
        profile.set_proxy(selenium_proxy)
        driver = webdriver.Firefox(firefox_profile=profile)
    elif selenium_web_driver == "Ie":
        profile = webdriver.IeProfile()
        profile.set_proxy(selenium_proxy)
        driver = webdriver.Ie(ie_profile=profile)

    return driver


def save_web_page_stats_to_har(url, webdriver_name='Chrome'):
    """Generate the HAR archive from an URL.
    """
    browsermob_server = Server("<put-here-path-to-program>/browsermob-proxy")
    browsermob_server.start()
    proxy_conn = browsermob_server.create_proxy()
    driver = create_selenium_webdriver(webdriver_name,
                                       proxy_conn.selenium_proxy())
    try:
        proxy_conn.new_har(url, options={'captureHeaders': True})
        driver.get(url)

        har_json = json.dumps(proxy_conn.har, ensure_ascii=False,
                              indent=4, separators=(',', ': '))
        with io.open("results.har", mode='wt', buffering=1,
                     encoding='utf8', errors='backslashreplace',
                     newline=None) as output_har_f:
            output_har_f.write(unicode(har_json))

        # print har_json
    finally:
        proxy_conn.close()
        browsermob_server.stop()
        driver.quit()


def main():
    """Main program."""

    # Get the usage string from the doc-string of this script
    # (ie. usage_string := doc_string )
    current_python_script_pathname = inspect.getfile(inspect.currentframe())
    dummy_pyscript_dirname, pyscript_filename = \
                os.path.split(os.path.abspath(current_python_script_pathname))
    pyscript_filename = os.path.splitext(pyscript_filename)[0]  # no extension
    pyscript_metadata = __import__(pyscript_filename)
    pyscript_docstring = pyscript_metadata.__doc__

    # The ArgParser
    parser = argparse.ArgumentParser(description='Generate a HAR archive'
                                                 'for an URL.',
                                     epilog=pyscript_docstring,
                                     formatter_class=\
                                                  RawDescriptionHelpFormatter)
    parser.add_argument('-w', '--web_driver', nargs=1, default='Chrome',
                        required=False, metavar='web-driver',
                        help='Specify which Selenium web-driver to use to '
                             'load URL. (default: %(default)s)')
    parser.add_argument('urls', metavar='URLs', nargs='+',
                        default='http://www.cnn.com/',
                        help='The list of the URLs to measure into HAR '
                             'archives.')

    args = parser.parse_args()

    if args.web_driver:
        if isinstance(args.web_driver, list):
            # this type check is necessary for some argparse.ArgumentParser()
            # installed in Mac OS/X
            selenium_web_driver = args.web_driver[0]
        else:
            # normal case for argparse.ArgumentParser() in Linux
            selenium_web_driver = args.web_driver

    if check_selenium_webdriver(selenium_web_driver):
        save_web_page_stats_to_har(args.urls[0], selenium_web_driver)


if __name__ == '__main__':
    main()

