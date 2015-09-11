#!/usr/bin/env python

"""Generate HAR archives from a set of URLs and report the different
performance timings (profiling) of each object requested for rendering
each URL given.
"""

import sys
import os
import argparse
from argparse import RawDescriptionHelpFormatter
import json
import inspect
import io
import re
import socket
from browsermobproxy import Server
from selenium import webdriver
from selenium.webdriver.chrome.options import Options as ChromeOptions


# pylint: disable=too-few-public-methods
class NullChromeOptions(ChromeOptions):
    """ A null Chrome Options for the Selenium Chrome webdriver.
    The issue is that the Selenium Chrome webdriver:

        https://github.com/browserstack/selenium-webdriver-python/blob/master/selenium/webdriver/chrome/webdriver.py#L52

    adds the 'chrome_options.to_capabilities()' to the
    'desired_capabilities' dictionary, which is used
    afterwards in the code. But the default
    'Chrome.Options.to_capabilities()' method always add a
    'chromeOptions' key with a dictionary, which dictionary
    in turn has an 'args' and an 'extensions' keys:

        https://github.com/browserstack/selenium-webdriver-python/blob/master/selenium/webdriver/chrome/options.py#L145

    We need a Chrome.Options object whose 'toCapabilities()
    method always return an empty dictionary, so everything
    in the 'desired_capabilities' dictionary is not affected.
    """

    def __init__(self):
        """ Instance constructor. """
        ChromeOptions.__init__(self)

    # pylint: disable=no-self-use
    def to_capabilities(self):
        """ Returns an empty dictionary (null Chrome options for the
        Selenium webdriver). """
        return {}


def check_selenium_webdriver(selenium_web_driver):
    """Check if the given 'selenium_web_driver' string is a valid
    Selenium web-driver we recognize."""

    return selenium_web_driver in ["Chrome", "Firefox", "Ie"]


def create_selenium_webdriver(selenium_web_driver, browsermob_proxy):
    """Create the Selenium web-driver requested, associated to the
    the browsermob_proxy given."""

    driver = None

    if selenium_web_driver == "Chrome":
        chromedriver = "<PUT-HERE-PATH-TO>/bin/chromedriver"
        os.environ["webdriver.chrome.driver"] = chromedriver

        chrome_proxy = browsermob_proxy.proxy

        # For the code below, see also:
        # pylint: disable=line-too-long
        #    https://code.google.com/p/selenium/wiki/DesiredCapabilities
        #    https://code.google.com/p/selenium/source/browse/py/selenium/webdriver/common/desired_capabilities.py
        #
        # (there is code there for other Selenium Web-drivers, like IPhone,
        # Android, and PhantomJS), and
        #
        #    https://code.google.com/p/selenium/source/browse/py/test/selenium/webdriver/common/proxy_tests.py
        #    https://code.google.com/p/selenium/source/browse/py/selenium/webdriver/common/proxy.py
        #
        chrome_desired_caps = {
            "browserName": "chrome",
            "version": "",
            "platform": "ANY",
            "javascriptEnabled": True,
            "acceptSslCerts": True,
            "proxy": {
                "httpProxy": chrome_proxy,
                "ftpProxy": None,
                "sslProxy": chrome_proxy,
                "noProxy": None,
                "proxyType": "MANUAL",
                "autodetect": False
                },
            "chrome.switches": ["allow-running-insecure-content",
                                "disable-web-security"]
            }

        null_chrome_options = NullChromeOptions()

        driver = webdriver.Chrome(desired_capabilities=chrome_desired_caps,
                                  chrome_options=null_chrome_options)

    elif selenium_web_driver == "Firefox":
        # see the ./py/selenium/webdriver/firefox/webdriver_prefs.json in the
        # Selenium Python bindings for the frozen and mutable preferences of
        # the Firefox webdriver in Selenium
        profile = webdriver.FirefoxProfile()
        profile.accept_untrusted_certs = True
        profile.assume_untrusted_cert_issuer = True
        profile.set_proxy(browsermob_proxy.selenium_proxy())
        driver = webdriver.Firefox(firefox_profile=profile)

    elif selenium_web_driver == "Ie":
        profile = webdriver.IeProfile()
        profile.set_proxy(browsermob_proxy.selenium_proxy())
        driver = webdriver.Ie(ie_profile=profile)

    return driver


def get_a_random_free_tcp_port():
    """Tries to get a random, unused TCP port.
    Issue is, there could be a race-condition in the Operating System
    between the instant this unused port is found here and the later
    instant when it is used, if some other process happen to used in
    that interval."""
    test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    test_socket.bind(("", 0))
    test_socket.listen(1)
    port_allocated = test_socket.getsockname()[1]
    test_socket.close()
    return port_allocated


def report_har_entry(har_entry, profiling_rept_file):
    """Report the profiling information of a single HAR HTML archive entry,
    ie., only one component inside the whole HTML document, writing the
    report to a file."""

    # This is a syntactic validator of a complex data structure (a HAR HTML
    # archive, so it needs to validate many conditions, etc, so you will
    # receive pylint complains on too-many-branches and
    # too-many-return-statements

    if not isinstance(har_entry, dict):
        logerr("HAR-entry is not a dictionary.")
        return
    if "request" not in har_entry:
        logerr("HAR-entry does not have a ['request'] key.")
        return
    if not isinstance(har_entry["request"], dict):
        logerr("['request'] key in HAR-entry is not a dictionary.")
        return

    # Report the URL requested
    if "url" not in har_entry["request"]:
        logerr("The ['request'] sub-tree in HAR-entry does not have an "
               "'url' key.")
        return
    profiling_rept_file.write("URL: " + har_entry["request"]["url"] + "\n")

    # Report different fields of the server response to this HTTP request
    if "response" not in har_entry:
        logerr("HAR-entry does not have a ['response'] key.")
        return
    if not isinstance(har_entry["response"], dict):
        logerr("['response'] key in HAR-entry is not a dictionary.")
        return
    if "status" in har_entry["response"]:
        profiling_rept_file.write("   Response status: " +
                                  str(har_entry["response"]["status"]) + "\n")
    if "content" in har_entry["response"] and \
       isinstance(har_entry["response"]["content"], dict):
        if "size" in har_entry["response"]["content"]:
            obj_size = str(har_entry["response"]["content"]["size"])
            profiling_rept_file.write("   Response size: " + obj_size + "\n")
        if "mimeType" in har_entry["response"]["content"]:
            obj_mime = har_entry["response"]["content"]["mimeType"]
            profiling_rept_file.write("   Response type: " + obj_mime + "\n")

    # Report the start date when this HTTP request was submitted
    if "startedDateTime" in har_entry:
        profiling_rept_file.write("   startedDateTime: " +
                                  har_entry["startedDateTime"] + "\n")

    # Report the different timings of this HTTP request
    if "timings" not in har_entry:
        logerr("HAR-entry does not have a ['timings'] key.")
        return
    if not isinstance(har_entry["timings"], dict):
        logerr("['timings'] key in HAR-entry is not a dictionary.")
        return
    timings_std_keys = ["receive", "send", "ssl", "connect",
                        "dns", "blocked", "wait"]
    for timing_key in timings_std_keys:
        if timing_key in har_entry["timings"]:
            # Get the timing profiling for this key 'timing_key'
            timing_profiling = str(har_entry["timings"][timing_key])
            profiling_rept_file.write("   timings['" +
                                      timing_key + "']: " +
                                      timing_profiling + "\n")


def report_har_dictionary(har_dict, profiling_rept_file):
    """Report a profiling information of a HAR HTML archive dictionary
    to a file-object."""

    if not isinstance(har_dict, dict):
        logerr("HAR-tree is not a dictionary.")
        return
    if "log" not in har_dict:
        logerr("'log' key not in HAR HTML archive.")
        return
    if "entries" not in har_dict["log"]:
        logerr("'entries' key not in ['log] sub-tree of the HAR "
               "HTML archive.")
        return
    if not isinstance(har_dict["log"]["entries"], list):
        logerr("['log']['entries'] sub-tree in the HAR HTML archive is "
               "not a list.")
        return
    for entry in har_dict["log"]["entries"]:
        report_har_entry(entry, profiling_rept_file)


def save_web_page_stats_to_har(url, webdriver_name, save_to_file):
    """Generate the HAR archive from an URL with the Selenium webdriver
    'webdriver_name', saving the HAR file to 'save_to_file'
    """
    # pylint: disable=line-too-long
    browsermob_executable = "<PUT-HERE-PATH-TO>/bin/browsermob-proxy"
    browsermob_server = Server(browsermob_executable)
    browsermob_server.start()
    random_port = get_a_random_free_tcp_port()
    proxy_conn = browsermob_server.create_proxy({"port": random_port})
    driver = create_selenium_webdriver(webdriver_name, proxy_conn)
    try:
        proxy_conn.new_har(url, options={'captureHeaders': True})
        driver.get(url)

        har_json = json.dumps(proxy_conn.har, ensure_ascii=False,
                              indent=4, separators=(',', ': '))
        # Save '.HAR' file
        with io.open(save_to_file + '.har', mode='wt', buffering=1,
                     encoding='utf8', errors='backslashreplace',
                     newline=None) as output_har_f:
            output_har_f.write(unicode(har_json))

        # Save '.PROF' file with profiling report (timings, sizes, etc)
        with io.open(save_to_file + '.prof', mode='wb', buffering=1,
                     newline=None) as prof_output:
            report_har_dictionary(proxy_conn.har, prof_output)

    finally:
        proxy_conn.close()
        browsermob_server.stop()
        driver.quit()


def logerr(err_msg):
    """Log to standard error."""

    sys.stderr.write(err_msg)


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
    parser.add_argument('urls', metavar='URL', nargs='+',
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

    if not check_selenium_webdriver(selenium_web_driver):
        logerr("Selenium webdriver '" + selenium_web_driver +
               "' not supported yet.")
        sys.exit(1)

    for url in args.urls:
        destination_file = re.sub('[^0-9a-zA-Z]+', '_', url)
        save_web_page_stats_to_har(url, selenium_web_driver,
                                   destination_file)


if __name__ == '__main__':
    main()
