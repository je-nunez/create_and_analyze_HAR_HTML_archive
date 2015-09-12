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

    return selenium_web_driver in ["chrome", "firefox", "phantomjs",
                                   "safari", "ie"]


def create_selenium_webdriver(selenium_web_driver, browsermob_proxy):
    """Create the Selenium web-driver requested, associated to the
    the browsermob_proxy given."""

    driver = None

    if selenium_web_driver == "chrome":
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

    elif selenium_web_driver == "firefox":
        # see the ./py/selenium/webdriver/firefox/webdriver_prefs.json in the
        # Selenium Python bindings for the frozen and mutable preferences of
        # the Firefox webdriver in Selenium
        profile = webdriver.FirefoxProfile()
        profile.accept_untrusted_certs = True
        profile.assume_untrusted_cert_issuer = True
        profile.set_proxy(browsermob_proxy.selenium_proxy())
        driver = webdriver.Firefox(firefox_profile=profile)

    elif selenium_web_driver == "phantomjs":

        # pylint: disable=line-too-long
        phantomjs_exec_path = '<PUT-HERE-PATH-TO>/bin/phantomjs'

        # options to PhantomJS: see http://phantomjs.org/api/command-line.html
        phantomjs_proxy = browsermob_proxy.proxy
        proxy_address = "--proxy={0}".format(phantomjs_proxy)
        phantomjs_args = [proxy_address, '--proxy-type=http',
                          '--ignore-ssl-errors=yes']
        driver = webdriver.PhantomJS(executable_path=phantomjs_exec_path,
                                     service_args=phantomjs_args)
        driver.set_window_size(1366, 768)

    elif selenium_web_driver == "safari":
        # To install the Selenium web-driver for Safari, follow instructions
        # here, otherwise Selenium would time-out trying to connect to Safari:
        #
        #    https://code.google.com/p/selenium/issues/detail?id=7933#c33
        #
        # pylint: disable=line-too-long
        # (see http://central.maven.org/maven2/org/seleniumhq/selenium/selenium-safari-driver/)
        #
        # The Selenium Safari driver needs this environment variable,
        # according to its source code:
        #    ./selenium/webdriver/safari/webdriver.py
        #
        # 52  try:
        # 53      executable_path = os.environ["SELENIUM_SERVER_JAR"]
        # 54  except:
        # 55      raise Exception("No executable path given, please add one to Environment Variable \
        # 56      'SELENIUM_SERVER_JAR'")
        #
        # pylint: disable=line-too-long
        os.environ['SELENIUM_SERVER_JAR'] = '<PUT-HERE-PATH-TO>/bin/selenium-server-standalone-2.47.1.jar'
        safari_proxy = browsermob_proxy.proxy
        #
        # See: https://code.google.com/p/selenium/wiki/DesiredCapabilities
        # and also
        #
        #      selenium/java/server/src/org/openqa/selenium/server/browserlaunchers/SafariCustomProfileLauncher.java
        #
        # where, to set a proxy for Safari, they need to change the System
        # Proxy (see method " private void setupSystemProxy() { ... }"
        #

        safari_desired_caps = {
            "browserName": "safari",
            "version": "",
            "platform": "ANY",
            "javascriptEnabled": True,
            "acceptSslCerts": True,
            "proxy": {
                "httpProxy": safari_proxy,
                "ftpProxy": None,
                "sslProxy": None,
                "noProxy": None,
                "proxyType": "MANUAL",
                "autodetect": False
                },
            "honorSystemProxy": False,
            "safari.options": {
                "mode": "proxy",
                "honorSystemProxy": False
                }
            }
        quiet_flag = True
        driver = webdriver.Safari(desired_capabilities=safari_desired_caps,
                                  quiet=quiet_flag)

    elif selenium_web_driver == "ie":
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


def get_dict_keys(an_obj, expected_path_keys, warn_if_missing):
    """Returns the value of the

          an_obj[K1][K2]...[Kn]

    if and only if the object 'an_obj' is a dictionary and has that sequence
    of keys, where

          Ki

    is the i-th position in the parameter list 'expected_path_keys'.

    If such sequence of keys

          an_obj[K1][K2]...[Kn]

    is not found, then returns None.

    Optionally, warn to standard-error if the such sequence of keys
          an_obj[K1][K2]...[Kn]
    do not exist AND if requested to warn by the parameter 'warn_if_missing'.
    """

    current_node = an_obj
    accumulated_transversal = []
    for expected_key in expected_path_keys:
        if not isinstance(current_node, dict):
            if warn_if_missing:
                logerr("Object found after keys {0} is not a dictionary.\n".
                       format(accumulated_transversal))
            return None
        if expected_key not in current_node:
            if warn_if_missing:
                logerr("Key ['{0}'] not found after keys {1}.\n".
                       format(expected_key, ','.join(accumulated_transversal)))
            return None
        accumulated_transversal.append(expected_key)
        current_node = current_node[expected_key]

    return current_node


def report_har_entry(har_entry, profiling_rept_file):
    """Report the profiling information of a single HAR HTML archive entry,
    ie., only one component inside the whole HTML document, writing the
    report to a file."""

    expected_dictionaries = ["request", "response"]
    for expected_key in expected_dictionaries:
        if not get_dict_keys(har_entry, [expected_key], True):
            return

    # Check if we have a MIME-filter on which MIME-types to report only
    obj_mime = get_dict_keys(har_entry, ["response", "content", "mimeType"],
                             False)

    if Config.mime_type_pattern and not \
       Config.mime_type_pattern.search(obj_mime):
        # the URL MIME-type 'obj_mime' does not match requested MIME pattern
        return     # do not report on this component HAR entry

    # Report the URL requested
    url = get_dict_keys(har_entry, ["request", "url"], True)
    if not url:
        return  # the key har_entry["request"]["url"] was not found
    profiling_rept_file.write("URL: {0}\n".format(url))

    # Report different fields of the server response to this HTTP request
    status = get_dict_keys(har_entry, ["response", "status"], False)
    if status:
        profiling_rept_file.write("   Response status: {0:d}\n".
                                  format(status))

    obj_size = get_dict_keys(har_entry, ["response", "content", "size"],
                             False)
    if obj_size:
        profiling_rept_file.write("   Response size: {0:d}\n".format(obj_size))
    if obj_mime:
        profiling_rept_file.write("   Response type: {0}\n".format(obj_mime))

    # Report the start date when this HTTP request was submitted
    started_time = get_dict_keys(har_entry, ["startedDateTime"], False)
    if started_time:
        profiling_rept_file.write("   startedDateTime: {0}\n".
                                  format(started_time))

    # Report the different timings of this HTTP request
    if not get_dict_keys(har_entry, ["timings"], True):
        return

    timings_std_keys = ["receive", "send", "ssl", "connect",
                        "dns", "blocked", "wait"]
    for timing_key in timings_std_keys:
        profiling_time = get_dict_keys(har_entry, ["timings", timing_key],
                                       False)
        if profiling_time and isinstance(profiling_time, (int, long)) and \
           profiling_time >= Config.min_precision_delays:
            profiling_rept_file.write("   timings['{0}']: {1:d}\n".
                                      format(timing_key, profiling_time))


def report_har_dictionary(har_dict, profiling_rept_file):
    """Report a profiling information of a HAR HTML archive dictionary
    to a file-object."""

    list_entries = get_dict_keys(har_dict, ["log", "entries"], True)
    if not list_entries:
        logerr("['log']['entries'] sub-tree in the HAR HTML archive is "
               "not found.\n")
    elif not isinstance(list_entries, list):
        logerr("['log']['entries'] sub-tree in the HAR HTML archive is "
               "not a list.\n")
    else:
        for entry in list_entries:
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


#
# class Config(object):
#
# A (static) class to hold global config settings, instead of passing these
# global config up through all the levels of the functions call-stack

class Config(object):              # pylint: disable=too-few-public-methods
    """This class holds global config settings."""

    # Minimum precision of delay to report (ie., only delays in the HAR HTML
    # archive greater than this will be reported)
    min_precision_delays = -10000000

    # Report only those URLs whose MIME-types match this regular expression
    # pattern
    mime_type_pattern = None


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
    parser = argparse.ArgumentParser(description='Generate a HAR HTML archive'
                                                 'for an URL.',
                                     epilog=pyscript_docstring,
                                     formatter_class=\
                                                  RawDescriptionHelpFormatter)
    parser.add_argument('-w', '--web_driver', nargs=1, default='Chrome',
                        required=False, metavar='web-driver',
                        help='Specify which Selenium web-driver to use to '
                             'load URL. (default: %(default)s)')
    parser.add_argument('-n', '--non_zero', default=False, required=False,
                        action='store_true',
                        help='Only report real delays (ie., omit those delays'
                             ' that are zero or do not apply (are -1). '
                             '(default: %(default)s)')
    parser.add_argument('-m', '--min_precision', nargs=1, default=-10000,
                        required=False, type=int, metavar='PRECISION',
                        help='Specify the minimum precision of delay (in '
                             'milliseconds) up from this value to report '
                             'delays. (default: report all delays)')
    parser.add_argument('-t', '--type_pattern', nargs=1, default=None,
                        required=False, metavar='MIME-TYPE-PATTERN',
                        help='Report only those URLs whose MIME-types match '
                             'this regular expression. (default: all)')
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

    selenium_web_driver = selenium_web_driver.lower()
    if not check_selenium_webdriver(selenium_web_driver):
        logerr("Selenium webdriver '{0}' not supported yet.\n".
               format(selenium_web_driver))
        sys.exit(1)

    if args.non_zero:
        Config.min_precision_delays = 1

    if args.min_precision:
        if isinstance(args.min_precision, list):
            # this type check is necessary for some argparse.ArgumentParser()
            # installed in Mac OS/X
            Config.min_precision_delays = int(args.min_precision[0])
        else:
            # normal case for argparse.ArgumentParser() in Linux
            Config.min_precision_delays = int(args.min_precision)
        # check if both options '--non_zero' and '--min_precision' are given,
        # since they are implemented very similarly
        if args.non_zero and Config.min_precision_delays < 1:
            Config.min_precision_delays = 1

    if args.type_pattern:
        # MIME types are case insensitive. They are lowercase by convention
        # only. RFC 2045 says: "The type, subtype, and parameter names are
        # not case sensitive."
        Config.mime_type_pattern = re.compile(args.type_pattern[0],
                                              re.IGNORECASE)

    for url in args.urls:
        destination_file = re.sub('[^0-9a-zA-Z]+', '_', url)
        save_web_page_stats_to_har(url, selenium_web_driver,
                                   destination_file)


if __name__ == '__main__':
    main()
