# Create and analyze a HAR HTML archive from an URL using Python and Selenium

Create and analyze a HAR HTML archive from an URL using Python and Selenium.

A `HAR` archive has very important `SLA` metrics about a web page
(including all its elements), like the different `timings` and
`profiling` in the HTTP operations to request and retrieve each
component in the web page (the values below are in milliseconds):

                    "dns": 66,
                    "connect": 34,
                    "send": 0,
                    "ssl": -1,
                    "wait": 41,
                    "blocked": 0
                    "receive": 180,

to stand for the `dns` resolution delay, the tcp `connect` delay,
`ssl`, `send`, `wait`, `blocked`, and the tcp `receive` delays,
respectively. (The value `-1` represents `Use -1 if the timing does
not apply to the current request`: see the `W3` specification on
the `HAR` format below.)

The `HAR` archive gives other `profiling` information about the URLs
of the components of a web page, like their `MIME-type`s and `size`s,
besides the URLs themselves:

                    "content": {
                        "mimeType": "application/x-javascript",
                        "comment": "",
                        "size": 7163
                    }

For more information about `HAR` archives:

 https://en.wikipedia.org/wiki/.har

 https://dvcs.w3.org/hg/webperf/raw-file/tip/specs/HAR/Overview.html

For the importance on timing, see, for example:

 http://www.aosabook.org/en/posa/high-performance-networking-in-chrome.html

# WIP

This project is a *work in progress*. The implementation is *incomplete* and
subject to change. The documentation can be inaccurate.

# Usage example:

This program will create two output files, a `.har` file with the `HAR`
HTML archive, and a `.prof` with a report of some basic profiling taken
from the `HAR` file, like (for `http://www.cnn.com` -values are in
milliseconds):

     URL: http://data.cnn.com/jsonp/breaking_news/domestic.json?callback=<...>
        Response status: 200
        Response size: 169
        Response type: application/javascript
        startedDateTime: 2015-09-10T21:14:50.836-04:00
        timings['receive']: 2541
        timings['send']: 0
        timings['ssl']: -1
        timings['connect']: 3
        timings['dns']: 4
        timings['blocked']: 0
        timings['wait']: 69

This invocation:

      ./generate_har_file.py  -w chrome  -m 10  -t image/jpeg  https://www.flickr.com

will generate a HAR HTML archive for the URL `https://www.flickr.com`,
and a .PROF summary profile with only those URLs which any timing
component of it took at least `-m 10` milliseconds, and whose MIME
type matches with `-t image/jpeg`, using for all this the `Selenium`
`Google Chrome` webdriver. E.g. (timings are in milliseconds and
sizes in bytes):

     URL: https://s.yimg.com/uy/build/images/sohp/inspiration/solar-storm3.jpg
        Response status: 200
        Response size: 434348
        Response type: image/jpeg
        startedDateTime: 2015-09-11T20:49:05.990-04:00
        timings['receive']: 643
        timings['wait']: 33

(The saved `.har` HAR HTML archive has `all` the information
retrieved from the URL, so it is not affected by the filtering, in
this example `-m 10 -t image/jpeg`, which only affects the profiling
report in the generated `.prof` file.)

# Required libraries and auxiliary programs

The Python module for the `Selenium Web Browser` automation, like,
e.g., by:

    conda install --channel https://conda.anaconda.org/chen selenium

The `BrowserMob Proxy` is also necessary, since it caches all the
HAR information about the webpage:

    http://bmp.lightbody.net/

and the Python module for the `BrowserMob Proxy`:

     pip install browsermob-proxy

    ( https://browsermob-proxy-py.readthedocs.org/en/latest/ )

The program allows to use several types of Selenium `webdrivers`: to
use one webdriver, you don't need the others installed. The custom
paths for the webdrivers in your system should be put in the config
file `.generate_har_file.conf` since the program does a basic
verification that they are valid. This config file can be located
either in the current directory (checked first) or in the base
`$HOME` directory.

If you want to use the `PhantomJS` webdriver (`--web_driver phantomjs`),
you need to:

     Install NodeJS

     Install PhantomJS, like by the NodeJS package manager

           npm -g install phantomjs

For the `Mozilla Firefox` webdriver (option `--web_driver firefox`),
you need to have `Firefox` installed.

To use the `Google Chrome` webdriver (option `--web_driver chrome`),
you need to have it installed, plus the Selenium `chromedriver`
webdriver:

  In Mac OS:

       brew install chromedriver

or download the `chromedriver` webdriver directly from:

    http://chromedriver.storage.googleapis.com/index.html

(according to its latest release in:

    http://chromedriver.storage.googleapis.com/LATEST_RELEASE
)

To use the `Apple Safari` webdriver (option `--web_driver safari`),
you need to have it installed and:

     1. Install the Java JAR archive for the Selenium Standalone Server:

             selenium-server-standalone-<version>.jar

        at http://www.seleniumhq.org/download/

     2. Install the Selenium webdriver for Safari, following these
        instructions (otherwise Selenium would start Safari but
        time-out trying to connect to it):

          https://code.google.com/p/selenium/issues/detail?id=7933#c33

        which refers to the Selenium Safari webdriver here:

          http://central.maven.org/maven2/org/seleniumhq/selenium/selenium-safari-driver/

# Other schemas to obtain performance profiling data

The `World Wide Web Consortium (W3C)` has developed other schemas to obtain performance
profiling data of web browsing, in which the browsers may offer this information as an
`API` interface available from bein called inside the webpage (and not as an archive format
or report, as the `HAR` HTML archive is):

       http://www.w3.org/TR/navigation-timing/

       http://www.w3.org/TR/performance-timeline/

       http://www.w3.org/TR/resource-timing/

       http://www.w3.org/TR/user-timing/

# Known issues

The Selenium webdriver for Safari seems to have issues setting the proxy
(the BrowserMob Proxy), so, while the script is able to load the URL in Safari,
it is not able to retrieve the `HAR` HTML archive from BrowserMob Proxy. According
to the `Java` source code to wrap Safari:

      selenium/java/server/src/org/openqa/selenium/server/browserlaunchers/SafariCustomProfileLauncher.java

where, to set a proxy for Safari (like BrowserMob Proxy), it needs to change the
System Proxy (see below the method `private void setupSystemProxy() { ... }` in
this file):

     @Override
     protected void launch(String url) {
       if (!browserConfigurationOptions.is("honorSystemProxy")) {
         setupSystemProxy();
       }

       if (browserConfigurationOptions.is(CapabilityType.ForSeleniumServer.ENSURING_CLEAN_SESSION)) {
         ensureCleanSession();
       }

       launchSafari(url);
     }
     ...
     private void setupSystemProxy() {
       if (WindowsUtils.thisIsWindows()) {
         wpm.backupRegistrySettings();
         changeRegistrySettings();
       } else {
         mpm.backupNetworkSettings();
         mpm.changeNetworkSettings();
       }
     }

