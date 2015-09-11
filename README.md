# Create and analyze a HAR archive from an URL

Create and analyze a HAR archive in Python from an URL.

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
respectively.

The `HAR` archive gives other `profiling` information about the URLs
of the components of a web page, like their `MIME-type`s and `size`s,
besides the URLs themselves:

                    "content": {
                        "mimeType": "application/x-javascript",
                        "comment": "",
                        "size": 7163
                    }

This program will create two output files, a `.har` file with the `HAR`
HTML archive, and a `.prof` with a report of some basic profiling taken
from the `HAR` file, like (for `http://www.cnn.com`)

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

For more information about `HAR` archives:

 https://en.wikipedia.org/wiki/.har
   
 https://dvcs.w3.org/hg/webperf/raw-file/tip/specs/HAR/Overview.html

# WIP

This project is a *work in progress*. The implementation is *incomplete* and
subject to change. The documentation can be inaccurate.

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

For the Selenium `chromedriver` web-driver, you need to install:

  In Mac OS:
       brew install chromedriver

Or download the `chromedriver` web-driver directly from:

    http://chromedriver.storage.googleapis.com/index.html

(according to its latest release in:

    http://chromedriver.storage.googleapis.com/LATEST_RELEASE
)

