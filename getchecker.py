from burp import IBurpExtender, IHttpListener, ITab
from java.io import PrintWriter
from java.util import ArrayList
from java.awt import Component
from java.util import Arrays
from java.lang import Runnable
from java.net import URL
from java.net import HttpURLConnection
from java.io import BufferedReader
from java.io import InputStreamReader
from java.io import IOException

class BurpExtender(IBurpExtender, ITab, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)
        callbacks.setExtensionName("GET Checker")
        callbacks.registerHttpListener(self)
        return

    def createIssue(self, url):
        issue = "Possible HTTP Verb Tampering Detected"
        detail = "A request to the following URL resulted in a 2XX response: " + url
        self.callbacks.addScanIssue(
            self.callbacks.applyMarkers(
                self.helpers.analyzeRequest(url),
                None,
                [self.helpers.stringToBytes(url)],
                [issue],
                [detail],
                None,
                None
            )
        )

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            request = messageInfo.getRequest()
            analyzedRequest = self.helpers.analyzeRequest(request)

            method = analyzedRequest.getMethod()
            if method == "POST":
                url = self.helpers.analyzeRequest(messageInfo).getUrl().toString()
                self.stdout.println("POST Request detected: " + url)

                try:
                    req = URL(url)
                    conn = req.openConnection()
                    conn.setRequestMethod("GET")
                    conn.setDoOutput(True)
                    responseCode = conn.getResponseCode()
                    self.stdout.println("GET - HTTP Verb Tampering Detection: " + str(responseCode))
                    if responseCode >= 200 and responseCode < 300:
                        self.createIssue(url)
                except IOException as e:
                    self.stderr.println("Error making GET request: " + str(e))
        return

    def getTabCaption(self):
        return "Detector HTTP Verb Method"

    def getUiComponent(self):
        return None

if __name__ in ("__main__",):
    pass
