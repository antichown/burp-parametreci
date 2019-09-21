from burp import IScannerCheck
import re
import urllib
from burp import IBurpExtender
from burp import IScanIssue
from java.io import PrintWriter

class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, _callbacks):
        global helpers,callbacks, derr, dout
        callbacks = _callbacks
        helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Parametreci v0.1")
        Tara = ParametreScn()
        dout = PrintWriter(callbacks.getStdout(), True)
        derr = PrintWriter(callbacks.getStderr(), True)
        dout.println("Parametreci | twitter.com/0x94")
        callbacks.registerScannerCheck(Tara)


class ParametreScn(IScannerCheck):
    def __init__(self):
        self.url_regex = "http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\), ]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"
        self.other_url = "://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\), ]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"
        self.file_regex="[a-zA-Z]{1,3}"
        self.ftp_regex="(ftp):"
        self.sql_regex=".sql{1,3}"

    def doPassiveScan(self, baseRequestResponse):
        found=[]
        request  = baseRequestResponse.getRequest()
        url  = helpers.analyzeRequest(baseRequestResponse).getUrl()
        http_msg = [callbacks.applyMarkers(baseRequestResponse, None, None)]
        params = helpers.analyzeRequest(request).getParameters()
        if len(params) > 0:
            for namekey in params:
                name = namekey.getName()
                valuem = namekey.getValue()
                valuem = urllib.unquote(urllib.unquote(valuem))

                if re.search(self.url_regex, valuem):
                    found.append(valuem+"\nParametre Url")
                elif re.search(self.other_url, valuem):
                    found.append(valuem+"\nParametre Url")
                elif re.search(self.file_regex, valuem):
                    found.append(valuem+"\nParametre File Url")
                elif re.search(self.ftp_regex, valuem):
                    found.append(valuem+"\nFtp url")
                elif re.search(self.sql_regex,valuem):
                    found.append(valuem+"\nSQL File Url")

            if found:
                for par in found:
                    return [CustomScanIssue(baseRequestResponse.getHttpService(),
                                            url,
                                            http_msg,
                                            "Parametre Bilgisi!",
                                            par,
                                            "Information")]


class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        pass

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
