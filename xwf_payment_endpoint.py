# -*- coding: UTF-8 -*-

"""
PaymentEndPointHandler
This endpoint implementation illustrate the integration with XWF Payments API.
It is intended as an example only and doesn't cover any security topic
(Ex. replaying requests, PartnerAccessToken authorization verification, error handling...).
"""

__version__ = "1.0.0"
__author__ = "Youssef"
__all__ = ["PaymentEndPointHandler"]

from urllib.parse import urlparse, parse_qs
from datetime import datetime

import http.server as SimpleHTTPServer
import socketserver as SocketServer
import requests
import hmac
import hashlib
import sys
import enum
import cgi
import json

XWF_END_POINT = "https://my.endpoint.com"
XWF_GRAPH_URL = "https://my.graph-url.com"

XWF_PARTNER_ID = "FillYourPartnerNumber"
XWF_SECRET_KEY = "FillYourPartnerSecret"
XWF_ACCESS_TOKEN = "FillYourPartnerAccessToken"

XWF_RESPONSE_ERROR = '{ "status": "%s", "error": "%s" }'
XWF_RESPONSE_SUCCESS = '{ "status": "%s", "redirection_url": "%s" }'

PAY_URL_PARAMS = "payment_id=%s&amount=%s&currency=%s&timestamp=%s&customer=%s&callback_url=%s"

# Hold all payment requests
payment_requests = []

XWF_PAYMENT_FORM = """
<html>
    <head>
      <meta charset='UTF-8'>
    </head>
    <body>
      <div style='text-align: center;'>
        <form action="%s" method='post'>
          <div style="display: inline-block; text-align: left;">
            <h2><strong>Payment Summary</strong></h2>
            <label for='payment_id'><b>Trans ID</b></label>
              <input style="border:none" type='text'
                name="payment_id" id="payment_id" value="%s" readonly>
            <br/>
            <label for='amount'><b>Amount&nbsp;</b></label>
              <input style="border:none" type='text' name="amount"
                id="amount" value="%s %s" readonly><br>

            <h2><strong>Payment Details</strong></h2>
            <label for='name'>Full Name&nbsp;&nbsp;</label>
              <input type='text' name="fullname" id="fullname"><br><br>
            <label for='card'>Card Number</label>
              <input type='text' name="cardnbr" id="cardnbr"><br><br>
            <label for='ccv'> CCV </label>
              <input type='text' name="CCV" id="CCV">
            <label for='expire'> Expiration </label>
              <input type='text' name="expire" id="expire">
            <br><br>
            <input onclick="window.location.href = 'https://%s';" type='submit'>
            <input type='reset'>
          </div>
        </form>
      </div>
    </body>
  <html>"""


class PaymentStatus(enum.Enum):
    Init = 0
    Success = 1
    Canceled = 2
    Error = 3
    Declined = 4
    Abandoned = 5
    Failure = 6


def calculate_hmac_token(timestamp):
    """ Calculate HMAC based on partner ID, timestamp and a shared secret
        hmac = sha256 ( timestamp + partner_id, secret)
    """
    text_bin = (str(timestamp) + XWF_PARTNER_ID).encode()
    secret_bin = (XWF_SECRET_KEY).encode()
    digest = hmac.new(secret_bin,
                msg=text_bin, digestmod=hashlib.sha256).hexdigest()
    print("digest = ", digest)
    return digest


class PaymentRequest():
    """ Holds the details of a payment request received from XWF.
    """
    def __init__(self, form):
        self._hmac = form.get("hmac")
        self._amount = form.get("amount")
        self._currency = form.get("currency")
        self._callback = form.get("callback_url")
        self._customer = form.get("phone_number")
        self._timestamp = str(form.get("timestamp")).strip()
        self._payment_id = str(form.get("payment_id")).strip()
        self._payment_status = PaymentStatus.Init

    def toUrlParams(self):
        return PAY_URL_PARAMS % (self._payment_id,
                self._amount, self._currency,
                self._timestamp, self._customer, self._callback)

    def isNotValidRequest(self):
        """ Check if any required attribute is missing in the payment
        request.
        """
        return (self._payment_id is None or self._amount is None
                or self._currency is None or self._hmac is None
                or self._timestamp is None or self._customer)

    def isValidHMAC(self):
        """ Check if HMAC is valid.
        """
        hmac_verify = calculate_hmac_token(self._timestamp)
        return hmac_verify == self._hmac


class PaymentEndPointHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
    """ Implement an HTTP handler providing both integration with Payments API and
    payment processing and redirections.
    """
    def do_GET(self):
        """ Serve a GET request to the payment for to collect information.
        The form is then sending the details using a POST request to /process_payment
        """
        content = ""
        if self.path.startswith("/pay"):
            queries = parse_qs(urlparse(self.path).query)
            if (len(queries["payment_id"]) != 1
                    or len(queries["timestamp"]) != 1
                    or len(queries["currency"]) != 1
                    or len(queries["callback_url"]) != 1
                    or len(queries["amount"]) != 1):
                print("Wrong URL Parameters. Failed redirection")
                print("Queries = ", queries)
                self._send_response(401, "", "")
                return

            content = XWF_PAYMENT_FORM % (
                XWF_END_POINT + "/process_payment",
                queries["payment_id"][0],
                queries["amount"][0],
                queries["currency"][0],
                queries["callback_url"][0])
            self._send_response(200, content, "html/text")

    def do_POST(self):
        """ Serve a POST request from both XWF and the payment form.
        """
        if self.path.endswith("/make_payment"):
            """ Initial payment request triggered by XWF after an end user click on buy a pack. """
            self._handle_payment_request()
        elif self.path.endswith("/payment_status"):
            """ Payment status request triggered by xwf to verify payment status """
            self._handle_payment_status()
        elif self.path.endswith("/process_payment"):
            """ Process payment information collected by the form at /pay """
            self._handle_process_payment()

    def _send_response_to_xwf_endpoint(self, payment_id, status):
        """ Sends a POST request to XWF to update with a payment request status """
        now = datetime.now()
        timestamp = int(datetime.timestamp(now))
        hmac_value = calculate_hmac_token(timestamp)
        content = {
            'access_token': XWF_ACCESS_TOKEN,
            'payment_id': payment_id,
            'hmac': hmac_value,
            'timestamp': timestamp,
            'status': status.lower()}
        response = requests.post(XWF_GRAPH_URL, data=content)
        print("payment_id = ", payment_id)
        print("response = ", response.content)
        return

    def _send_response(self, code, content="", content_type=""):
        self.send_response(code)
        self.end_headers()
        self.send_header("Content-type", content_type)
        self.wfile.write(content.encode())

    def _send_redirect(self, callback):
        self.send_response(302)
        self.send_header('Location', callback)
        self.end_headers()

    def _handle_payment_request(self):
        ctype, pdict = cgi.parse_header(self.headers['content-type'])
        if ctype != 'application/json':
            self.send_response(400)
            self.end_headers()
            return

        length = int(self.headers['content-length'])
        data = json.loads(self.rfile.read(length))
        req = PaymentRequest(data)
        if req.isNotValidRequest():
            print("Payment Request is not valid. queries = ", req)
            req._payment_status = PaymentStatus.Error
            payment_requests.append(req)
            content = XWF_RESPONSE_ERROR % (PaymentStatus.Error.name, "")
            self._send_response(200, content, "application/json")
            return

        if req.isValidHMAC():
            print("Hmac verification succeeded. payment_id = ", req._payment_id)
            redirect_url = XWF_END_POINT + "/pay?" + req.toUrlParams()
            content = XWF_RESPONSE_SUCCESS % (
                PaymentStatus.Success.name.lower(), redirect_url)
            self._send_response(200, content, "application/json")
            payment_requests.append(req)
        else:
            print("Hmac verification failed. payment_id = ", req._payment_id)
            req._payment_status = PaymentStatus.Error
            payment_requests.append(req)
            content = XWF_RESPONSE_ERROR % (PaymentStatus.Failure.name.lower(), "")
            self._send_response(200, content, "application/json")

    def _handle_payment_status(self):
        form = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            environ={'REQUEST_METHOD': 'POST'}
        )
        req = PaymentRequest(form)
        if req._partner_id != XWF_PARTNER_ID:
            print("Wrong Partner Id = ", req._partner_id)
            return

        if req.isValidHMAC():
            for item in payment_requests:
                if (item._payment_id == req._payment_id
                        and item._payment_status != PaymentStatus.Init):
                    content = '{ "status": "%s" }' % (item._payment_status.value.lower())
                    self._send_response(200, content, "application/json")
                    return

        print("Unknown payment request. payment_id = ", req._payment_id)
        content = XWF_RESPONSE_ERROR % (PaymentStatus.Failure.name.lower(), "")
        self._send_response(200, content, "application/json")

    def _handle_process_payment(self):
        form = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            environ={'REQUEST_METHOD': 'POST'}
        )
        payment_id = form.getvalue("payment_id")
        for item in payment_requests:
            if (item._payment_id == payment_id):
                if (item._payment_status == PaymentStatus.Init):
                    print("Payment success for payment_id = ", payment_id)
                    item._payment_status = PaymentStatus.Success

                    # Update XWF with the transaction status
                    print("Update XWF Graph")
                    self._send_response_to_xwf_endpoint(
                        payment_id, PaymentStatus.Success.name.lower())
                    # Redirect user to the main page
                    self._send_redirect(item._callback)
                    return
                else:
                    item._payment_status = PaymentStatus.Error

        print("Error while processing payment_id = ", payment_id)
        content = "Unauthorized Payment failed"
        self._send_response(401, content, "htmn/text")


def main():
    if sys.argv[1:]:
        port = int(sys.argv[1])
    else:
        port = 8000

    Handler = PaymentEndPointHandler
    httpd = SocketServer.TCPServer(("", port), Handler)
    httpd.allow_reuse_address = True
    httpd.serve_forever()


if __name__ == '__main__':
    main()
