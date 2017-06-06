<?php
/**
 * Contains NTLMSoapClient.
 */

/**
 * Soap Client using Microsoft's NTLM Authentication.
 *
 * Copyright (c) 2008 Invest-In-France Agency http://www.invest-in-france.org
 *
 * Author : Thomas Rabaix
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * @link http://rabaix.net/en/articles/2008/03/13/using-soap-php-with-ntlm-authentication
 * @author Thomas Rabaix
 *
 * @package php-ews\Auth
 */
class NTLMSoapClient extends SoapClient {
    /**
     * cURL resource used to make the SOAP request
     *
     * @var resource
     */
    protected $ch;

    /**
     * Whether or not to validate ssl certificates
     *
     * @var boolean
     */
    protected $validate = true;

    protected $verbose = false;
    protected $debug = false;

    /**
     * String to hold the exchange cookie value
     *
     * @var string $cookie
     */
    protected $cookie = null;
    protected $cookie_expires = null;

    private $curlhttp_auth = CURLAUTH_NTLM;
    protected $last_http_code = null;

    /**
     * Performs a SOAP request
     *
     * @link http://php.net/manual/en/function.soap-soapclient-dorequest.php
     *
     * @param string $request the xml soap request
     * @param string $location the url to request
     * @param string $action the soap action.
     * @param integer $version the soap version
     * @param integer $one_way
     * @return string the xml soap response.
     */
    public function __doRequest($request, $location, $action, $version, $one_way = 0)
    {
        $headers = array(
            'Method: POST',
            'Connection: Keep-Alive',
            'User-Agent: PHP-SOAP-CURL',
            'Content-Type: text/xml; charset=utf-8',
            'SOAPAction: "' . $action . '"',
        );

        if (!empty($this->cookie)) {
            $headers[] = sprintf("Cookie: exchangecookie=%s", $this->cookie);
        }

        if ($this->debug) {
            echo "Sending to $location as $this->curlhttp_auth\n";
            echo "Headers to send:\n";
            var_dump($headers);
        }

        $loop_count = 0;
        if (preg_match('/FindFolder$/', $action))
            $loop_count = 2;
        do {

            $this->__last_request_headers = $headers;
            $this->ch = curl_init($location);

            curl_setopt($this->ch, CURLOPT_SSL_VERIFYPEER, $this->validate);
            curl_setopt($this->ch, CURLOPT_SSL_VERIFYHOST, $this->validate ? 2 : 0);
            curl_setopt($this->ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($this->ch, CURLOPT_HTTPHEADER, $headers);
            curl_setopt($this->ch, CURLOPT_POST, true);
            curl_setopt($this->ch, CURLOPT_POSTFIELDS, $request);
            curl_setopt($this->ch, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
            curl_setopt($this->ch, CURLOPT_HTTPAUTH, $this->curlhttp_auth);
            curl_setopt($this->ch, CURLOPT_USERPWD, $this->user . ':' . $this->password);
            curl_setopt($this->ch, CURLOPT_HEADER, true);

            // If our queries cross the threshold for the CAS throttling, well get no response back from Exchange
            // So we will wait for 60 seconds (most throttling is done on a minute basis) and then try again.
            // We allow this to be done twice.
            // NOTE if we are doing a FindFolder action, we only allow the 1 try.  (As we use FindFolder to determine a correct connection or not)

            $loop_count++;
            $response = curl_exec($this->ch);
            if ($this->debug) {
                echo "Received HTTP Code: " . curl_getinfo($this->ch, CURLINFO_HTTP_CODE) . PHP_EOL;
                var_dump($response);
                if ($this->validate) {
                    echo "SSL Verify Host: ";
                    echo curl_getinfo($this->ch, CURLINFO_SSL_VERIFYRESULT) . PHP_EOL;
                }
            }
            if ($response !== false) {
                if ($this->curlhttp_auth == CURLAUTH_NTLM &&
                    (
                        curl_getinfo($this->ch, CURLINFO_HTTP_CODE) == '401'
                        // This next line is to specifically trap Citrix Netscaler errors - Netscaler doesn't correctly passthrough NTLM/Kerberos Authentication, so we trap and revert to BASIC authentication
                        || (curl_getinfo($this->ch, CURLINFO_HTTP_CODE) == '500' && preg_match("#Http/1.1 Internal Server Error 43550 #", $response))
                    )
                ) {
                    if ($this->debug) {
                        echo "Changing to BASIC authentication and retrying\n";
                    }
                    $response = false;
                    $this->curlhttp_auth = CURLAUTH_BASIC;
                    $loop_count = 2;
                }
            } else {
                if ($this->debug) {
                    echo "Got no response - sleeping for 60 seconds to give the remote server a rest.\n";
                }
                sleep(60);
            }
        } while ($response === false && $loop_count < 3);

        // If the response if false than there was an error and we throw
        // an exception.
        $this->last_http_code = curl_getinfo($this->ch, CURLINFO_HTTP_CODE);
        if ($response === false) {
            $message[] = "Failed to send command to Exchange Server.";
            $message[] = print_r(curl_getinfo($this->ch), true);
            $message[] = curl_error($this->ch);
            $message[] = print_r($headers, true);
            $message[] = print_r($request, true);
            $message[] = curl_getinfo($this->ch, CURLINFO_HTTP_CODE);
            throw(new EWS_Exception(implode("\r\n", $message), curl_errno($this->ch)));
        } else {
            switch (curl_getinfo($this->ch, CURLINFO_HTTP_CODE)) {
                case 0:
                    throw(new EWS_Exception("Failed to send command to Exchange Server", ExchangeWebServices::EXCHANGE_COMMS_SEND_FAIL));
                    break;
                case 401:
                    throw(new EWS_Exception("Username/Password Problem", ExchangeWebServices::EXCHANGE_COMMS_CREDENTIALS_FAIL));
                    break;
                case 404:
                    throw(new EWS_Exception("Domain Problem?", ExchangeWebServices::EXCHANGE_COMMS_DOMAIN_FAIL));
                    break;
                case 500:
                    // In the case of a 500 error, we trap and throw the error
                    throw(new EWS_Exception(str_replace("\r\n", PHP_EOL, $response), ExchangeWebServices::EXCHANGE_COMMS_GENERAL_FAIL));

            }
        }

        $curl_header_size = curl_getinfo($this->ch, CURLINFO_HEADER_SIZE);
        $response_headers = substr($response, 0, $curl_header_size);

        // Look for the exchange cookie and use it if found.
        if (preg_match('/\r\nSet-Cookie:(.+)\r\n/', $response_headers, $matches)) {
            foreach (explode(";", $matches[1]) AS $v) {
                $v = trim($v); // trim - might break some things, but shouldn't!
                if (false !== ($ti = strpos($v, "="))) {
                    $key = substr($v, 0, $ti++);
                    $value = substr($v, $ti);
                    switch ($key) {
                        case "exchangecookie":
                            $this->cookie = $value;
                            break;
                        case "expires";
                            $this->cookie_expires = strftime('%Y-%m-%d %H:%M', strtotime($value));
                            break;
                    }
                }
            }
        }

        $response = trim(substr($response, $curl_header_size));
        return preg_replace(array("/>&#x[0-9];/", "/&#x[0-9];/"), array(">", " "), $response);
    }

    /**
     * Returns last SOAP request headers
     *
     * @link http://php.net/manual/en/function.soap-soapclient-getlastrequestheaders.php
     *
     * @return string the last soap request headers
     */
    public function __getLastRequestHeaders()
    {
        return implode('n', $this->__last_request_headers) . "\n";
    }

    public function __getLastHTTPCode()
    {
        return $this->last_http_code;

    }

    /**
     * Sets whether or not to validate ssl certificates
     *
     * @param boolean $validate
     */
    public function validateCertificate($validate = true)
    {
        $this->validate = $validate;

        return true;
    }

    public function setExchangeCookie($cookie_value, $cookie_expires)
    {

        if (!empty($cookie_value) && !empty($cookie_expires)) {
            $this->cookie = (strtotime($cookie_expires) > strtotime("now")) ? $cookie_value : null;
            $this->cookie_expires = (empty($this->cookie)) ? null : $cookie_expires;
        }

        return true;

    }

    public function getExchangeCookie()
    {
        return $this->cookie;
    }


    public function getExchangeCookieExpires()
    {
        return $this->cookie_expires;
    }

    public function setCurlAuth($curlauth)
    {
        $this->curlhttp_auth = $curlauth;
    }

    public function getCurlAuth()
    {
        return $this->curlhttp_auth;
    }

    public function setCurlSSLValidate($validate = true)
    {
        $this->validate = $validate;
    }

    public function setSOAPVerbose($verbose = true)
    {
        $this->verbose = $verbose ? true : false;
    }

    public function setSOAPDebug($debug = true)
    {
        $this->debug = $debug ? true : false;
    }
}
