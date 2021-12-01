/*
  The modified version developed by Mobize(K. Suwatchai)

  The MIT License (MIT)
  Copyright (c) 2021 K. Suwatchai (Mobizt)

  Permission is hereby granted, free of charge, to any person returning a copy of
  this software and associated documentation files (the "Software"), to deal in
  the Software without restriction, including without limitation the rights to
  use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
  the Software, and to permit persons to whom the Software is furnished to do so,
  subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
  FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
  COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
  IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
  CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

  //////////////////////////////////////////////////////////////////////////

  This file is part of the Arduino NINA firmware.
  Copyright (c) 2018 Arduino SA. All rights reserved.

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
  
*/

#ifndef WIFISSLCLIENT_H
#define WIFISSLCLIENT_H

#include <mbedtls/net.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>

#include <mbedtls/platform.h>

#include <Arduino.h>
// #include <Client.h>
#include <IPAddress.h>
#include <string>

class WiFiSSLClient /*: public Client*/ {

public:
  WiFiSSLClient();

  uint8_t status();

  virtual int connect(/*IPAddress*/uint32_t ip, uint16_t port);
  virtual int connect(const char* host, uint16_t port);
  /* Secure Connection Upgradable Supports */
  virtual int ns_connect(const char *host, uint16_t port);
  /* Secure Connection Upgradable Supports */
  virtual int ns_connectSSL(const char *host, uint16_t port, bool verifyRootCA = false);
  /* Secure Connection Upgradable Supports */
  virtual size_t _write(uint8_t); //replacing virtual size_t write(uint8_t);
  /* Secure Connection Upgradable Supports */
  virtual size_t _write(const uint8_t *buf, size_t size); //replacing virtual size_t write(const uint8_t *buf, size_t size);
  /* Secure Connection Upgradable Supports */
  virtual int available(); //update virtual int available();
  /* Secure Connection Upgradable Supports */
  virtual int _read(); //replacing virtual int read();
  /* Secure Connection Upgradable Supports */
  virtual int _read(uint8_t *buf, size_t size); //replacing virtual int read(uint8_t *buf, size_t size);
  /* Secure Connection Upgradable Supports */
  virtual int peek(); //update virtual int peak();
  virtual void flush();
  virtual void stop();
  virtual uint8_t connected();
  virtual operator bool();

  // using Print::write;

  virtual /*IPAddress*/uint32_t remoteIP();
  virtual uint16_t remotePort();

private:
  int connect(const char* host, uint16_t port, bool sni);
  /* Secure Connection Upgradable Supports */
  int start_socket(const char *host, uint16_t port, int timeout);
  /* Secure Connection Upgradable Supports */
  int ns_lwip_write(const uint8_t *buf, int bufLen);
  /* Secure Connection Upgradable Supports */
  int ns_lwip_read(uint8_t *buf, int bufLen);
  /* Secure Connection Upgradable Supports */
  int ns_available();
  /* Secure Connection Upgradable Supports */
  int ns_read();
  /* Secure Connection Upgradable Supports */
  int ns_read(uint8_t *buf, size_t size);

private:
  static const char *ROOT_CAs;

  mbedtls_entropy_context _entropyContext;
  mbedtls_ctr_drbg_context _ctrDrbgContext;
  mbedtls_ssl_context _sslContext;
  mbedtls_ssl_config _sslConfig;
  mbedtls_net_context _netContext;
  mbedtls_x509_crt _caCrt;
  bool _connected;
  int _peek;
  /* Secure Connection Upgradable Supports */
  bool _ns = false;
  /* Secure Connection Upgradable Supports */
  bool _insecure = false;
  /* Secure Connection Upgradable Supports */
  std::string _rxBuf;

  SemaphoreHandle_t _mbedMutex;
};

#endif /* WIFISSLCLIENT_H */
