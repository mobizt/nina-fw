/*
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

#include <lwip/netdb.h>
#include <lwip/sockets.h>
#include "esp_partition.h"
#include <lwip/err.h>
#include <lwip/sys.h>
#include <lwip/netdb.h>
#include <algorithm>
#include <string>
#include <WiFi.h>

#include "WiFiSSLClient.h"

class __Guard
{
public:
  __Guard(SemaphoreHandle_t handle)
  {
    _handle = handle;

    xSemaphoreTakeRecursive(_handle, portMAX_DELAY);
  }

  ~__Guard() { xSemaphoreGiveRecursive(_handle); }

private:
  SemaphoreHandle_t _handle;
};

#define synchronized __Guard __guard(_mbedMutex);

WiFiSSLClient::WiFiSSLClient() : _connected(false), _peek(-1)
{
  _netContext.fd = -1;

  _mbedMutex = xSemaphoreCreateRecursiveMutex();
}

int WiFiSSLClient::connect(const char *host, uint16_t port, bool sni)
{
  synchronized
  {
    _netContext.fd = -1;
    _connected = false;
    _ns = false;

    mbedtls_ssl_init(&_sslContext);
    mbedtls_ctr_drbg_init(&_ctrDrbgContext);
    mbedtls_ssl_config_init(&_sslConfig);
    mbedtls_entropy_init(&_entropyContext);
    mbedtls_x509_crt_init(&_caCrt);
    mbedtls_net_init(&_netContext);

    if (mbedtls_ctr_drbg_seed(&_ctrDrbgContext, mbedtls_entropy_func,
                              &_entropyContext, NULL, 0) != 0)
    {
      stop();
      return 0;
    }

    if (mbedtls_ssl_config_defaults(&_sslConfig, MBEDTLS_SSL_IS_CLIENT,
                                    MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT) != 0)
    {
      stop();
      return 0;
    }

    mbedtls_ssl_conf_authmode(&_sslConfig, MBEDTLS_SSL_VERIFY_REQUIRED);

    spi_flash_mmap_handle_t handle;
    const unsigned char *certs_data = {};

    const esp_partition_t *part = esp_partition_find_first(
        ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY, "certs");
    if (part == NULL)
    {
      return 0;
    }

    int ret = esp_partition_mmap(part, 0, part->size, SPI_FLASH_MMAP_DATA,
                                 (const void **)&certs_data, &handle);
    if (ret != ESP_OK)
    {
      return 0;
    }

    ret = mbedtls_x509_crt_parse(&_caCrt, certs_data,
                                 strlen((char *)certs_data) + 1);
    if (ret < 0)
    {
      stop();
      return 0;
    }

    mbedtls_ssl_conf_ca_chain(&_sslConfig, &_caCrt, NULL);

    mbedtls_ssl_conf_rng(&_sslConfig, mbedtls_ctr_drbg_random,
                         &_ctrDrbgContext);

    if (mbedtls_ssl_setup(&_sslContext, &_sslConfig) != 0)
    {
      stop();
      return 0;
    }

    if (sni && mbedtls_ssl_set_hostname(&_sslContext, host) != 0)
    {
      stop();
      return 0;
    }

    char portStr[6];
    itoa(port, portStr, 10);

    if (mbedtls_net_connect(&_netContext, host, portStr,
                            MBEDTLS_NET_PROTO_TCP) != 0)
    {
      stop();
      return 0;
    }

    mbedtls_ssl_set_bio(&_sslContext, &_netContext, mbedtls_net_send,
                        mbedtls_net_recv, NULL);

    int result;

    do
    {
      result = mbedtls_ssl_handshake(&_sslContext);
    } while (result == MBEDTLS_ERR_SSL_WANT_READ ||
             result == MBEDTLS_ERR_SSL_WANT_WRITE);

    if (result != 0)
    {
      stop();
      return 0;
    }

    mbedtls_net_set_nonblock(&_netContext);
    _connected = true;

    return 1;
  }
}

int WiFiSSLClient::connect(const char *host, uint16_t port)
{
  return connect(host, port, true);
}

/* Secure Connection Upgradable Supports */
int WiFiSSLClient::start_socket(const char *host, uint16_t port, int timeout)
{

  mbedtls_net_init(&_netContext);

  _netContext.fd = lwip_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  if (_netContext.fd < 0)
  {
    return 0;
  }

  int enable = 1;

  uint32_t srv((uint32_t)0);
  if (!WiFi.hostByName(host, srv))
  {
    return 0;
  }

  struct sockaddr_in serv_addr;
  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = srv;
  serv_addr.sin_port = htons(port);

  if (lwip_connect(_netContext.fd, (struct sockaddr *)&serv_addr,
                   sizeof(serv_addr)) == 0)
  {
    if (timeout <= 0)
    {
      timeout = 30000; // Milli seconds.
    }
    timeval so_timeout = {.tv_sec = timeout / 1000,
                          .tv_usec = (timeout % 1000) * 1000};

#define ROE(x, msg) \
  {                 \
    if (((x) < 0))  \
    {               \
                    \
      return 0;     \
    }               \
  }
    ROE(lwip_setsockopt(_netContext.fd, SOL_SOCKET, SO_RCVTIMEO, &so_timeout,
                        sizeof(so_timeout)),
        "SO_RCVTIMEO");
    ROE(lwip_setsockopt(_netContext.fd, SOL_SOCKET, SO_SNDTIMEO, &so_timeout,
                        sizeof(so_timeout)),
        "SO_SNDTIMEO");

    ROE(lwip_setsockopt(_netContext.fd, IPPROTO_TCP, TCP_NODELAY, &enable,
                        sizeof(enable)),
        "TCP_NODELAY");
    ROE(lwip_setsockopt(_netContext.fd, SOL_SOCKET, SO_KEEPALIVE, &enable,
                        sizeof(enable)),
        "SO_KEEPALIVE");
  }
  else
  {
    return 0;
  }

  fcntl(_netContext.fd, F_SETFL,
        fcntl(_netContext.fd, F_GETFL, 0) | O_NONBLOCK);

  return 1;
}

/* Secure Connection Upgradable Supports */
int WiFiSSLClient::ns_connect(const char *host, uint16_t port)
{

  synchronized
  {
    _ns = true;
    _connected = false;
    if (start_socket(host, port, 30000) == 0)
      return 0;
    _connected = true;
    return 1;
  }
}

/* Secure Connection Upgradable Supports */
int WiFiSSLClient::ns_connectSSL(const char *host, uint16_t port, bool verifyRootCA)
{
  synchronized
  {
    if (_netContext.fd < 0)
      return 0;

    mbedtls_ssl_init(&_sslContext);
    mbedtls_ctr_drbg_init(&_ctrDrbgContext);
    mbedtls_ssl_config_init(&_sslConfig);
    mbedtls_entropy_init(&_entropyContext);
    mbedtls_x509_crt_init(&_caCrt);

    if (mbedtls_ctr_drbg_seed(&_ctrDrbgContext, mbedtls_entropy_func, &_entropyContext, NULL, 0) != 0)
    {
      stop();
      return 0;
    }

    if (mbedtls_ssl_config_defaults(&_sslConfig, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) != 0)
    {
      stop();
      return 0;
    }

    if (verifyRootCA)
    {
      mbedtls_ssl_conf_authmode(&_sslConfig, MBEDTLS_SSL_VERIFY_REQUIRED);
	
      spi_flash_mmap_handle_t handle;
      const unsigned char *certs_data = {};
      
      const esp_partition_t *part = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY, "certs");
      if (part == NULL)
      {
        return 0;
      }
      
      int ret = esp_partition_mmap(part, 0, part->size, SPI_FLASH_MMAP_DATA, (const void **)&certs_data, &handle);
      if (ret != ESP_OK)
      {
        return 0;
      }
      
      ret = mbedtls_x509_crt_parse(&_caCrt, certs_data, strlen((char *)certs_data) + 1);
      if (ret < 0)
      {
        stop();
        return 0;
      }
      
      mbedtls_ssl_conf_ca_chain(&_sslConfig, &_caCrt, NULL);

    }else {
	  mbedtls_ssl_conf_authmode(&_sslConfig, MBEDTLS_SSL_VERIFY_NONE);
	}

    mbedtls_ssl_conf_rng(&_sslConfig, mbedtls_ctr_drbg_random, &_ctrDrbgContext);

    if (mbedtls_ssl_setup(&_sslContext, &_sslConfig) != 0)
    {
      stop();
      return 0;
    }

    if (mbedtls_ssl_set_hostname(&_sslContext, host) != 0)
    {
      stop();
      return 0;
    }

    char portStr[6];
    itoa(port, portStr, 10);

    mbedtls_ssl_set_bio(&_sslContext, &_netContext.fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    int result;

    do
    {
      result = mbedtls_ssl_handshake(&_sslContext);
    } while (result == MBEDTLS_ERR_SSL_WANT_READ || result == MBEDTLS_ERR_SSL_WANT_WRITE);

    if (result != 0)
    {
      stop();
      return 0;
    }

    _connected = true;
    _ns = false;

    return 1;
  }
}

/* Secure Connection Upgradable Supports */
int WiFiSSLClient::ns_lwip_write(const uint8_t *buf, int bufLen)
{
  return lwip_write(_netContext.fd, buf, bufLen);
}

/* Secure Connection Upgradable Supports */
int WiFiSSLClient::ns_lwip_read(uint8_t *buf, int bufLen)
{
  fd_set readset;
  fd_set writeset;
  fd_set errset;

  struct timeval tv;

  FD_ZERO(&readset);
  FD_SET(_netContext.fd, &readset);
  FD_ZERO(&writeset);
  FD_SET(_netContext.fd, &writeset);

  FD_ZERO(&errset);
  FD_SET(_netContext.fd, &errset);

  tv.tv_sec = 1;
  tv.tv_usec = 0;
  int ret = lwip_select(_netContext.fd, &readset, &writeset, &errset, &tv);

  if (ret < 0)
    return ret;

  return read(_netContext.fd, buf, bufLen);
}

/* Secure Connection Upgradable Supports */
int WiFiSSLClient::connect(/*IPAddress*/ uint32_t ip, uint16_t port)
{
  char ipStr[16];

  sprintf(ipStr, "%d.%d.%d.%d", ((ip & 0xff000000) >> 24),
          ((ip & 0x00ff0000) >> 16), ((ip & 0x0000ff00) >> 8),
          ((ip & 0x000000ff) >> 0) /*ip[0], ip[1], ip[2], ip[3]*/);

  return connect(ipStr, port, false);
}

/* Secure Connection Upgradable Supports */
size_t WiFiSSLClient::_write(uint8_t b) { return _write(&b, 1); } //replacing virtual size_t write(uint8_t);

/* Secure Connection Upgradable Supports */
size_t WiFiSSLClient::_write(const uint8_t *buf, size_t size) //replacing size_t write(const uint8_t *buf, size_t size)
{
  synchronized
  {
    if (_ns)
    {
      return ns_lwip_write(buf, size);
    }
    else
    {
      int written = mbedtls_ssl_write(&_sslContext, buf, size);

      if (written < 0)
      {
        written = 0;
      }

      return written;
    }
  }
}

/* Secure Connection Upgradable Supports */
int WiFiSSLClient::available() //update int available()
{
  synchronized
  {
    if (_ns)
    {
      return ns_available();
    }
    else
    {

      int result = mbedtls_ssl_read(&_sslContext, NULL, 0);

      int n = mbedtls_ssl_get_bytes_avail(&_sslContext);

      if (n == 0 && result != 0 && result != MBEDTLS_ERR_SSL_WANT_READ)
      {
        stop();
      }

      return n;
    }
  }
}

/* Secure Connection Upgradable Supports */
int WiFiSSLClient::ns_available()
{

  if (_netContext.fd < 0)
    return 0;

  if (_rxBuf.length() == 0)
  {
    int bufLen = 1024;
    uint8_t *tmp = new uint8_t[bufLen];
    memset(tmp, 0, bufLen);
    int ret = ns_lwip_read(tmp, bufLen);
    if (ret > 0)
      _rxBuf += (char *)tmp;
    delete[] tmp;
  }

  int result = _rxBuf.length();

  return result;
}

/* Secure Connection Upgradable Supports */
int WiFiSSLClient::_read() //replacing int read()
{

  if (_ns)
  {
    return ns_read();
  }
  else
  {
    uint8_t b;
    if (_peek != -1)
    {
      b = _peek;
      _peek = -1;
    }
    else if (_read(&b, sizeof(b)) == -1)
    {
      return -1;
    }

    return b;
  }
}

/* Secure Connection Upgradable Supports */
int WiFiSSLClient::ns_read()
{

  if (_netContext.fd < 0)
    return 0;

  int c = -1;
  if (_rxBuf.length() == 0)
  {
    uint8_t *buf = new uint8_t[2];
    memset(buf, 0, 2);
    int ret = ns_lwip_read(buf, 1);
    if (ret > 0)
      c = buf[0];
    delete[] buf;
  }
  else
  {
    c = _rxBuf.c_str()[0];
    _rxBuf.erase(0, 1);
  }

  return c;
}

/* Secure Connection Upgradable Supports */
int WiFiSSLClient::_read(uint8_t *buf, size_t size) //replacing int read(uint8_t *buf, size_t size)
{
  synchronized
  {

    if (!available())
    {
      return -1;
    }

    if (_ns)
    {
      return ns_read(buf, size);
    }
    else
    {

      int result = mbedtls_ssl_read(&_sslContext, buf, size);

      if (result < 0)
      {
        if (result != MBEDTLS_ERR_SSL_WANT_READ &&
            result != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
          stop();
        }

        return -1;
      }

      return result;
    }
  }
}

/* Secure Connection Upgradable Supports */
int WiFiSSLClient::ns_read(uint8_t *buf, size_t size)
{

  if (_netContext.fd < 0)
    return 0;

  if (_rxBuf.length() == 0)
    return ns_lwip_read(buf, size);
  else
  {
    size_t sz = size;
    if (sz > _rxBuf.length())
      sz = _rxBuf.length();
    memcpy(buf, (uint8_t *)_rxBuf.c_str(), sz);
    _rxBuf.erase(0, sz);
    return sz;
  }
}

/* Secure Connection Upgradable Supports */
int WiFiSSLClient::peek() //update int peak();
{
  if (_peek == -1)
  {
    _peek = _read();
  }

  return _peek;
}

void WiFiSSLClient::flush() {}

void WiFiSSLClient::stop()
{
  synchronized
  {
    if (_netContext.fd > 0)
    {
      mbedtls_ssl_session_reset(&_sslContext);

      mbedtls_net_free(&_netContext);
      mbedtls_x509_crt_free(&_caCrt);
      mbedtls_entropy_free(&_entropyContext);
      mbedtls_ssl_config_free(&_sslConfig);
      mbedtls_ctr_drbg_free(&_ctrDrbgContext);
      mbedtls_ssl_free(&_sslContext);
    }

    _connected = false;
    _netContext.fd = -1;
  }

  vTaskDelay(1);
}

uint8_t WiFiSSLClient::connected()
{
  synchronized
  {
    if (!_connected)
    {
      return 0;
    }

    if (available())
    {
      return 1;
    }

    return 1;
  }
}

WiFiSSLClient::operator bool()
{
  return ((_netContext.fd != -1) && _connected);
}

/*IPAddress*/ uint32_t WiFiSSLClient::remoteIP()
{
  struct sockaddr_storage addr;
  socklen_t len = sizeof(addr);

  getpeername(_netContext.fd, (struct sockaddr *)&addr, &len);

  return ((struct sockaddr_in *)&addr)->sin_addr.s_addr;
}

uint16_t WiFiSSLClient::remotePort()
{
  struct sockaddr_storage addr;
  socklen_t len = sizeof(addr);

  getpeername(_netContext.fd, (struct sockaddr *)&addr, &len);

  return ntohs(((struct sockaddr_in *)&addr)->sin_port);
}
