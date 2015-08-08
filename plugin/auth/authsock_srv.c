/*  Copyright (c) 2010, 2015, Oracle and/or its affiliates. All rights reserved.

    This program is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation; version 2 of the
    License.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA */

/**
  @file

  authsock_srv authentication plugin.

  Authentication is based on the response from the service listening on the socket
*/
#include <mysql/plugin_auth.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pwd.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

static int socket_auth(MYSQL_PLUGIN_VIO *vio, MYSQL_SERVER_AUTH_INFO *info)
{
  unsigned char *pkt;
  const char *sockpath = "/tmp/authsock.sock";
  int s, t, len;
  char str[100];
  struct sockaddr_un remote;

  if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
      return CR_ERROR;
  }

  remote.sun_family = AF_UNIX;
  strcpy(remote.sun_path, sockpath);
  len = strlen(remote.sun_path) + sizeof(remote.sun_family);
  if (connect(s, (struct sockaddr *)&remote, len) == -1) {
      return CR_ERROR;
  }

  /* no user name yet ? read the client handshake packet with the user name */
  if (info->user_name == 0)
  {
    if (vio->read_packet(vio, &pkt) < 0)
      return CR_ERROR;
  }

  if (vio->read_packet(vio, &pkt) < 0)
    return CR_ERROR;

  sprintf(str, "{\"username\": \"%s\", \"password\": \"%s\"}\n", info->user_name, pkt);
  if (send(s, str, strlen(str), 0) == -1)
      return CR_ERROR;

  t = recv(s, str, 100, 0);
  str[t] = 0;
  if (strncmp(str, "OK", 2) == 0) {
      close(s);
      return CR_OK;
  }

  close(s);
  return CR_ERROR;
}

int generate_auth_string_hash(char *outbuf __attribute__((unused)),
                              unsigned int *buflen,
                              const char *inbuf __attribute__((unused)),
                              unsigned int inbuflen __attribute__((unused)))
{
  *buflen= 0;
  return 0;
}

int validate_auth_string_hash(char* const inbuf  __attribute__((unused)),
                              unsigned int buflen  __attribute__((unused)))
{
  return 0;
}

int set_salt(const char* password __attribute__((unused)),
             unsigned int password_len __attribute__((unused)),
             unsigned char* salt __attribute__((unused)),
             unsigned char* salt_len)
{
  *salt_len= 0;
  return 0;
}

static struct st_mysql_auth socket_auth_handler=
{
  MYSQL_AUTHENTICATION_INTERFACE_VERSION,
  "mysql_clear_password",
  socket_auth,
  generate_auth_string_hash,
  validate_auth_string_hash,
  set_salt,
  0
};

mysql_declare_plugin(socket_auth)
{
  MYSQL_AUTHENTICATION_PLUGIN,
  &socket_auth_handler,
  "authsock_srv",
  "Daniël van Eeden",
  "Unix socket service authication plugin",
  PLUGIN_LICENSE_GPL,
  NULL,
  NULL,
  0x0100,
  NULL,
  NULL,
  NULL,
  0,
}
mysql_declare_plugin_end;
