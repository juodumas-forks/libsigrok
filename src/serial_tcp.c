/*
 * This file is part of the libsigrok project.
 *
 * Copyright (C) 2010-2012 Bert Vermeulen <bert@biot.com>
 * Copyright (C) 2010-2012 Uwe Hermann <uwe@hermann-uwe.de>
 * Copyright (C) 2012 Alexandru Gagniuc <mr.nuke.me@gmail.com>
 * Copyright (C) 2014 Uffe Jakobsen <uffe@uffe.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <glib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <libsigrok/libsigrok.h>
#include "libsigrok-internal.h"
#ifdef HAVE_LIBSERIALPORT
#include <libserialport.h>
#endif
#ifdef G_OS_WIN32
#include <windows.h> /* for HANDLE */
#endif
#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif

#define LOG_PREFIX "serial-tcp"

#define SER_TCP_CONN_PREFIX	"tcp"
#define SER_TCP_DEFAULT_PORT	"23"
#define LENGTH_BYTES		4


/* void prbuf(const void *buf, long unsigned int count); */
/* void prbuf(const void *buf, long unsigned int count) { */
/* 	for (long unsigned int i = 0; i < count; ++i) { */
/* 		char *x = (char *)buf + i; */
/* 		*x == '\0' ? sr_err("byte=00") : sr_err("byte=%02x", *x); */ 
/* 	} */
/* } */


/**
 * @file
 *
 * Serial port handling, wraps the external libserialport dependency.
 */

#ifdef HAVE_SERIAL_COMM

/**
 * @defgroup grp_serial_tcp Serial port handling, libserialport group
 *
 * Serial port handling functions, based on libserialport.
 *
 * @{
 */


SR_PRIV int ser_name_is_tcp(struct sr_serial_dev_inst *serial)
{
	size_t off;
	char sep;

sr_err("== checking if name matches name");

	if (!serial)
		return 0;
	if (!serial->port || !*serial->port)
		return 0;

	if (!g_str_has_prefix(serial->port, SER_TCP_CONN_PREFIX))
		return 0;
	off = strlen(SER_TCP_CONN_PREFIX);
	sep = serial->port[off];
	if (sep != '\0' && sep != '/')
		return 0;

	return 1;
}

static int sr_ser_tcp_open(struct sr_serial_dev_inst *serial, int flags)
{
	struct addrinfo hints;
	struct addrinfo *results, *res;
	int err;
	char **params;

	(void)flags;

sr_err("== TCP OPEN");

sr_err("== serial->port: %s.", serial->port);
	// parsing address and port from conn
	params = g_strsplit(serial->port, "/", 4);
	serial->tcp_address = g_strdup(params[1]);
	serial->tcp_port = g_strdup(params[2]);
	serial->tcp_socket = -1;
	g_strfreev(params);

	if ( !serial->tcp_address || !*serial->tcp_address ) {
		sr_err("TCP address must be provided.");
		return SR_ERR;
	}
	if ( !serial->tcp_port || !*serial->tcp_port ) {
		sr_dbg("Using default TCP port.");
		serial->tcp_port = SER_TCP_DEFAULT_PORT;
	}

sr_err("== tcp_addr: [%s]", serial->tcp_address);
sr_err("== tcp_port: [%s]", serial->tcp_port);

	// make a connection
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	err = getaddrinfo(serial->tcp_address, serial->tcp_port, &hints, &results);

	if (err) {
		sr_err("Address lookup failed: %s:%s: %s", serial->tcp_address, serial->tcp_port,
		gai_strerror(err));
		return SR_ERR;
	}

	for (res = results; res; res = res->ai_next) {
		if ((serial->tcp_socket = socket(res->ai_family
						, res->ai_socktype
						, res->ai_protocol
			)) < 0)
			continue;
		if (connect(serial->tcp_socket, res->ai_addr, res->ai_addrlen) != 0) {
			close(serial->tcp_socket);
			serial->tcp_socket = -1;
			continue;
		}
		break;
	}

	freeaddrinfo(results);

	if (serial->tcp_socket < 0) {
		sr_err("Failed to connect to %s:%s: %s"
			, serial->tcp_address
			, serial->tcp_port
			, g_strerror(errno
		));
		return SR_ERR;
	}

	sr_err("=== sr_ser_tcp_open() end ===");
	return SR_OK;
}

static int sr_ser_tcp_close(struct sr_serial_dev_inst *serial)
{
sr_err("== TCP CLOSE");

	if (close(serial->tcp_socket) < 0)
		return SR_ERR;

	return SR_OK;
}

// TODO NEEDED for TCP?
/* static int sr_ser_tcp_drain(struct sr_serial_dev_inst *serial) */
/* { */
/* sr_err("== TCP DRAIN"); */

/* 	int ret; */
/* 	char *error; */

/* 	if (!serial->sp_data) { */
/* 		sr_dbg("Cannot drain unopened serial port %s.", serial->port); */
/* 		return SR_ERR; */
/* 	} */

/* 	ret = sp_drain(serial->sp_data); */

/* 	if (ret == SP_ERR_FAIL) { */
/* 		error = sp_last_error_message(); */
/* 		sr_err("Error draining port (%d): %s.", */
/* 			sp_last_error_code(), error); */
/* 		sp_free_error_message(error); */
/* 		return SR_ERR; */
/* 	} */

/* 	return SR_OK; */
/* } */

static int sr_ser_tcp_write(struct sr_serial_dev_inst *serial,
	const void *buf, size_t count,
	int nonblocking, unsigned int timeout_ms)
{
	int ret;

	(void)nonblocking;
	(void)timeout_ms;

	if (serial->tcp_socket < 0) {
		sr_dbg("Cannot write to unopened port %s.", serial->port);
		return SR_ERR;
	}

	ret = send(serial->tcp_socket, buf, count, MSG_OOB);

	if (ret < 0) {
		sr_err("Send error: %s", g_strerror(errno));
		return SR_ERR;
	}

	return ret;
}

static int sr_ser_tcp_read(struct sr_serial_dev_inst *serial,
	void *buf, size_t count,
	int nonblocking, unsigned int timeout_ms)
{
	int len;

	(void)nonblocking;

	if (serial->tcp_socket < 0) {
		sr_dbg("Cannot read from unopened port %s.", serial->port);
		return SR_ERR;
	}
	
	fd_set read_fd_set;
	FD_ZERO(&read_fd_set);
	FD_SET((unsigned int)serial->tcp_socket, &read_fd_set);

	/* Initialize the timeout data structure. */
	struct timeval timeout;
	timeout.tv_sec = 0;
	timeout.tv_usec = timeout_ms * 1000; // TODO not enough time for TCP/wifi?

	int ready = select(serial->tcp_socket + 1, &read_fd_set, NULL, NULL, &timeout);
	
	if (ready == -1) {
		sr_err("select error??? TODO man -s2 select");
	}

	if (!(FD_ISSET(serial->tcp_socket, &read_fd_set))) {
		sr_err("== TCP READ timeout:%dms", timeout_ms);
		return 0;
	}

	len = recv(serial->tcp_socket, buf, count, 0);

	if (len < 0) {
		sr_err("Receive error: %s", g_strerror(errno));
		return SR_ERR;
	}

	return len;
}

#ifdef G_OS_WIN32
typedef HANDLE event_handle;
#else
typedef int event_handle;
#endif

static int sr_ser_tcp_source_add_int(struct sr_serial_dev_inst *serial,
	int events,
	void **keyptr, gintptr *fdptr, unsigned int *pollevtptr)
{
sr_err("== TCP source add init");

	struct sp_event_set *event_set;
	gintptr poll_fd;
	unsigned int poll_events;
	enum sp_event mask;

	if ((events & (G_IO_IN | G_IO_ERR)) && (events & G_IO_OUT)) {
		sr_err("Cannot poll input/error and output simultaneously.");
		return SR_ERR_ARG;
	}
	if (!serial->sp_data) {
		sr_err("Invalid serial port.");
		return SR_ERR_ARG;
	}

	if (sp_new_event_set(&event_set) != SP_OK)
		return SR_ERR;

	mask = 0;
	if (events & G_IO_IN)
		mask |= SP_EVENT_RX_READY;
	if (events & G_IO_OUT)
		mask |= SP_EVENT_TX_READY;
	if (events & G_IO_ERR)
		mask |= SP_EVENT_ERROR;

	if (sp_add_port_events(event_set, serial->sp_data, mask) != SP_OK) {
		sp_free_event_set(event_set);
		return SR_ERR;
	}
	if (event_set->count != 1) {
		sr_err("Unexpected number (%u) of event handles to poll.",
			event_set->count);
		sp_free_event_set(event_set);
		return SR_ERR;
	}

	poll_fd = (gintptr) ((event_handle *)event_set->handles)[0];
	mask = event_set->masks[0];

	sp_free_event_set(event_set);

	poll_events = 0;
	if (mask & SP_EVENT_RX_READY)
		poll_events |= G_IO_IN;
	if (mask & SP_EVENT_TX_READY)
		poll_events |= G_IO_OUT;
	if (mask & SP_EVENT_ERROR)
		poll_events |= G_IO_ERR;

	/*
	 * Using serial->sp_data as the key for the event source is not quite
	 * proper, as it makes it impossible to create another event source
	 * for the same serial port. However, these fixed keys will soon be
	 * removed from the API anyway, so this is OK for now.
	 */
	*keyptr = serial->sp_data;
	*fdptr = poll_fd;
	*pollevtptr = poll_events;

	return SR_OK;
}

static int sr_ser_tcp_source_add(struct sr_session *session,
	struct sr_serial_dev_inst *serial, int events, int timeout,
	sr_receive_data_callback cb, void *cb_data)
{
sr_err("== TCP source add");

	int ret;
	void *key;
	gintptr poll_fd;
	unsigned int poll_events;

	ret = sr_ser_tcp_source_add_int(serial, events,
		&key, &poll_fd, &poll_events);
	if (ret != SR_OK)
		return ret;

	return sr_session_fd_source_add(session,
		key, poll_fd, poll_events,
		timeout, cb, cb_data);
}

static int sr_ser_tcp_source_remove(struct sr_session *session,
	struct sr_serial_dev_inst *serial)
{
sr_err("== TCP source remove");

	void *key;

	key = serial->sp_data;
	return sr_session_source_remove_internal(session, key);
}

static GSList *sr_ser_tcp_list(GSList *list, sr_ser_list_append_t append)
{
sr_err("== TCP LIST");

	struct sp_port **ports;
	size_t i;
	const char *name;
	const char *desc;

	if (sp_list_ports(&ports) != SP_OK)
		return list;

	for (i = 0; ports[i]; i++) {
		name = sp_get_port_name(ports[i]);
		desc = sp_get_port_description(ports[i]);
		list = append(list, name, desc);
	}

	sp_free_port_list(ports);

	return list;
}

/* static size_t sr_ser_tcp_get_rx_avail(struct sr_serial_dev_inst *serial) */
/* { */
/* sr_err("== TCP rx avail"); */

/* 	int rc; */

/* 	if (!serial) */
/* 		return 0; */

/* 	rc = sp_input_waiting(serial->sp_data); */
/* 	if (rc < 0) */
/* 		return 0; */

/* 	return rc; */
/* } */

static struct ser_lib_functions ser_tcp = {
	.open = sr_ser_tcp_open,
	.close = sr_ser_tcp_close,
	//.drain = sr_ser_tcp_drain,
	.write = sr_ser_tcp_write,
	.read = sr_ser_tcp_read,
	.set_params = std_dummy_set_params,
	.setup_source_add = sr_ser_tcp_source_add,
	.setup_source_remove = sr_ser_tcp_source_remove,
	.list = sr_ser_tcp_list,
	.get_frame_format = NULL,
	/* .get_rx_avail = sr_ser_tcp_get_rx_avail, */
};
SR_PRIV struct ser_lib_functions *ser_lib_funcs_tcp = &ser_tcp;

#else

SR_PRIV struct ser_lib_functions *ser_lib_funcs_tcp = NULL;

#endif
