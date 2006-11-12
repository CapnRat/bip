/*
 * $Id: irc.c,v 1.156 2005/04/21 06:58:50 nohar Exp $
 *
 * This file is part of the bip project
 * Copyright (C) 2004 2005 Arnaud Cornet and Lo�c Gomez
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * See the file "COPYING" for the exact licensing terms.
 */

#include "config.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "util.h"
#include "irc.h"
#include "bip.h"
#include "log.h"
#include "connection.h"
#include "md5.h"

#define S_CONN_DELAY (10)

extern int sighup;

static int irc_join(struct link_server *server, struct line *line);
static int irc_part(struct link_server *server, struct line *line);
static int irc_mode(struct link_server *server, struct line *line);
static int irc_kick(struct link_server *server, struct line *line);
static int irc_privmsg(struct link_server *server, struct line *line);
static int irc_notice(struct link_server *server, struct line *line);
static int irc_quit(struct link_server *server, struct line *line);
static int irc_nick(struct link_server *server, struct line *line);
static int irc_generic_quit(struct link_server *server, struct line *line);
static int irc_topic(struct link_server *server, struct line *line);
static int irc_332(struct link_server *server, struct line *line);
static int irc_333(struct link_server *server, struct line *line);
static int irc_353(struct link_server *server, struct line *line);
static int irc_366(struct link_server *server, struct line *line);
void irc_server_shutdown(struct link_server *s);

void irc_client_free(struct link_client *cli);
static char *make_irc_mask(char *nick, char *oldim);
extern int conf_backlog;
extern int conf_log_sync_interval;
extern int conf_error;
extern char conf_errstr[];
extern int conf_blreset_on_talk;

void write_user_list(connection_t *c, char *dest);

static void irc_copy_cli(struct link_client *src, struct link_client *dest,
		struct line *line);
static void irc_cli_make_join(struct link_client *ic);

#define LAGOUT_TIME (360)
#define LAGCHECK_TIME (90)
#define RECONN_TIMER (120)
#define LOGGING_TIMEOUT (360)
#define CONN_INTERVAL 60
#define CONNECT_TIMEOUT 60

struct channel *channel_new(const char *name)
{
	struct channel *chan;
	chan = calloc(sizeof(struct channel), 1);
	if (!chan)
		fatal("calloc");
	chan->name = strdup(name);
	hash_init(&chan->nicks, HASH_NOCASE);
	return chan;
}

static char *make_irc_mask(char *nick, char *oldim)
{
	char *nm;
	char *imaskend = oldim;
	if (!imaskend) {
		imaskend = "!bip@bip.bip.bip";
	} else {
		while (*imaskend && *imaskend != '!')
			imaskend++;
		if (*imaskend == '\0')
			imaskend = "!bip@bip.bip.bip";
	}

	nm = malloc(strlen(nick) + strlen(imaskend) + 1);
	*nm = 0;
	strcat(nm, nick);
	strcat(nm, imaskend);
	return nm;
}

char *nick_from_ircmask(char *mask)
{
	char *nick = mask;
	char *ret;
	size_t len;

	if (!mask)
		fatal("nick_from_ircmask");

	while (*nick && *nick != '!')
		nick++;
	if (!*nick)
		return strdup(mask);
	len = nick - mask;
	ret = malloc(len + 1);
	if (!ret)
		fatal("malloc");
	memcpy(ret, mask, len);
	ret[len] = 0;
	return ret;
}

static int is_irc_mask(char *mask)
{
	while (*mask && *mask != '!')
		mask++;
	if (*mask == 0)
		return 0;
	while (*mask && *mask != '@')
		mask++;
	if (*mask == 0)
		return 0;
	return 1;
}

static void set_ircmask(struct link_server *server, char *ircmask)
{
	if (!is_irc_mask(ircmask))
		return;
	if (server->irc_mask)
		free(server->irc_mask);
	server->irc_mask = strdup(ircmask);
}

#define NAMESIZE 256

list_t *channel_name_list(struct channel *c)
{
	list_t *ret;
	hash_iterator_t hi;
	size_t s = NAMESIZE;
	ret = list_new(NULL);

	size_t len = 0;
	char *str = malloc(NAMESIZE);
	*str = 0;
	for (hash_it_init(&c->nicks, &hi); hash_it_item(&hi);
			hash_it_next(&hi)){
		struct nick *n = hash_it_item(&hi);

		if (strlen(n->name) + 2 >= NAMESIZE)
			fatal("nick too big for me"); /* FIXME */

		if (len + strlen(n->name) + 2 + (n->ovmask ? 1 : 0)
				>= NAMESIZE) {
			list_add_last(ret, str);
			str = malloc(s);
			*str = 0;
			len = 0;
		}
		if (len != 0) {
			strncat(str, " ", NAMESIZE);
			len++;
		}
		if (n->ovmask & NICKOP) {
			strncat(str, "@", NAMESIZE);
			len++;
		} else if (n->ovmask & NICKVOICED) {
			strncat(str, "+", NAMESIZE);
			len++;
		}
		strncat(str, n->name, NAMESIZE);
		len += strlen(n->name);
		if (len >= NAMESIZE)
			fatal("internal error 5");
	}
	list_add_last(ret, str);
	return ret;
}

static int irc_001(struct link_server *server, struct line *line)
{
	int ret = OK_FORGET;
	char *p, *ps, *pe;
	size_t len;
	char *ircmask, *oldircmask;

	if (LINK(server)->s_state == IRCS_WAS_CONNECTED)
		LINK(server)->s_state = IRCS_RECONNECTING;
	else
		LINK(server)->s_state = IRCS_CONNECTING;

	if (line->elemc != 3)
		return ERR_PROTOCOL;

	ps = pe = line->elemv[2];
	pe += strlen(pe);
	p = strrchr(ps, ' ');
	if (!p)
		return ERR_PROTOCOL;
	p++;

	len = pe - p;
	ircmask = malloc(len + 1);
	if (!ircmask)
		fatal("malloc");
	memcpy(ircmask, p, len);
	ircmask[len] = 0;

	oldircmask = server->irc_mask;
	server->irc_mask = NULL;
	set_ircmask(server, ircmask);
	if (server->nick)
		free(server->nick);
	server->nick = nick_from_ircmask(ircmask);
	if (server->irc_mask == NULL)
		server->irc_mask = make_irc_mask(server->nick, "");

	/* 001 means the nick we sent is accepted by server, inform clients */
	if (oldircmask && LINK(server)->s_state == IRCS_RECONNECTING &&
			LINK(server)->prev_nick) {
		if (strcmp(LINK(server)->prev_nick, server->nick) != 0) {
			/*
			 * Inform connected clients that server<->proxy
			 * disconnection resulted in nick change
			 * sadly the oldircmask info is a guess only
			 */
			int i;
			for (i = 0; i < LINK(server)->l_clientc; i++) {
				struct link_client *c =
					LINK(server)->l_clientv[i];
				WRITE_LINE1(CONN(c), oldircmask, "NICK",
						server->nick);
			}
		}
	}
	if (LINK(server)->prev_nick)
		free(LINK(server)->prev_nick);
	LINK(server)->prev_nick = strdup(server->nick);

	if (oldircmask)
		free(oldircmask);
	free(ircmask);
	return ret;
}

void irc_start_lagtest(struct link_server *l)
{
	l->laginit_ts = time(NULL);
	write_line_fast(CONN(l), "PING :" S_PING "\r\n");
}

/*
 * returns 0 if we ping timeout
 */
void irc_compute_lag(struct link_server *is)
{
	if (is->laginit_ts == -1)
		fatal("irc_compute_lag");

	is->lag = time(NULL) - is->laginit_ts;
}

int irc_lags_out(struct link_server *is)
{
	if (is->lag > LAGOUT_TIME) {
		mylog(LOG_ERROR, "%s Lags out! closing", LINK(is)->name);
		return 1;
	} else {
		mylog(LOG_DEBUG, "%s lag : %d\n", LINK(is)->name, is->lag);
		return 0;
	}
}

void irc_lag_init(struct link_server *is)
{
	is->lagtest_timeout = LAGCHECK_TIME;
	is->laginit_ts = -1;
}

static void irc_server_join(struct link_server *s)
{
	list_iterator_t it;
	for (list_it_init(&LINK(s)->chan_infos_order, &it); list_it_item(&it);
			list_it_next(&it)) {
		struct chan_info *ci = list_it_item(&it);
		if (!ci->key)
			WRITE_LINE1(CONN(s), NULL, "JOIN", ci->name);
		else
			WRITE_LINE2(CONN(s), NULL, "JOIN", ci->name, ci->key);
	}
}

static void irc_server_connected(struct link_server *server)
{
	int i;
	char *initmask;
        LINK(server)->s_state = IRCS_CONNECTED;
        irc_server_join(server);
        log_connected(LINK(server)->log);

	/* Tell already connected clients what the nick is */
	initmask = make_irc_mask(server->nick, server->irc_mask);

	/* we change nick on client */
	for (i = 0; i < LINK(server)->l_clientc; i++) {
		struct link_client *ic = LINK(server)->l_clientv[i];
		WRITE_LINE1(CONN(ic), initmask, "NICK", server->nick);
	}
	free(initmask);

	/* basic helper for nickserv and co */
	list_iterator_t itocs;
	for (list_it_init(&LINK(server)->on_connect_send, &itocs);
				list_it_item(&itocs); list_it_next(&itocs)) {
                ssize_t len = strlen(list_it_item(&itocs)) + 2;
                char *str = malloc(len + 1);
                sprintf(str, "%s\r\n", (char *)list_it_item(&itocs));
                write_line(CONN(server), str);
                free(str);
        }

	if (LINK(server)->l_clientc == 0) {
		if (LINK(server)->away_nick)
			WRITE_LINE1(CONN(server), NULL, "NICK",
					LINK(server)->away_nick);
		if (LINK(server)->no_client_away_msg)
			WRITE_LINE1(CONN(server), NULL, "AWAY",
					LINK(server)->no_client_away_msg);
	}
}

static int who_arg_to_ovmask(char *str)
{
	int ovmask = 0;
	if (strchr(str, '@'))
		ovmask |= NICKOP;
	if (strchr(str, '+'))
		ovmask |= NICKVOICED;
	return ovmask;
}

/*
 * Given the way irc nets disrespect the rfc, maybe we should completely forget
 * about this damn ircmask...
:irc.iiens.net 352 pwet * ~a je.suis.t1r.net irc.iiens.net pwet H :0 d
*/
static int parse_352(struct link_server *server, struct line *line)
{
	char *im;

	if (line->elemc < 8)
		return ERR_PROTOCOL;

	if (strcmp(line->elemv[2], "*") == 0) {
		if (server->irc_mask &&
				strcmp(line->elemv[1], server->nick) == 0) {
			im = malloc(strlen(server->nick) +
					strlen(line->elemv[3]) +
					strlen(line->elemv[4]) + 2 + 1);
			strcpy(im, server->nick);
			strcat(im, "!");
			strcat(im, line->elemv[3]);
			strcat(im, "@");
			strcat(im, line->elemv[4]);
			set_ircmask(server, im);
			free(im);
			return OK_FORGET;
		}
	} else {
		struct channel *channel;
		struct nick *nick;

		channel = hash_get(&server->channels, line->elemv[2]);
		if (!channel)
			return OK_COPY;

		nick = hash_get(&channel->nicks, line->elemv[6]);
		if (!nick)
			return OK_COPY;

		nick->ovmask = who_arg_to_ovmask(line->elemv[7]);
	}
	return OK_COPY_WHO;
}

static int irc_315(struct link_server *server, struct line *l)
{
	struct link *link = LINK(server);
	if (link->who_client) {
		--link->who_client->who_count;

		if (link->who_client->who_count < 0)
			fatal("negative who count");
	}
	l = NULL; /* keep gcc happy */

	return OK_COPY_WHO;
}

/*
 * parses:join part mode kick kill privmsg quit nick names
 * returns: -1 invalid protocol
 */
int irc_dispatch_server(struct link_server *server, struct line *line)
{
	int ret = OK_COPY;

	if (line->elemc == 0)
		return ERR_PROTOCOL;

	if (strcmp(line->elemv[0], "PING") == 0) {
		if (line->elemc < 2)
			return ERR_PROTOCOL;
		struct line *resp = irc_line_new();
		char *resps;
		irc_line_append(resp, "PONG");
		irc_line_append(resp, line->elemv[1]);
		resp->colon = 1; /* it seems some ircds want it */
		resps = irc_line_to_string(resp);
		write_line_fast(CONN(server), resps);
		irc_line_free(resp);
		free(resps);
		ret = OK_FORGET;
	} else if (strcmp(line->elemv[0], "PONG") == 0) {
		if (line->elemc == 3  && strcmp(line->elemv[2], S_PING) == 0) {
			if (server->laginit_ts != -1) {
				irc_compute_lag(server);
				irc_lag_init(server);
			}
			ret = OK_FORGET;
		}
	} else if (strcmp(line->elemv[0], "433") == 0) {
		if (LINK(server)->s_state != IRCS_CONNECTED) {
			size_t nicklen = strlen(server->nick);
			char *newnick = malloc(nicklen + 2);
			strcpy(newnick, server->nick);
			if (strlen(server->nick) < 9)
				strcat(newnick, "`");
			else if (newnick[8] != '`') {
				newnick[8] = '`';
				newnick[9] = 0;
			} else {
				newnick[8] = rand() * ('z' - 'a') / RAND_MAX +
					'a';
				newnick[9] = 0;
			}
			free(server->nick);
			server->nick = newnick;

			WRITE_LINE1(CONN(server), NULL, "NICK", server->nick);
			ret = OK_FORGET;
		}
	} else if (LINK(server)->s_state == IRCS_RECONNECTING) {
		ret = OK_FORGET;
		if (strcmp(line->elemv[0], "376") == 0) /* end of motd */
			irc_server_connected(server);
		else if (strcmp(line->elemv[0], "422") == 0) /* no motd */
				irc_server_connected(server);

	} else if (LINK(server)->s_state == IRCS_CONNECTING) {
		ret = OK_FORGET;
		if (strcmp(line->elemv[0], "NOTICE") == 0) {
		} else if (strcmp(line->elemv[0], "376") == 0) {
							/* end of motd */
			irc_server_connected(server);
			list_add_last(&LINK(server)->init_strings,
					irc_line_dup(line));
		} else if (strcmp(line->elemv[0], "422") == 0) { /* no motd */
			irc_server_connected(server);
			list_add_last(&LINK(server)->init_strings,
					irc_line_dup(line));
		} else {
			list_add_last(&LINK(server)->init_strings,
					irc_line_dup(line));
		}
	} else if (strcmp(line->elemv[0], "001") == 0) {
		ret = irc_001(server, line);
		if (LINK(server)->s_state == IRCS_CONNECTING) {
			if (!list_is_empty(&LINK(server)->init_strings))
				return ERR_PROTOCOL;
			list_add_last(&LINK(server)->init_strings,
					irc_line_dup(line));
		}
	} else if (strcmp(line->elemv[0], "JOIN") == 0) {
		ret = irc_join(server, line);
	} else if (strcmp(line->elemv[0], "332") == 0) {
		ret = irc_332(server, line);
	} else if (strcmp(line->elemv[0], "333") == 0) {
		ret = irc_333(server, line);
	} else if (strcmp(line->elemv[0], "352") == 0) {
		ret = parse_352(server, line);
	} else if (strcmp(line->elemv[0], "315") == 0) {
		ret = irc_315(server, line);
	} else if (strcmp(line->elemv[0], "353") == 0) {
		ret = irc_353(server, line);
	} else if (strcmp(line->elemv[0], "366") == 0) {
		ret = irc_366(server, line);
	} else if (strcmp(line->elemv[0], "PART") == 0) {
		ret = irc_part(server, line);
	} else if (strcmp(line->elemv[0], "MODE") == 0) {
		ret = irc_mode(server, line);
	} else if (strcmp(line->elemv[0], "TOPIC") == 0) {
		ret = irc_topic(server, line);
	} else if (strcmp(line->elemv[0], "KICK") == 0) {
		ret = irc_kick(server, line);
	} else if (strcmp(line->elemv[0], "PRIVMSG") == 0) {
		ret = irc_privmsg(server, line);
	} else if (strcmp(line->elemv[0], "NOTICE") == 0) {
		ret = irc_notice(server, line);
	} else if (strcmp(line->elemv[0], "QUIT") == 0) {
		ret = irc_quit(server, line);
	} else if (strcmp(line->elemv[0], "NICK") == 0) {
		ret = irc_nick(server, line);
	}

	if (ret == OK_COPY) {
		int i;
		for (i = 0; i < LINK(server)->l_clientc; i++) {
			char *s = irc_line_to_string(line);
			write_line(CONN(LINK(server)->l_clientv[i]), s);
			free(s);
		}
	}
	if (ret == OK_COPY_WHO && LINK(server)->who_client) {
		char *s;

		s = irc_line_to_string(line);
		write_line(CONN(LINK(server)->who_client), s);
		free(s);

		if (LINK(server)->who_client->who_count == 0) {
			int i;
			for (i = 0; i < LINK(server)->l_clientc; i++) {
				struct link_client *ic =
						LINK(server)->l_clientv[i];
				if (ic == LINK(server)->who_client) {
					if (!list_is_empty(&ic->who_queue))
						fatal("who active and queued?");
					continue;
				}

				if (!list_is_empty(&ic->who_queue)) {
					char *l;
					while ((l = list_remove_first(
							&ic->who_queue))) {
						write_line(CONN(server), l);
						free(l);
					}
					LINK(server)->who_client = ic;
					break;
				}
			}
			if (i == LINK(server)->l_clientc)
				LINK(server)->who_client = NULL;
		}
	}
	return ret;
}

/* send join and related stuff to client */
static void irc_send_join(struct link_client *ic, struct channel *chan)
{
	WRITE_LINE1(CONN(ic), LINK(ic)->l_server->irc_mask, "JOIN", chan->name);
	if (chan->topic)
		WRITE_LINE3(CONN(ic), P_SERV, "332", LINK(ic)->l_server->nick,
				chan->name, chan->topic);
	if (chan->creator && chan->create_ts)
		WRITE_LINE4(CONN(ic), P_SERV, "333", LINK(ic)->l_server->nick,
				chan->name, chan->creator, chan->create_ts);

	/* XXX: could be more efficient */
	if (conf_backlog && log_has_backlog(LINK(ic)->log, chan->name)) {
		char *line;
		int skip = 0;
		while ((line =
		    log_backread(LINK(ic)->log, chan->name, &skip))) {
			if (!skip)
				write_line(CONN(ic), line);
			free(line);
		}
		WRITE_LINE2(CONN(ic), P_IRCMASK, "PRIVMSG", chan->name,
				"End of backlog.");
	}

	list_t *name_list = channel_name_list(chan);
	char *s;
	while ((s = list_remove_first(name_list))) {
		char tmptype[2];
		tmptype[0] = chan->type;
		tmptype[1] = 0;
		WRITE_LINE4(CONN(ic), P_SERV, "353", LINK(ic)->l_server->nick,
				tmptype, chan->name, s);
		free(s);
	}
	list_free(name_list);

	WRITE_LINE3(CONN(ic), P_SERV, "366", LINK(ic)->l_server->nick,
			chan->name, "End of /NAMES list.");

}

static void write_init_string(connection_t *c, struct line *line, char *nick)
{
	char *tmp;
	char *l;

	tmp = line->elemv[1];
	line->elemv[1] = nick;
	l = irc_line_to_string(line);
	write_line(c, l);
	free(l);
	line->elemv[1] = tmp;
}

static void bind_to_link(struct link *l, struct link_client *ic)
{
	int i = l->l_clientc;

	LINK(ic) = l;
	l->l_clientc++;
	l->l_clientv = realloc(l->l_clientv, l->l_clientc *
			sizeof(struct link_client *));
	if (!l->l_clientv)
		fatal("realloc");
	l->l_clientv[i] = ic;
}

void unbind_from_link(struct link_client *ic)
{
	struct link *l = LINK(ic);
	int i;

	for (i = 0; i < l->l_clientc; i++)
		if (l->l_clientv[i] == ic)
			break;
	if (i == l->l_clientc)
		fatal("unbind_from_link");

	if (l->who_client == ic)
		l->who_client = NULL;

	for (i = i + 1; i < l->l_clientc; i++)
		l->l_clientv[i - 1] = l->l_clientv[i];

	l->l_clientc--;
	l->l_clientv = realloc(l->l_clientv, l->l_clientc *
			sizeof(struct link_client *));
	if (l->l_clientc == 0) { /* realloc was equiv to free() */
		l->l_clientv = NULL;
		return;
	}
	if (!l->l_clientv)
		fatal("realloc");
}

int irc_cli_bip(struct link_client *ic, struct line *line)
{
	return adm_bip(ic, line);
}

#define PASS_SEP ':'

static char *get_str_elem(char *str, int num)
{
	char *ret;
	char *c;
	char *cur = str;
	int index = 0;

	while ((c = strchr(cur, PASS_SEP))) {
		if (index < num) {
			index++;
			cur = c + 1;
			continue;
		}
		if (c - cur < 1)
			return NULL;
		ret = malloc(c - cur + 1);
		strncpy(ret, cur, c - cur);
		ret[c - cur] = 0;
		return ret;
	}
	if (index == num) {
		c = str + strlen(str);
		if (c - cur < 1)
			return NULL;
		ret = malloc(c - cur + 1);
		strncpy(ret, cur, c - cur);
		ret[c - cur] = 0;
		return ret;
	}
	return NULL;
}

static void irc_cli_make_join(struct link_client *ic)
{
	if (LINK(ic)->l_server) {
		/* join channels, step one, those in conf, in order */
		list_iterator_t li;
		for (list_it_init(&LINK(ic)->chan_infos_order, &li);
				list_it_item(&li); list_it_next(&li)) {
			struct chan_info *ci = (struct chan_info *)
				list_it_item(&li);
			struct channel *chan;
			if ((chan = hash_get(&LINK(ic)->l_server->channels,
							ci->name)))
				irc_send_join(ic, chan);
		}

		/* step two, those not in conf */
		hash_iterator_t hi;
		for (hash_it_init(&LINK(ic)->l_server->channels, &hi);
				hash_it_item(&hi); hash_it_next(&hi)) {
			struct channel *chan = (struct channel *)
				hash_it_item(&hi);
			if (!hash_get(&LINK(ic)->chan_infos, chan->name))
				irc_send_join(ic, chan);
		}

		/* backlog privates */
		char *str;
		int skip = 0;
		while ((str = log_backread(LINK(ic)->log, S_PRIVATES, &skip))) {
			if (!skip)
				write_line(CONN(ic), str);
			free(str);
		}
	}
}

static int irc_cli_startup(struct link_client *ic, struct line *line,
		list_t *linkl)
{
	char *initmask;
	char *init_nick;
	char *user, *pass, *connname;
	(void)line;

	if (!ic->init_pass)
		fatal("internal irc_cli_startup");

	user = get_str_elem(ic->init_pass, 0);
	if (!user)
		return ERR_AUTH;
	pass = get_str_elem(ic->init_pass, 1);
	if (!pass) {
		free(user);
		return ERR_AUTH;
	}
	connname = get_str_elem(ic->init_pass, 2);
	if (!connname) {
		free(pass);
		free(user);
		return ERR_AUTH;
	}

	list_iterator_t it;
	for (list_it_init(linkl, &it); list_it_item(&it); list_it_next(&it)) {
		struct link *l = list_it_item(&it);
		if (strcmp(user, l->username) == 0
				&& strcmp(connname, l->name) == 0) {
			if (chash_cmp(pass, l->password, l->seed) == 0) {
				bind_to_link(l, ic);
				break;
			}
		}
	}

	if (!LINK(ic))
		mylog(LOG_ERROR, "Invalid credentials (user:%s connection:%s)",
				user, connname);
	free(user);
	free(connname);
	free(pass);

	free(ic->init_pass);
	ic->init_pass = NULL;
	init_nick = ic->init_nick;
	ic->init_nick = NULL;

	if (!LINK(ic)) {
		free(init_nick);
		return ERR_AUTH;
	}

#ifdef HAVE_LIBSSL
	if (LINK(ic)->s_state != IRCS_CONNECTED) {
		/* Check if we have an untrusted certificate from the server */
		if (ssl_check_trust(ic)) {
			TYPE(ic) = IRC_TYPE_TRUST_CLIENT;
			ic->allow_trust = 1;
			free(init_nick);
			return OK_FORGET;
		}
	}
#endif

	if (LINK(ic)->s_state == IRCS_NONE) {
		/* drop it if corresponding server hasn't connected at all. */
		write_line_fast(CONN(ic), ":irc.bip.net NOTICE pouet "
				":ERROR Proxy not yet connected, try again "
				"later\r\n");
		unbind_from_link(ic);
		free(init_nick);
		return OK_CLOSE;
	}

#if 0
	TODO code this -- OR NOT!
	if (!connection_check_source(ic, ic->client->src_ipl))
		return ERR_AUTH;
#endif

	TYPE(ic) = IRC_TYPE_CLIENT;

	if (LINK(ic)->l_server)
		initmask = make_irc_mask(init_nick,
				LINK(ic)->l_server->irc_mask);
	else
		initmask = make_irc_mask(init_nick, LINK(ic)->prev_ircmask);

	for (list_it_init(&LINK(ic)->init_strings, &it);
			list_it_item(&it); list_it_next(&it))
		write_init_string(CONN(ic), list_it_item(&it), init_nick);

	/* we change nick on server */
	if (LINK(ic)->l_server) {
		struct link_server *server = LINK(ic)->l_server;
		WRITE_LINE1(CONN(ic), initmask, "NICK", server->nick);

		if (!LINK(ic)->ignore_first_nick)
			WRITE_LINE1(CONN(server), NULL, "NICK", init_nick);
		else if (LINK(ic)->away_nick &&
				strcmp(LINK(ic)->away_nick, server->nick) == 0)
			WRITE_LINE1(CONN(server), NULL, "NICK",
					LINK(server)->connect_nick);

		/* change away status */
		if (server && LINK(ic)->no_client_away_msg)
			WRITE_LINE0(CONN(server), NULL, "AWAY");
	}

	free(initmask);
	if (!LINK(ic)->l_server) {
		free(init_nick);
		return OK_FORGET;
	}

	irc_cli_make_join(ic);

	log_client_connected(LINK(ic)->log);
	free(init_nick);

	return OK_FORGET;
}

static int irc_cli_nick(struct link_client *ic, struct line *line, list_t *cl)
{
	if (line->elemc != 2)
		return ERR_PROTOCOL;

	if ((ic->state & IRCC_READY) == IRCC_READY)
		return OK_COPY;

	ic->state |= IRCC_NICK;
	if (ic->init_nick)
		free(ic->init_nick);
	ic->init_nick = strdup(line->elemv[1]);

	if ((ic->state & IRCC_READY) == IRCC_READY)
		return irc_cli_startup(ic, line, cl);

	if ((ic->state & IRCC_PASS) != IRCC_PASS)
		WRITE_LINE2(CONN(ic), P_SERV, "NOTICE", ic->init_nick,
				"You should type /QUOTE PASS your_username:your_password:your_connection_name");

	return OK_FORGET;
}

static int irc_cli_user(struct link_client *ic, struct line *line, list_t *cl)
{
	if (line->elemc != 5)
		return ERR_PROTOCOL;

	if ((ic->state & IRCC_READY) == IRCC_READY)
		return ERR_PROTOCOL;

	ic->state |= IRCC_USER;
	if ((ic->state & IRCC_READY) == IRCC_READY)
		return irc_cli_startup(ic, line, cl);
	return OK_FORGET;
}

static int irc_cli_pass(struct link_client *ic, struct line *line, list_t *cl)
{
	if (line->elemc != 2)
		return ERR_PROTOCOL;

	if ((ic->state & IRCC_READY) == IRCC_READY)
		return ERR_PROTOCOL;

	ic->state |= IRCC_PASS;
	if (ic->init_pass)
		free(ic->init_pass);
	ic->init_pass = strdup(line->elemv[1]);
	if ((ic->state & IRCC_READY) == IRCC_READY)
		return irc_cli_startup(ic, line, cl);
	return OK_FORGET;
}

static int irc_cli_quit(struct link_client *ic, struct line *line)
{
	(void)ic;
	(void)line;
	return OK_CLOSE;
}

static int irc_cli_privmsg(struct link_client *ic, struct line *line)
{
	log_cli_privmsg(LINK(ic)->log, LINK(ic)->l_server->nick,
				line->elemv[1], line->elemv[2]);
	if (conf_blreset_on_talk)
		adm_blreset(ic);
	return OK_COPY_CLI;
}

static int irc_cli_notice(struct link_client *ic, struct line *line)
{
	log_cli_notice(LINK(ic)->log, LINK(ic)->l_server->nick,
				line->elemv[1], line->elemv[2]);
	return OK_COPY_CLI;
}

static int irc_cli_who(struct link_client *ic, struct line *line)
{
	struct link *l = LINK(ic);

	if (l->who_client && l->who_client != ic) {
		list_add_first(&ic->who_queue, irc_line_to_string(line));
		return OK_FORGET;
	}

	if (!l->who_client)
		l->who_client = ic;

	++ic->who_count;

	return OK_COPY;
}

#if 0
static void unbind_to_server(struct link_client *ic)
{
	struct irc_server *s = ic->client->server;
	int i;
	for (i = 0; i < s->clientc; i++)
		if (s->clientv[i] == ic)
			break;
	if (i == s->clientc)
		fatal("unbind_to_server");
	for (i = i + 1; i < s->clientc; i++)
		s->clientv[i - 1] = s->clientv[i];

	s->clientc--;
	s->clientv = realloc(s->clientv, s->clientc *
			sizeof(struct irc_client *));
	if (s->clientc == 0) { /* realloc was equiv to free() */
		s->clientv = NULL;
		return;
	}
	if (!s->clientv)
		fatal("realloc");
}

static void bind_to_server(struct irc_client *ic)
{
	struct irc_server *s = ic->client->server;
	int i = s->clientc;
	s->clientc++;
	s->clientv = realloc(s->clientv, s->clientc *
			sizeof(struct irc_client *));
	if (!s->clientv)
		fatal("realloc");
	s->clientv[i] = ic;
}
#endif

static void irc_notify_disconnection(struct link_server *is)
{
	int i;
	for (i = 0; i < LINK(is)->l_clientc; i++) {
		struct link_client *ic = LINK(is)->l_clientv[i];
		hash_iterator_t hi;
		for (hash_it_init(&is->channels, &hi); hash_it_item(&hi);
			hash_it_next(&hi)) {
			struct channel *c = (struct channel *)hash_it_item(&hi);
			WRITE_LINE3(CONN(ic), P_IRCMASK, "KICK",
					c->name, is->nick,
					"Server disconnected, reconnecting");
		}
		WRITE_LINE2(CONN(ic), P_IRCMASK, "PRIVMSG", is->irc_mask,
					"Server disconnected, reconnecting");
	}
}

void irc_add_channel_info(struct link_server *ircs, char *chan, char *key)
{
	struct chan_info *ci;
	if (!ischannel(*chan))
		return;

	ci = hash_get(&LINK(ircs)->chan_infos, chan);
	if (!ci) {
		struct chan_info *ci;
		ci = malloc(sizeof(struct chan_info));
		ci->name = strdup(chan);
		ci->key = key ? strdup(key) : NULL;
		hash_insert(&LINK(ircs)->chan_infos, chan, ci);
		list_add_last(&LINK(ircs)->chan_infos_order, ci);
	} else {
		if (ci->key) {
			free(ci->key);
			ci->key = NULL;
		}
		ci->key = key ? strdup(key) : NULL;
	}
}

static int irc_cli_join(struct link_client *irc, struct line *line)
{
	if (line->elemc != 2 && line->elemc != 3)
		return ERR_PROTOCOL;

	char *s, *e, *ks, *ke = 0;
	s = line->elemv[1];
	if (line->elemc == 3)
		ks = line->elemv[2];
	else
		ks = NULL;

	while ((e = strchr(s, ','))) {
		size_t len = e - s;
		char *p = malloc(len + 1);
		size_t klen;
		char *kp = NULL;

		memcpy(p, s, len);
		p[len] = 0;
		if (ks) {
			if (strlen(ks)) {
				ke = strchr(ks, ',');
				if (!ke)
					ke = ks + strlen(ks);
				klen = ke - ks;
				kp = malloc(klen + 1);
				memcpy(kp, ks, klen);
				kp[klen] = 0;
				if (*ke == 0)
					ks = NULL;
			} else
				kp = ks = NULL;
		}

		irc_add_channel_info(LINK(irc)->l_server, p, kp);
		free(p);
		if (kp) {
			free(kp);
			if (ks)
				ks = ke + 1;
		}
		s = e + 1;
	}

	irc_add_channel_info(LINK(irc)->l_server, s, ks);
	return OK_COPY;
}

static int irc_cli_part(struct link_client *irc, struct line *line)
{
	if (line->elemc != 2 && line->elemc != 3)
		return ERR_PROTOCOL;

	struct chan_info *ci;
	if ((ci = hash_remove_if_exists(&LINK(irc)->chan_infos,
					line->elemv[1])) != NULL) {
		list_remove(&LINK(irc)->chan_infos_order, ci);
		free(ci->name);
		if (ci->key)
			free(ci->key);
		free(ci);
	}
	return OK_COPY;
}

#ifdef HAVE_LIBSSL
static int irc_dispatch_trust_client(struct link_client *ic, struct line *line) 
{
	int r = OK_COPY;
	if (line->elemc < 2)
		return ERR_PROTOCOL;

	if (strcmp(line->elemv[0], "BIP") == 0 &&
	    strcmp(line->elemv[1], "TRUST") == 0)
		r = adm_trust(ic, line);

	return r;
}
#endif

int irc_cli_bip(struct link_client *ic, struct line *line);
static int irc_dispatch_client(struct link_client *ic, struct line *line)
{
	int r = OK_COPY;
	if (line->elemc == 0)
		return ERR_PROTOCOL;

	if (strcmp(line->elemv[0], "PING") == 0) {
		if (line->elemc < 2)
			return ERR_PROTOCOL;
		WRITE_LINE1(CONN(ic), LINK(ic)->name, "PONG", line->elemv[1]);
		r = OK_FORGET;
	} else if (LINK(ic)->s_state != IRCS_CONNECTED) {
		write_line_fast(CONN(ic), ":irc.bip.net NOTICE pouet "
				":ERROR Proxy not connected, please wait "
				"before sending commands\r\n");
		r = OK_FORGET;
	} else if (strcasecmp(line->elemv[0], "BIP") == 0) {
		r = irc_cli_bip(ic, line);
	} else if (strcmp(line->elemv[0], "JOIN") == 0) {
		r = irc_cli_join(ic, line);
	} else if (strcmp(line->elemv[0], "PART") == 0) {
		r = irc_cli_part(ic, line);
	} else if (strcmp(line->elemv[0], "NICK") == 0) {
		r = irc_cli_nick(ic, line, NULL);
	} else if (strcmp(line->elemv[0], "QUIT") == 0) {
		r = irc_cli_quit(ic, line);
	} else if (strcmp(line->elemv[0], "PRIVMSG") == 0) {
		r = irc_cli_privmsg(ic, line);
	} else if (strcmp(line->elemv[0], "NOTICE") == 0) {
		r = irc_cli_notice(ic, line);
	} else if (strcmp(line->elemv[0], "WHO") == 0) {
		r = irc_cli_who(ic, line);
	}

	if (r == OK_COPY || r == OK_COPY_CLI) {
		char *str = irc_line_to_string(line);
		if (LINK(ic)->s_state == IRCS_CONNECTED &&
				LINK(ic)->l_server->irc_mask)
			write_line(CONN(LINK(ic)->l_server), str);
		else if (LINK(ic)->l_server->irc_mask)
			WRITE_LINE2(CONN(ic), P_IRCMASK, "PRIVMSG",
					LINK(ic)->l_server->irc_mask,
					":Not connected please try again "
					"later...\r\n");

		free(str);
		if (r == OK_COPY_CLI) {
			int i;
			struct link_server *s = LINK(ic)->l_server;

			for (i = 0; i < LINK(s)->l_clientc; i++)
				irc_copy_cli(ic, LINK(s)->l_clientv[i], line);
		}
	}
	return r;
}

static void irc_copy_cli(struct link_client *src, struct link_client *dest,
		struct line *line)
{
	char *str;
	if (src == dest)
		return;

	if (line->elemc <= 2 || strcmp(line->elemv[0], "PRIVMSG") != 0) {
		str = irc_line_to_string(line);
		write_line(CONN(dest), str);
		free(str);
		return;
	}

	if (ischannel(*line->elemv[1]) || LINK(src) != LINK(dest)) {
		line->origin = LINK(src)->l_server->irc_mask;
		str = irc_line_to_string(line);
		line->origin = NULL;
		write_line(CONN(dest), str);
		free(str);
		return;
	}

	/* LINK(src) == LINK(dest) */
	size_t len = strlen(line->elemv[2]) + 5;
	char *tmp;

	if (len == 0)
		return;

	tmp = malloc(len);

	snprintf(tmp, len, " -> %s", line->elemv[2]);
	tmp[len - 1] = 0;

	line->origin = line->elemv[1];
	/* tricky: */
	line->elemv[1] = LINK(src)->l_server->irc_mask;

	free(line->elemv[2]);
	line->elemv[2] = tmp;
	str = irc_line_to_string(line);
	/* end of trick: */
	line->elemv[1] = line->origin;
	line->origin = NULL;
	write_line(CONN(dest), str);
	free(str);
	return;
}

static int irc_dispatch_loging_client(struct link_client *ic, struct line *line,
		list_t *linkl)
{
	if (line->elemc == 0)
		return ERR_PROTOCOL;

	if (strcmp(line->elemv[0], "NICK") == 0) {
		return irc_cli_nick(ic, line, linkl);
	} else if (strcmp(line->elemv[0], "USER") == 0) {
		return irc_cli_user(ic, line, linkl);
	} else if (strcmp(line->elemv[0], "PASS") == 0) {
		return irc_cli_pass(ic, line, linkl);
	}
	return OK_FORGET;
}

int irc_dispatch(struct link_any *l, struct line *line, list_t *linkl)
{
	switch (TYPE(l)) {
	case IRC_TYPE_SERVER:
		return irc_dispatch_server((struct link_server*)l, line);
		break;
	case IRC_TYPE_CLIENT:
		return irc_dispatch_client((struct link_client*)l, line);
		break;
	case IRC_TYPE_LOGING_CLIENT:
		return irc_dispatch_loging_client((struct link_client*)l,
				line, linkl);
		break;
#ifdef HAVE_LIBSSL		
	case IRC_TYPE_TRUST_CLIENT:
		return irc_dispatch_trust_client((struct link_client*)l, line);
		break;
#endif
	default:
		fatal("gn������");
	}
	return ERR_PROTOCOL; /* never reached */
}

static int origin_is_me(struct line *l, struct link_server *server)
{
	char *nick;

	if (!l->origin)
		return 0;
	nick = nick_from_ircmask(l->origin);
	if (strcmp(nick, server->nick) == 0) {
		free(nick);
		return 1;
	}
	free(nick);
	return 0;
}

static int irc_join(struct link_server *server, struct line *line)
{
	char *s_nick;
	char *s_chan;
	struct channel *channel;
	struct nick *nick;

	if (line->elemc != 2 && line->elemc != 3)
		return ERR_PROTOCOL;

	s_chan = line->elemv[1];
	log_join(LINK(server)->log, line->origin, s_chan);

	channel = hash_get(&server->channels, s_chan);
	if (origin_is_me(line, server)) {
		if (!channel) {
			channel = channel_new(s_chan);
			hash_insert(&server->channels, s_chan, channel);
		}
		return OK_COPY;
	}
	/* if we're not on channel and !origin_is_me, we should not get any
	 * JOIN */
	if (!channel)
		return ERR_PROTOCOL;
	if (!line->origin)
		return ERR_PROTOCOL;
	s_nick = nick_from_ircmask(line->origin);

	nick = calloc(sizeof(struct nick), 1);
	if (!nick)
		fatal("calloc");
	nick->name = s_nick;	/* not freeing s_nick */
	hash_insert(&channel->nicks, s_nick, nick);
	return OK_COPY;
}

static int irc_332(struct link_server *server, struct line *line)
{
	struct channel *channel;
	if (line->elemc != 4)
		return ERR_PROTOCOL;

	channel = hash_get(&server->channels, line->elemv[2]);
	/* we can get topic reply for chans we're not on */
	if (!channel)
		return OK_COPY;

	if (channel->topic)
		free(channel->topic);
	channel->topic = strdup(line->elemv[3]);

	log_init_topic(LINK(server)->log, channel->name, channel->topic);
	return OK_COPY;
}

static int irc_333(struct link_server *server, struct line *line)
{
	struct channel *channel;
	if (line->elemc != 5)
		return ERR_PROTOCOL;

	channel = hash_get(&server->channels, line->elemv[2]);
	/* we can get topic info reply for chans we're not on */
	if (!channel)
		return OK_COPY;
	if (channel->creator)
		free(channel->creator);
	channel->creator = strdup(line->elemv[3]);
	if (channel->create_ts)
		free(channel->create_ts);
	channel->create_ts = strdup(line->elemv[4]);
	log_init_topic_time(LINK(server)->log, channel->name, channel->creator,
			channel->create_ts);
	return OK_COPY;
}

static void nick_free(struct nick *nick)
{
	if (nick->name)
		free(nick->name);
	free(nick);
}

static int irc_353(struct link_server *server, struct line *line)
{
	struct channel *channel;
	struct nick *nick;
	char *names, *eon;
	size_t len;
	char *tmp;

	if (line->elemc != 5)
		return ERR_PROTOCOL;

	channel = hash_get(&server->channels, line->elemv[3]);
	/* we can get names reply for chans we're not on */
	if (!channel)
		return OK_COPY;

	if (!channel->running_names) {
		channel->running_names = 1;
		hash_iterator_t hi;
		for (hash_it_init(&channel->nicks, &hi); hash_it_item(&hi);
				hash_it_next(&hi)) {
			nick_free(hash_it_item(&hi));
		}
		hash_clean(&channel->nicks);
	}

	/* TODO check that type is one of "=" / "*" / "@" */
	channel->type = line->elemv[2][0];

	names = line->elemv[4];

	while (*names) {
		eon = names;
		int ovmask = 0;
		/* these should be exclusive */
		if (*names == '@') {
			names++;
			ovmask |= NICKOP;
		} else if (*names == '+') {
			names++;
			ovmask |= NICKVOICED;
		}
		eon = names;
		while (*eon && *eon != ' ')
			eon++;

		len = eon - names;
		tmp = malloc(len + 1);
		if (!tmp)
			fatal("malloc");
		memcpy(tmp, names, len);
		tmp[len] = 0;

		nick = malloc(sizeof(struct nick));
		if (!nick)
			fatal("malloc");
		nick->name = tmp;
		nick->ovmask = ovmask;

		hash_insert(&channel->nicks, nick->name, nick);
		while (*eon && *eon == ' ')
			eon++;
		names = eon;
	}
	return OK_COPY;
}

static int irc_366(struct link_server *server, struct line *line)
{
	struct channel *channel;

	if (line->elemc != 4)
		return ERR_PROTOCOL;

	channel = hash_get(&server->channels, line->elemv[2]);
	if (channel && channel->running_names)
		channel->running_names = 0;
	return OK_COPY;
}

static void channel_free(struct channel *c)
{
	if (c->name)
		free(c->name);
	if (c->mode)
		free(c->mode);
	if (c->key)
		free(c->key);
	if (c->topic)
		free(c->topic);
	if (c->creator)
		free(c->creator);
	if (c->create_ts)
		free(c->create_ts);

/*
	char *l;
	while ((l = (char *)list_remove_first(&c->bans)))
		free(l);
*/
	hash_iterator_t hi;
	for (hash_it_init(&c->nicks, &hi); hash_it_item(&hi); hash_it_next(&hi))
		nick_free(hash_it_item(&hi));
	hash_clean(&c->nicks);
	free(c);
}

static int irc_part(struct link_server *server, struct line *line)
{
	char *s_nick;
	char *s_chan;
	struct channel *channel;
	struct nick *nick;

	if (line->elemc != 2 && line->elemc != 3)
		return ERR_PROTOCOL;

	s_chan = line->elemv[1];

	channel = hash_get(&server->channels, s_chan);
	/* we can't get part message for chans we're not on */
	if (!channel)
		return ERR_PROTOCOL;

	if (origin_is_me(line, server)) {
		log_part(LINK(server)->log, line->origin, s_chan,
				line->elemc == 3 ? line->elemv[2] : NULL);

		hash_remove(&server->channels, s_chan);
		channel_free(channel);
		return OK_COPY;
	}

	if (!line->origin)
		return ERR_PROTOCOL;
	s_nick = nick_from_ircmask(line->origin);
	nick = hash_get(&channel->nicks, s_nick);
	if (!nick) {
		free(s_nick);
		return ERR_PROTOCOL;
	}
	nick = hash_remove(&channel->nicks, s_nick);
	free(s_nick);

	log_part(LINK(server)->log, line->origin, s_chan,
			line->elemc == 3 ? line->elemv[2]:NULL);

	nick_free(nick);
	return OK_COPY;
}

static void mode_add_letter_uniq(struct link_server *s, char c)
{
	int i;
	for (i = 0; i < s->user_mode_len; i++) {
		if (s->user_mode[i] == c)
			return;
	}
	s->user_mode = realloc(s->user_mode, s->user_mode_len + 1);
	s->user_mode[s->user_mode_len++] = c;
}

static void mode_remove_letter(struct link_server *s, char c)
{
	int i;
	for (i = 0; i < s->user_mode_len; i++) {
		if (s->user_mode[i] == c) {
			for (; i < s->user_mode_len - 1; i++)
				s->user_mode[i] = s->user_mode[i + 1];
			s->user_mode_len--;
			s->user_mode = realloc(s->user_mode, s->user_mode_len);
			return;
		}
	}
}

static void irc_user_mode(struct link_server *server, struct line *line)
{
	char *mode;
	int add = 1;
	for (mode = line->elemv[2]; *mode; mode++) {
		if (*mode == '-')
			add = 0;
		else if (*mode == '+')
			add = 1;
		else {
			if (add) {
				mode_add_letter_uniq(server, *mode);
			} else {
				mode_remove_letter(server, *mode);
			}
		}
	}
}

static int irc_mode(struct link_server *server, struct line *line)
{
	struct channel *channel;
	char *mode;
	int add = 1;
	unsigned cur_arg = 0;
	struct nick *nick;

	if (line->elemc < 3)
		return ERR_PROTOCOL;

	/* nick mode change */
	if (strcmp(line->elemv[1], server->nick) == 0) {
		log_mode(LINK(server)->log, line->origin, line->elemv[1],
				line->elemv[2], line->elemv + 3,
				line->elemc - 3);
		irc_user_mode(server, line);
		return OK_COPY;
	}

	if (!ischannel(line->elemv[1][0]))
		return ERR_PROTOCOL;

	/* channel mode change */
	channel = hash_get(&server->channels, line->elemv[1]);
	/* we can't get mode message for chans we're not on */
	if (!channel)
		return ERR_PROTOCOL;
	log_mode(LINK(server)->log, line->origin, line->elemv[1],
			line->elemv[2], line->elemv + 3, line->elemc - 3);

	/*       
	 * MODE -a+b.. #channel args
	 *         ^            ^
	 *       mode         cur_arg
	 */
	for (mode = line->elemv[2]; *mode; mode++) {
		switch (*mode) {
		case '-':
			add = 0;
			break;
		case '+':
			add = 1;
			break;
		case 'b':
			if (cur_arg + 3 >= line->elemc)
				return ERR_PROTOCOL;
			cur_arg++;
			break;
		case 'o':

			if (cur_arg + 3 >= line->elemc)
				return ERR_PROTOCOL;

			nick = hash_get(&channel->nicks,
					line->elemv[cur_arg + 3]);
			if (!nick)
				return ERR_PROTOCOL;
			if (add)
				nick->ovmask |= NICKOP;
			else
				nick->ovmask &= ~NICKOP;
			cur_arg++;
			break;
		case 'v':
			if (cur_arg + 3 >= line->elemc)
				return ERR_PROTOCOL;

			nick = hash_get(&channel->nicks,
					line->elemv[cur_arg + 3]);
			if (!nick)
				return ERR_PROTOCOL;
			if (add)
				nick->ovmask |= NICKVOICED;
			else
				nick->ovmask &= ~NICKVOICED;
			cur_arg++;
			break;
		case 'k':
			if (add) {
				if (cur_arg + 3 >= line->elemc)
					return ERR_PROTOCOL;

				channel->key = strdup(line->elemv[cur_arg + 3]);
				cur_arg++;
			} else {
				if (channel->key) {
					free(channel->key);
					channel->key = NULL;
				}
			}
			break;
		case 'l':
			if (add)
				cur_arg++;
			break;
		case 'h':
		case 'H':
		case 'e':
			if (cur_arg + 3 >= line->elemc)
				return ERR_PROTOCOL;
			cur_arg++;
			break;
		default:
			break;
		}
	}
	return OK_COPY;
}

static char *irc_timestamp(void)
{
	char *ts = malloc(21);
	snprintf(ts, 20, "%ld", (long int)time(NULL));
	return ts;
}

static int irc_topic(struct link_server *server, struct line *line)
{
	struct channel *channel;
	char *topic;

	if (line->elemc != 3)
		return ERR_PROTOCOL;

	channel = hash_get(&server->channels, line->elemv[1]);
	/* we can't get topic message for chans we're not on */
	if (!channel)
		return ERR_PROTOCOL;
	
	if (channel->topic)
		free(channel->topic);
	topic = line->elemv[2];
	if (*topic == ':')
		topic++;
	channel->topic = strdup(topic);

	/*
	 * :arion.oftc.net 333 bip`luser #bipqSDFQE3
	 * nohar!~nohar@borne28.noc.nerim.net 1107338095
	 */

	if (channel->creator)
		free(channel->creator);
	channel->creator = strmaydup(line->origin);
	if (channel->create_ts)
		free(channel->create_ts);
	channel->create_ts = irc_timestamp();

	log_topic(LINK(server)->log, line->origin, line->elemv[1], topic);
	return OK_COPY;
}

static int irc_kick(struct link_server *server, struct line *line)
{
	struct channel *channel;
	struct nick *nick;

	if (line->elemc != 3 && line->elemc != 4)
		return ERR_PROTOCOL;

	channel = hash_get(&server->channels, line->elemv[1]);
	/* we can't get kick message for chans we're not on */
	if (!channel)
		return ERR_PROTOCOL;

	nick = hash_get(&channel->nicks, line->elemv[2]);
	if (!nick)
		return ERR_PROTOCOL;

	if (strcmp(nick->name, server->nick) == 0) {
		log_kick(LINK(server)->log, line->origin, channel->name,
				nick->name,
				line->elemc == 4 ? line->elemv[3] : NULL);

		hash_remove(&server->channels, channel->name);
		channel_free(channel);
		return OK_COPY;
	}

	hash_remove(&channel->nicks, nick->name);
	nick_free(nick);
	log_kick(LINK(server)->log, line->origin, line->elemv[1],
			line->elemv[2],
			line->elemc == 4 ? line->elemv[3] : NULL);
	return OK_COPY;
}

static int irc_privmsg(struct link_server *server, struct line *line)
{
	if (LINK(server)->s_state == IRCS_CONNECTED)
		log_privmsg(LINK(server)->log, line->origin, line->elemv[1],
				line->elemv[2]);
	return OK_COPY;
}

static int irc_notice(struct link_server *server, struct line *line)
{
	if (LINK(server)->s_state == IRCS_CONNECTED)
		log_notice(LINK(server)->log, line->origin, line->elemv[1],
				line->elemv[2]);
	return OK_COPY;
}

static int irc_quit(struct link_server *server, struct line *line)
{
	return irc_generic_quit(server, line);
}

static int irc_nick(struct link_server *server, struct line *line)
{
	struct channel *channel;
	struct nick *nick;
	hash_iterator_t hi;
	char *s_nick;

	if (line->elemc != 2)
		return ERR_PROTOCOL;

	if (!line->origin)
		return ERR_PROTOCOL;

	s_nick = nick_from_ircmask(line->origin);

	if (strcmp(s_nick, server->nick) == 0) {
		char *nim;
		free(server->nick);
		server->nick = strdup(line->elemv[1]);

		/* How the hell do we handle that crap cleanly ? */
		nim = make_irc_mask(line->elemv[1], server->irc_mask);
		if (nim) {
			free(server->irc_mask);
			server->irc_mask = nim;
		}
		if (LINK(server)->follow_nick &&
				(LINK(server)->away_nick == NULL ||
				strcmp(server->nick, LINK(server)->away_nick))
				!= 0) {
			free(LINK(server)->connect_nick);
			LINK(server)->connect_nick = strdup(server->nick);
		}
	}

	for (hash_it_init(&server->channels, &hi); hash_it_item(&hi);
			hash_it_next(&hi)) {
		channel = hash_it_item(&hi);
		nick = hash_get(&channel->nicks, s_nick);
		if (!nick)
			continue;
		hash_remove(&channel->nicks, s_nick);
		free(nick->name);
		nick->name = strdup(line->elemv[1]);
		hash_insert(&channel->nicks, nick->name, nick);
		log_nick(LINK(server)->log, s_nick, channel->name,
				line->elemv[1]);
	}

	free(s_nick);
	return OK_COPY;
}

static int irc_generic_quit(struct link_server *server, struct line *line)
{
	struct channel *channel;
	struct nick *nick;
	hash_iterator_t hi;
	char *s_nick;

	if (line->elemc != 2 && line->elemc != 1)
		return ERR_PROTOCOL;

	if (!line->origin)
		return ERR_PROTOCOL;
	s_nick = nick_from_ircmask(line->origin);

	for (hash_it_init(&server->channels, &hi); hash_it_item(&hi);
			hash_it_next(&hi)) {
		channel = hash_it_item(&hi);
		nick = hash_get(&channel->nicks, s_nick);
		if (!nick)
			continue;
		hash_remove(&channel->nicks, s_nick);
		nick_free(nick);

		log_quit(LINK(server)->log, line->origin, channel->name,
				line->elemc == 2 ?  line->elemv[1] : NULL);
	}
	free(s_nick);
	return OK_COPY;
}

static void irc_server_startup(struct link_server *ircs)
{
	char *nick;

	if (LINK(ircs)->s_password)
		WRITE_LINE1(CONN(ircs), NULL, "PASS", LINK(ircs)->s_password);

	WRITE_LINE4(CONN(ircs), NULL, "USER", LINK(ircs)->user, "0", "*",
			LINK(ircs)->real_name);

	nick = ircs->nick;
	if (LINK(ircs)->away_nick && LINK(ircs)->l_clientc == 0) {
		if (nick)
			free(nick);
		nick = strdup(LINK(ircs)->away_nick);
	}
	if ((!LINK(ircs)->follow_nick && !LINK(ircs)->away_nick)
			|| nick == NULL) {
		if (nick)
			free(nick);
		nick = strdup(LINK(ircs)->connect_nick);
	}

	ircs->nick = nick;
	WRITE_LINE1(CONN(ircs), NULL, "NICK", ircs->nick);
}

static void server_next(struct link *l)
{
	l->cur_server++;
	if (l->cur_server >= l->serverc)
		l->cur_server -= l->serverc;
}

static struct link_client *irc_accept_new(connection_t *conn)
{
	struct link_client *ircc;
	connection_t *newconn;

	newconn = accept_new(conn);
	if (!newconn)
		return NULL;

	ircc = calloc(sizeof(struct link_client), 1);
	CONN(ircc) = newconn;
	TYPE(ircc) = IRC_TYPE_LOGING_CLIENT;
	CONN(ircc)->user_data = ircc;
	return ircc;
}

void server_cleanup(struct link_server *server)
{
	if (server->nick) {
		free(server->nick);
		server->nick = NULL;
	}
	if (server->irc_mask) {
		free(server->irc_mask);
		server->irc_mask = NULL;
	}
	if (LINK(server)->s_state == IRCS_CONNECTED) {
		LINK(server)->s_state = IRCS_WAS_CONNECTED;
	} else {
		struct line *s;
		LINK(server)->s_state = IRCS_NONE;
		while ((s = list_remove_first(&LINK(server)->init_strings)))
			irc_line_free(s);
	}

	hash_iterator_t hi;
	for (hash_it_init(&server->channels, &hi); hash_it_item(&hi);
			hash_it_next(&hi))
		channel_free(hash_it_item(&hi));
	hash_init(&server->channels, HASH_NOCASE);

	if (CONN(server)) {
		connection_free(CONN(server));
		CONN(server) = NULL;
	}
	irc_lag_init(server);

}

void irc_client_close(struct link_client *ic)
{
	if (TYPE(ic) == IRC_TYPE_CLIENT) {
		struct link_server *is = LINK(ic)->l_server;
		log_client_disconnected(LINK(ic)->log);
		unbind_from_link(ic);
		if (LINK(ic)->l_clientc == 0) {
			if (is && LINK(ic)->away_nick)
				WRITE_LINE1(CONN(is), NULL, "NICK",
						LINK(ic)->away_nick);
			if (is && LINK(ic)->no_client_away_msg)
				WRITE_LINE1(CONN(is), NULL, "AWAY",
						LINK(ic)->no_client_away_msg);
			log_client_none_connected(LINK(ic)->log);
		}
		irc_client_free(ic);
	} else if (TYPE(ic) == IRC_TYPE_LOGING_CLIENT) {
		irc_client_free(ic);
	}
}

static void irc_close(struct link_any *l)
{
	if (CONN(l)) {
		connection_free(CONN(l));
		CONN(l) = NULL;
	}
	if (TYPE(l) == IRC_TYPE_SERVER) {
		/* TODO: free link_server as a whole */
		int timer = 0;
		struct link_server *is = (struct link_server *)l;

		if (LINK(is)->s_state == IRCS_CONNECTED)
			irc_notify_disconnection(is);
		irc_server_shutdown(is);
		log_disconnected(LINK(is)->log);

		server_next(LINK(is));
		server_cleanup(is);
		if (LINK(is)->last_connection &&
				time(NULL) - LINK(is)->last_connection
					< CONN_INTERVAL)
			timer = RECONN_TIMER;
		mylog(LOG_ERROR, "%s dead, reconnecting in %d seconds",
				LINK(l)->name, timer);
		LINK(is)->recon_timer = timer;

		irc_server_free((struct link_server *)is);
		LINK(is)->l_server = NULL;
	} else {
		irc_client_close((struct link_client *)l);
	}
}

struct link_client *irc_client_new(void)
{
	struct link_client *c;

	c = calloc(sizeof(struct link_client), 1);
	list_init(&c->who_queue, list_ptr_cmp);

	return c;
}

struct link_server *irc_server_new(struct link *link, connection_t *conn)
{
	struct link_server *s;

	s = calloc(sizeof(struct link_server), 1);
	if (!s)
		fatal("calloc");

	TYPE(s) = IRC_TYPE_SERVER;
	hash_init(&s->channels, HASH_NOCASE);

	link->l_server = s;
	LINK(s) = link;
	CONN(s) = conn;

	irc_lag_init(s);
	return s;
}

void irc_server_free(struct link_server *s)
{
	if (s->nick)
		free(s->nick);
	if (s->irc_mask)
		free(s->irc_mask);
	if (s->user_mode)
		free(s->user_mode);
	free(s);
}

connection_t *irc_server_connect(struct link *link)
{
	struct link_server *ls;
	connection_t *conn;

	mylog(LOG_INFO, "Connecting user '%s' to network '%s' using server "
		"%s:%d", link->username, link->name,
		link->serverv[link->cur_server]->host,
		link->serverv[link->cur_server]->port);
	conn = connection_new(link->serverv[link->cur_server]->host,
				link->serverv[link->cur_server]->port,
				link->vhost, link->bind_port,
#ifdef HAVE_LIBSSL
				link->s_ssl, link->ssl_check_mode,
				link->ssl_check_store,
#else
				0, 0, NULL,
#endif
				CONNECT_TIMEOUT);
	if (!conn)
		fatal("connection_new");

	ls = irc_server_new(link, conn);

	conn->user_data = ls;
	irc_server_startup(ls);
	return conn;
}

int irc_server_lag_compute(struct link *l)
{
	struct link_server *server = l->l_server;

	if (LINK(server)->s_state == IRCS_CONNECTED) {
		if (server->laginit_ts != -1) {
			irc_compute_lag(server);
			if (!irc_lags_out(server))
				return 0;
			return 1;
		} else {
			server->lagtest_timeout--;
			if (server->lagtest_timeout == 0)
				irc_start_lagtest(server);
		}
	}
	return 0;
}

void irc_server_shutdown(struct link_server *s)
{
	if (!s->nick)
		return;
	if (LINK(s)->prev_nick)
		free(LINK(s)->prev_nick);
	LINK(s)->prev_nick = strdup(s->nick);

	if (LINK(s)->prev_ircmask) {
		free(LINK(s)->prev_ircmask);
		LINK(s)->prev_ircmask = NULL;
	}
	if (s->irc_mask)
		LINK(s)->prev_ircmask = strdup(s->irc_mask);
}


#ifdef HAVE_OIDENTD
/* ugly */
void oidentd_dump(list_t *connl)
{
	list_iterator_t it;
	FILE *f;
	char *home;
	char tmpbuf[256];
	int err;

	home = getenv("HOME");
	if (!home)
		return;
	strcpy(tmpbuf, home);
	strcat(tmpbuf, "/.oidentd.conf");
	f = fopen(tmpbuf, "w");
	if (!f)
		return;

	for (list_it_init(connl, &it); list_it_item(&it); list_it_next(&it)) {
		connection_t *c = list_it_item(&it);
		struct link_any *la = c->user_data;
		if (c->connected == CONN_OK && la &&
				TYPE(la) == IRC_TYPE_SERVER) {
			struct link_server *ls = (struct link_server*)la;
			struct link *l = LINK(ls);

			char *localip, *remoteip;
			int localport, remoteport;

			localip = connection_localip(CONN(ls));
			localport = connection_localport(CONN(ls));
			remoteip = connection_remoteip(CONN(ls));
			remoteport = connection_remoteport(CONN(ls));

			fprintf(f, "to %s fport %d from %s lport %d {\n",
					remoteip, remoteport, localip,
					localport);
			fprintf(f, "\treply \"%s\"\n", l->user);
			fprintf(f, "}\n");
			free(localip);
			free(remoteip);
		}
	}
	fflush(f);
	fclose(f);
	err = chmod(tmpbuf, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (err) {
		mylog(LOG_WARN, "Unable to set modes for '%s': %s", tmpbuf,
				strerror(errno));
	}
}
#endif

/* do not use */
list_t *_connections = NULL;

struct link_client *reloading_client;
/*
 * The main loop
 * inc is the incoming connection, clientl list a list of client struct that
 * represent the accepcted credentials
 */
void irc_main(connection_t *inc, list_t *ll)
{
	list_t reconnectl;
	list_t timerwaitl;
	list_t connl;
	list_t connecting_c;
	list_t connected_c;
	int timeleft = 1000;
	int logflush_timer = conf_log_sync_interval;

	list_init(&reconnectl, NULL);
	list_init(&timerwaitl, NULL);
	list_init(&connl, list_ptr_cmp);
	list_init(&connecting_c, list_ptr_cmp);
	list_init(&connected_c, list_ptr_cmp);

	_connections = &connl;

	/* XXX: This one MUST be first */
	list_add_first(&connl, inc);

	/*
	 * Merge with already connected data, happens on SIGHUP
	 */
	list_iterator_t it;
	for (list_it_init(ll, &it); list_it_item(&it); list_it_next(&it)) {
		struct link *link = list_it_item(&it);
		if (link->l_server)
			list_add_last(&connl, CONN(link->l_server));
		else
			list_add_last(&reconnectl, link);
		if (link->l_clientc) {
			int i;
			for (i = 0; i < link->l_clientc; i++) {
				struct link_client *c;
				c = link->l_clientv[i];
				list_add_last(&connl, CONN(c));
				if (TYPE(c) == IRC_TYPE_LOGING_CLIENT)
					list_add_last(&connecting_c, c);
				if (TYPE(c) == IRC_TYPE_CLIENT)
					list_add_last(&connected_c, c);
			}
		}
	}
	if (conf_error && reloading_client) {
		char *nick;
		if (LINK(reloading_client)->l_server)
			nick = LINK(reloading_client)->l_server->nick;
		else
			nick = LINK(reloading_client)->prev_nick;
		WRITE_LINE2(CONN(reloading_client), P_IRCMASK, "PRIVMSG", nick,
				conf_errstr);
		reloading_client = NULL;
	}


	while (!sighup) {
		struct link *link;
		connection_t *conn;

		/* Compute timeouts for next reconnections and lagouts */
		if (timeleft == 0) {
			static int throttle_prot = S_CONN_DELAY - 1;

			timeleft = 1000;

			if (++throttle_prot == S_CONN_DELAY) {
				throttle_prot = 0;

				/* Lauch one reconnection at a time */
				if ((link = list_remove_first(&reconnectl))) {
					conn = irc_server_connect(link);
					list_add_last(&connl, conn);
					link->last_connection = time(NULL);
				}
			}

			/* log flushs */
			if (logflush_timer-- <= 0) {
				logflush_timer = conf_log_sync_interval;
				log_flush_all();
			}

			/* reconnects */
			list_iterator_t li;
			for (list_it_init(&timerwaitl, &li); list_it_item(&li);
					list_it_next(&li)) {
				struct link *l = list_it_item(&li);
				if (l->recon_timer <= 0) {
					list_it_remove(&li);
					list_add_last(&reconnectl, l);
				} else {
					l->recon_timer--;
				}
			}

			/* server lags */
			for (list_it_init(ll, &li); list_it_item(&li);
					list_it_next(&li)) {
				struct link *l = list_it_item(&li);
				if(l->l_server && irc_server_lag_compute(l)) {
					log_ping_timeout(l->log);
					list_remove(&connl, CONN(l->l_server));
					irc_close((struct link_any *)
							l->l_server);
					list_add_last(&timerwaitl, l);
				}
			}

			/* drop lagging connecting client */
			for (list_it_init(&connecting_c, &li);
					list_it_item(&li); list_it_next(&li)) {
				struct link_client *ic = list_it_item(&li);
				ic->logging_timer++;
				if (ic->logging_timer > LOGGING_TIMEOUT) {
					list_remove(&connl, CONN(ic));
					irc_close((struct link_any *)ic);
					list_it_remove(&li);
				}
			}
		}

		int nc;
		/* Da main loop */
		list_t *ready = wait_event(&connl, &timeleft, &nc);
#ifdef HAVE_OIDENTD
		if (nc)
			oidentd_dump(&connl);
#endif
		while ((conn = list_remove_first(ready))) {
			struct link_any *lc =
				(struct link_any *)conn->user_data;

			if (conn == inc) {
				struct link_client *n = irc_accept_new(conn);
				if (!n)
					fatal("Problem while binding local"
							" socket");
				list_add_last(&connl, CONN(n));
				list_add_last(&connecting_c, n);
				continue;
			}

			/* reached only if socket is not listening */
			int err;
			list_t *linel = read_lines(conn, &err);
			if (err) {
				if (TYPE(lc) == IRC_TYPE_SERVER) {
					mylog(LOG_ERROR, "read_lines error, "
						"closing %s ...",
						LINK(lc)->name);
					irc_server_shutdown(LINK(lc)->l_server);
				} else {
					mylog(LOG_ERROR, "read_lines error, "
						"closing...");
				}
				goto prot_err;
			}
			if (!linel)
				continue;

			char *line_s;
			while ((line_s = list_remove_first(linel))) {
				struct line *line;
				mylog(LOG_DEBUG, "\"%s\"", line_s);
				if (*line_s == 0) { /* irssi does that.*/
					free(line_s);
					continue;
				}

				line = irc_line(line_s);
				if (!line) {
					mylog(LOG_ERROR, "Error in protocol, "
							"closing...");
					free(line_s);
					goto prot_err_lines;
				}
				int r;
				int oldtype = TYPE(lc);
				r = irc_dispatch((struct link_any*)
						conn->user_data, line, ll);
				irc_line_free(line);
				free(line_s);
				if (r == ERR_PROTOCOL) {
					mylog(LOG_ERROR, "Error in protocol, "
							"closing...");
					goto prot_err_lines;
				}
				if (r == ERR_AUTH)
					goto prot_err_lines;
				/* XXX: not real error */
				if (r == OK_CLOSE)
					goto prot_err_lines;

				if (oldtype == IRC_TYPE_LOGING_CLIENT &&
						TYPE(lc) == IRC_TYPE_CLIENT) {
					list_remove(&connecting_c, lc);
					list_add_last(&connected_c, lc);
				}
			}
			list_free(linel);
			continue;
prot_err_lines:
			while ((line_s = list_remove_first(linel)))
				free(line_s);
prot_err:
			list_remove(&connl, conn);
			if (linel)
				list_free(linel);
			if (lc) {
				if (TYPE(lc) == IRC_TYPE_CLIENT)
					list_remove(&connected_c, lc);
				if (TYPE(lc) == IRC_TYPE_LOGING_CLIENT)
					list_remove(&connecting_c, lc);
				if (TYPE(lc) == IRC_TYPE_SERVER)
					list_add_last(&timerwaitl, LINK(lc));
				irc_close(lc);
			}
		}
		list_free(ready);
	}
	while (list_remove_first(&connecting_c))
		;
	while (list_remove_first(&connected_c))
		;
	while (list_remove_first(&connl))
		;
	while (list_remove_first(&timerwaitl))
		;
	while (list_remove_first(&reconnectl))
		;
	_connections = NULL;
	return;
}

void irc_client_free(struct link_client *cli)
{
	if (CONN(cli))
		connection_free(CONN(cli));
	if (cli->init_pass)
		free(cli->init_pass);
	if (cli->init_nick)
		free(cli->init_nick);
	free(cli);
}

/*
void irc_server_free(struct link_server *is)
{
	free(is);
}
*/
struct link *irc_link_new()
{
	struct link *link;
	link = calloc(sizeof(struct link), 1);
	if (!link)
		fatal("calloc");

	hash_init(&link->chan_infos, HASH_NOCASE);
	list_init(&link->chan_infos_order, list_ptr_cmp);
	list_init(&link->on_connect_send, list_ptr_cmp);
	return link;
}

