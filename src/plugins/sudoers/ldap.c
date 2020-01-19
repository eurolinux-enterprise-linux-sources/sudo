/*
 * Copyright (c) 2003-2018 Todd C. Miller <Todd.Miller@sudo.ws>
 *
 * This code is derived from software contributed by Aaron Spangler.
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
 */

#include <config.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#ifdef HAVE_LBER_H
# include <lber.h>
#endif
#include <ldap.h>
#if defined(HAVE_LDAP_SSL_H)
# include <ldap_ssl.h>
#elif defined(HAVE_MPS_LDAP_SSL_H)
# include <mps/ldap_ssl.h>
#endif
#ifdef HAVE_LDAP_SASL_INTERACTIVE_BIND_S
# ifdef HAVE_SASL_SASL_H
#  include <sasl/sasl.h>
# else
#  include <sasl.h>
# endif
#endif /* HAVE_LDAP_SASL_INTERACTIVE_BIND_S */

#include "sudoers.h"
#include "parse.h"
#include "gram.h"
#include "sudo_lbuf.h"
#include "sudo_ldap.h"
#include "sudo_ldap_conf.h"
#include "sudo_dso.h"

#if defined(HAVE_LDAP_SASL_INTERACTIVE_BIND_S) && !defined(LDAP_SASL_QUIET)
# define LDAP_SASL_QUIET	0
#endif

#ifndef HAVE_LDAP_UNBIND_EXT_S
#define ldap_unbind_ext_s(a, b, c)	ldap_unbind_s(a)
#endif

#ifndef HAVE_LDAP_SEARCH_EXT_S
# ifdef HAVE_LDAP_SEARCH_ST
#  define ldap_search_ext_s(a, b, c, d, e, f, g, h, i, j, k)		\
	ldap_search_st(a, b, c, d, e, f, i, k)
# else
#  define ldap_search_ext_s(a, b, c, d, e, f, g, h, i, j, k)		\
	ldap_search_s(a, b, c, d, e, f, k)
# endif
#endif

#define LDAP_FOREACH(var, ld, res)					\
    for ((var) = ldap_first_entry((ld), (res));				\
	(var) != NULL;							\
	(var) = ldap_next_entry((ld), (var)))

/* The TIMEFILTER_LENGTH is the length of the filter when timed entries
   are used. The length is computed as follows:
       81       for the filter itself
       + 2 * 17 for the now timestamp
*/
#define TIMEFILTER_LENGTH	115

/*
 * The ldap_search structure implements a linked list of ldap and
 * search result pointers, which allows us to remove them after
 * all search results have been combined in memory.
 */
struct ldap_search_result {
    STAILQ_ENTRY(ldap_search_result) entries;
    LDAP *ldap;
    LDAPMessage *searchresult;
};
STAILQ_HEAD(ldap_search_list, ldap_search_result);

/*
 * The ldap_entry_wrapper structure is used to implement sorted result entries.
 * A double is used for the order to allow for insertion of new entries
 * without having to renumber everything.
 * Note: there is no standard floating point type in LDAP.
 *       As a result, some LDAP servers will only allow an integer.
 */
struct ldap_entry_wrapper {
    LDAPMessage	*entry;
    double order;
};

/*
 * The ldap_result structure contains the list of matching searches as
 * well as an array of all result entries sorted by the sudoOrder attribute.
 */
struct ldap_result {
    struct ldap_search_list searches;
    struct ldap_entry_wrapper *entries;
    unsigned int allocated_entries;
    unsigned int nentries;
    bool user_matches;
    bool host_matches;
};
#define	ALLOCATION_INCREMENT	100

/*
 * The ldap_netgroup structure implements a singly-linked tail queue of
 * netgroups a user is a member of when querying netgroups directly.
 */
struct ldap_netgroup {
    STAILQ_ENTRY(ldap_netgroup) entries;
    char *name;
};
STAILQ_HEAD(ldap_netgroup_list, ldap_netgroup);

/* sudo_nss implementation */
static int sudo_ldap_open(struct sudo_nss *nss);
static int sudo_ldap_close(struct sudo_nss *nss);
static int sudo_ldap_parse(struct sudo_nss *nss);
static int sudo_ldap_setdefs(struct sudo_nss *nss);
static int sudo_ldap_lookup(struct sudo_nss *nss, int ret, int pwflag);
static int sudo_ldap_display_cmnd(struct sudo_nss *nss, struct passwd *pw);
static int sudo_ldap_display_defaults(struct sudo_nss *nss, struct passwd *pw,
    struct sudo_lbuf *lbuf);
static int sudo_ldap_display_bound_defaults(struct sudo_nss *nss,
    struct passwd *pw, struct sudo_lbuf *lbuf);
static int sudo_ldap_display_privs(struct sudo_nss *nss, struct passwd *pw,
    struct sudo_lbuf *lbuf);
static struct ldap_result *sudo_ldap_result_get(struct sudo_nss *nss,
    struct passwd *pw);
static char *sudo_ldap_get_first_rdn(LDAP *ld, LDAPMessage *entry);

/*
 * LDAP sudo_nss handle.
 * We store the connection to the LDAP server, the cached ldap_result object
 * (if any), and the name of the user the query was performed for.
 * If a new query is launched with sudo_ldap_result_get() that specifies a
 * different user, the old cached result is freed before the new query is run.
 */
struct sudo_ldap_handle {
    LDAP *ld;
    struct ldap_result *result;
    const char *username;
    struct gid_list *gidlist;
};

struct sudo_nss sudo_nss_ldap = {
    { NULL, NULL },
    sudo_ldap_open,
    sudo_ldap_close,
    sudo_ldap_parse,
    sudo_ldap_setdefs,
    sudo_ldap_lookup,
    sudo_ldap_display_cmnd,
    sudo_ldap_display_defaults,
    sudo_ldap_display_bound_defaults,
    sudo_ldap_display_privs
};

#ifdef HAVE_LDAP_INITIALIZE
static char *
sudo_ldap_join_uri(struct ldap_config_str_list *uri_list)
{
    struct ldap_config_str *uri;
    size_t len = 0;
    char *buf = NULL;
    debug_decl(sudo_ldap_join_uri, SUDOERS_DEBUG_LDAP)

    STAILQ_FOREACH(uri, uri_list, entries) {
	if (ldap_conf.ssl_mode == SUDO_LDAP_STARTTLS) {
	    if (strncasecmp(uri->val, "ldaps://", 8) == 0) {
		sudo_warnx(U_("starttls not supported when using ldaps"));
		ldap_conf.ssl_mode = SUDO_LDAP_SSL;
	    }
	}
	len += strlen(uri->val) + 1;
    }
    if (len == 0 || (buf = malloc(len)) == NULL) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    } else {
	char *cp = buf;

	STAILQ_FOREACH(uri, uri_list, entries) {
	    cp += strlcpy(cp, uri->val, len - (cp - buf));
	    *cp++ = ' ';
	}
	cp[-1] = '\0';
    }
    debug_return_str(buf);
}
#endif /* HAVE_LDAP_INITIALIZE */

/*
 * Wrapper for ldap_create() or ldap_init() that handles
 * SSL/TLS initialization as well.
 * Returns LDAP_SUCCESS on success, else non-zero.
 */
static int
sudo_ldap_init(LDAP **ldp, const char *host, int port)
{
    LDAP *ld;
    int ret = LDAP_CONNECT_ERROR;
    debug_decl(sudo_ldap_init, SUDOERS_DEBUG_LDAP)

#ifdef HAVE_LDAPSSL_INIT
    if (ldap_conf.ssl_mode != SUDO_LDAP_CLEAR) {
	const int defsecure = ldap_conf.ssl_mode == SUDO_LDAP_SSL;
	DPRINTF2("ldapssl_clientauth_init(%s, %s)",
	    ldap_conf.tls_certfile ? ldap_conf.tls_certfile : "NULL",
	    ldap_conf.tls_keyfile ? ldap_conf.tls_keyfile : "NULL");
	ret = ldapssl_clientauth_init(ldap_conf.tls_certfile, NULL,
	    ldap_conf.tls_keyfile != NULL, ldap_conf.tls_keyfile, NULL);
	/*
	 * Starting with version 5.0, Mozilla-derived LDAP SDKs require
	 * the cert and key paths to be a directory, not a file.
	 * If the user specified a file and it fails, try the parent dir.
	 */
	if (ret != LDAP_SUCCESS) {
	    bool retry = false;
	    if (ldap_conf.tls_certfile != NULL) {
		char *cp = strrchr(ldap_conf.tls_certfile, '/');
		if (cp != NULL && strncmp(cp + 1, "cert", 4) == 0) {
		    *cp = '\0';
		    retry = true;
		}
	    }
	    if (ldap_conf.tls_keyfile != NULL) {
		char *cp = strrchr(ldap_conf.tls_keyfile, '/');
		if (cp != NULL && strncmp(cp + 1, "key", 3) == 0) {
		    *cp = '\0';
		    retry = true;
		}
	    }
	    if (retry) {
		DPRINTF2("retry ldapssl_clientauth_init(%s, %s)",
		    ldap_conf.tls_certfile ? ldap_conf.tls_certfile : "NULL",
		    ldap_conf.tls_keyfile ? ldap_conf.tls_keyfile : "NULL");
		ret = ldapssl_clientauth_init(ldap_conf.tls_certfile, NULL,
		    ldap_conf.tls_keyfile != NULL, ldap_conf.tls_keyfile, NULL);
	    }
	}
	if (ret != LDAP_SUCCESS) {
	    sudo_warnx(U_("unable to initialize SSL cert and key db: %s"),
		ldapssl_err2string(ret));
	    if (ldap_conf.tls_certfile == NULL)
		sudo_warnx(U_("you must set TLS_CERT in %s to use SSL"),
		    path_ldap_conf);
	    goto done;
	}

	DPRINTF2("ldapssl_init(%s, %d, %d)", host, port, defsecure);
	if ((ld = ldapssl_init(host, port, defsecure)) != NULL)
	    ret = LDAP_SUCCESS;
    } else
#elif defined(HAVE_LDAP_SSL_INIT) && defined(HAVE_LDAP_SSL_CLIENT_INIT)
    if (ldap_conf.ssl_mode == SUDO_LDAP_SSL) {
	int sslrc;
	ret = ldap_ssl_client_init(ldap_conf.tls_keyfile, ldap_conf.tls_keypw,
	    0, &sslrc);
	if (ret != LDAP_SUCCESS) {
	    sudo_warnx("ldap_ssl_client_init(): %s (SSL reason code %d)",
		ldap_err2string(ret), sslrc);
	    goto done;
	}
	DPRINTF2("ldap_ssl_init(%s, %d, NULL)", host, port);
	if ((ld = ldap_ssl_init((char *)host, port, NULL)) != NULL)
	    ret = LDAP_SUCCESS;
    } else
#endif
    {
#ifdef HAVE_LDAP_CREATE
	DPRINTF2("ldap_create()");
	if ((ret = ldap_create(&ld)) != LDAP_SUCCESS)
	    goto done;
	DPRINTF2("ldap_set_option(LDAP_OPT_HOST_NAME, %s)", host);
	ret = ldap_set_option(ld, LDAP_OPT_HOST_NAME, host);
#else
	DPRINTF2("ldap_init(%s, %d)", host, port);
	if ((ld = ldap_init((char *)host, port)) == NULL)
	    goto done;
	ret = LDAP_SUCCESS;
#endif
    }

    *ldp = ld;
done:
    debug_return_int(ret);
}

/*
 * Walk through search results and return true if we have a matching
 * non-Unix group (including netgroups), else false.
 */
static bool
sudo_ldap_check_non_unix_group(LDAP *ld, LDAPMessage *entry, struct passwd *pw)
{
    struct berval **bv, **p;
    char *val;
    bool ret = false;
    debug_decl(sudo_ldap_check_non_unix_group, SUDOERS_DEBUG_LDAP)

    if (!entry)
	debug_return_bool(ret);

    /* get the values from the entry */
    bv = ldap_get_values_len(ld, entry, "sudoUser");
    if (bv == NULL)
	debug_return_bool(ret);

    /* walk through values */
    for (p = bv; *p != NULL && !ret; p++) {
	val = (*p)->bv_val;
	if (*val == '+') {
	    if (netgr_matches(val, def_netgroup_tuple ? user_runhost : NULL,
		def_netgroup_tuple ? user_srunhost : NULL, pw->pw_name))
		ret = true;
	    DPRINTF2("ldap sudoUser netgroup '%s' ... %s", val,
		ret ? "MATCH!" : "not");
	} else {
	    if (group_plugin_query(pw->pw_name, val + 2, pw))
		ret = true;
	    DPRINTF2("ldap sudoUser non-Unix group '%s' ... %s", val,
		ret ? "MATCH!" : "not");
	}
    }

    ldap_value_free_len(bv);	/* cleanup */

    debug_return_bool(ret);
}

/*
* Walk through search results and return true if we have a
* host match, else false.
*/
static bool
sudo_ldap_check_host(LDAP *ld, LDAPMessage *entry, struct passwd *pw)
{
    struct berval **bv, **p;
    char *val;
    bool negated;
    int matched = UNSPEC;
    debug_decl(sudo_ldap_check_host, SUDOERS_DEBUG_LDAP)

    if (!entry)
	debug_return_bool(false);

    /* get the values from the entry */
    bv = ldap_get_values_len(ld, entry, "sudoHost");
    if (bv == NULL)
	debug_return_bool(false);

    /* walk through values */
    for (p = bv; *p != NULL && matched != false; p++) {
	val = (*p)->bv_val;
	negated = sudo_ldap_is_negated(&val);

	/* match any or address or netgroup or hostname */
	if (strcmp(val, "ALL") == 0 || addr_matches(val) ||
	    netgr_matches(val, user_runhost, user_srunhost,
	    def_netgroup_tuple ? pw->pw_name : NULL) ||
	    hostname_matches(user_srunhost, user_runhost, val)) {

	    matched = negated ? false : true;
	}
	DPRINTF2("ldap sudoHost '%s' ... %s",
	    val, matched == true ? "MATCH!" : "not");
    }

    ldap_value_free_len(bv);	/* cleanup */

    debug_return_bool(matched == true);
}

static int
sudo_ldap_check_runas_user(LDAP *ld, LDAPMessage *entry, int *group_matched)
{
    struct berval **bv, **p;
    char *val;
    bool ret = false;
    debug_decl(sudo_ldap_check_runas_user, SUDOERS_DEBUG_LDAP)

    /* get the runas user from the entry */
    bv = ldap_get_values_len(ld, entry, "sudoRunAsUser");
    if (bv == NULL)
	bv = ldap_get_values_len(ld, entry, "sudoRunAs"); /* old style */
    if (bv == NULL) {
	DPRINTF2("sudoRunAsUser: no result.");
	if (*group_matched == UNSPEC) {
	    /* We haven't check for sudoRunAsGroup yet, check now. */
	    bv = ldap_get_values_len(ld, entry, "sudoRunAsGroup");
	    if (bv != NULL) {
		*group_matched = false;
		ldap_value_free_len(bv);
	    }
	}
	if (!ISSET(sudo_user.flags, RUNAS_USER_SPECIFIED))
	    debug_return_int(UNSPEC);
	switch (*group_matched) {
	case UNSPEC:
	    /*
	     * No runas user or group entries.  Match runas_default
	     * against what the user specified on the command line.
	     */
	    ret = userpw_matches(def_runas_default, runas_pw->pw_name, runas_pw);
	    break;
	case true:
	    /*
	     * No runas user entries but have a matching runas group entry.
	     * If trying to run as the invoking user, allow it.
	     */
	    if (userpw_matches(user_name, runas_pw->pw_name, runas_pw))
		ret = true;
	    break;
	}
	debug_return_int(ret);
    }

    /*
     * BUG:
     *
     * if runas is not specified on the command line, the only information
     * as to which user to run as is in the runas_default option.  We should
     * check to see if we have the local option present.  Unfortunately we
     * don't parse these options until after this routine says yes or no.
     * The query has already returned, so we could peek at the attribute
     * values here though.
     *
     * For now just require users to always use -u option unless its set
     * in the global defaults. This behaviour is no different than the global
     * /etc/sudoers.
     *
     * Sigh - maybe add this feature later
     */

    /* walk through values returned, looking for a match */
    for (p = bv; *p != NULL && !ret; p++) {
	val = (*p)->bv_val;
	switch (val[0]) {
	case '+':
	    if (netgr_matches(val, def_netgroup_tuple ? user_runhost : NULL,
		def_netgroup_tuple ? user_srunhost : NULL, runas_pw->pw_name))
		ret = true;
	    break;
	case '%':
	    if (usergr_matches(val, runas_pw->pw_name, runas_pw))
		ret = true;
	    break;
	case '\0':
	    /* Empty RunAsUser means run as the invoking user. */
	    if (ISSET(sudo_user.flags, RUNAS_USER_SPECIFIED) &&
		userpw_matches(user_name, runas_pw->pw_name, runas_pw))
		ret = true;
	    break;
	case 'A':
	    if (strcmp(val, "ALL") == 0) {
		ret = true;
		break;
	    }
	    /* FALLTHROUGH */
	default:
	    if (userpw_matches(val, runas_pw->pw_name, runas_pw))
		ret = true;
	    break;
	}
	DPRINTF2("ldap sudoRunAsUser '%s' ... %s", val, ret ? "MATCH!" : "not");
    }

    ldap_value_free_len(bv);	/* cleanup */

    debug_return_int(ret);
}

static int
sudo_ldap_check_runas_group(LDAP *ld, LDAPMessage *entry)
{
    struct berval **bv, **p;
    char *val;
    bool ret = false;
    debug_decl(sudo_ldap_check_runas_group, SUDOERS_DEBUG_LDAP)

    /* get the values from the entry */
    bv = ldap_get_values_len(ld, entry, "sudoRunAsGroup");
    if (bv == NULL) {
	DPRINTF2("sudoRunAsGroup: no result.");
	if (!ISSET(sudo_user.flags, RUNAS_USER_SPECIFIED)) {
	    if (runas_pw->pw_gid == runas_gr->gr_gid)
		ret = true;	/* runas group matches passwd db */
	}
	debug_return_int(ret);
    }

    /* walk through values returned, looking for a match */
    for (p = bv; *p != NULL && !ret; p++) {
	val = (*p)->bv_val;
	if (strcmp(val, "ALL") == 0 || group_matches(val, runas_gr))
	    ret = true;
	DPRINTF2("ldap sudoRunAsGroup '%s' ... %s",
	    val, ret ? "MATCH!" : "not");
    }

    ldap_value_free_len(bv);	/* cleanup */

    debug_return_int(ret);
}

/*
 * Walk through search results and return true if we have a runas match,
 * else false.  RunAs info is optional.
 */
static bool
sudo_ldap_check_runas(LDAP *ld, LDAPMessage *entry)
{
    int user_matched = UNSPEC;
    int group_matched = UNSPEC;
    debug_decl(sudo_ldap_check_runas, SUDOERS_DEBUG_LDAP)

    if (!entry)
	debug_return_bool(false);

    if (ISSET(sudo_user.flags, RUNAS_GROUP_SPECIFIED))
	group_matched = sudo_ldap_check_runas_group(ld, entry);
    user_matched = sudo_ldap_check_runas_user(ld, entry, &group_matched);

    debug_return_bool(group_matched != false && user_matched != false);
}

/*
 * Walk through search results and return true if we have a command match,
 * false if disallowed and UNSPEC if not matched.
 */
static int
sudo_ldap_check_command(LDAP *ld, LDAPMessage *entry, int *setenv_implied)
{
    struct sudo_digest digest, *allowed_digest = NULL;
    struct berval **bv, **p;
    char *allowed_cmnd, *allowed_args, *val;
    int ret = UNSPEC;
    bool negated;
    debug_decl(sudo_ldap_check_command, SUDOERS_DEBUG_LDAP)

    if (!entry)
	debug_return_int(ret);

    bv = ldap_get_values_len(ld, entry, "sudoCommand");
    if (bv == NULL)
	debug_return_int(ret);

    for (p = bv; *p != NULL && ret != false; p++) {
	val = (*p)->bv_val;

	/* Match against ALL ? */
	if (strcmp(val, "ALL") == 0) {
	    ret = true;
	    if (setenv_implied != NULL)
		*setenv_implied = true;
	    DPRINTF2("ldap sudoCommand '%s' ... MATCH!", val);
	    continue;
	}

	/* check for sha-2 digest */
	allowed_digest = sudo_ldap_extract_digest(&val, &digest);

	/* check for !command */
	allowed_cmnd = val;
	negated = sudo_ldap_is_negated(&allowed_cmnd);

	/* split optional args away from command */
	allowed_args = strchr(allowed_cmnd, ' ');
	if (allowed_args)
	    *allowed_args++ = '\0';

	/* check the command like normal */
	if (command_matches(allowed_cmnd, allowed_args, allowed_digest)) {
	    /*
	     * If allowed (no bang) set ret but keep on checking.
	     * If disallowed (bang), exit loop.
	     */
	    ret = negated ? false : true;
	}
	if (allowed_args != NULL)
	    allowed_args[-1] = ' ';	/* restore val */

	DPRINTF2("ldap sudoCommand '%s' ... %s",
	    val, ret == true ? "MATCH!" : "not");

	if (allowed_digest != NULL)
	    free(allowed_digest->digest_str);
    }

    ldap_value_free_len(bv);	/* more cleanup */

    debug_return_int(ret);
}

/*
 * Search for boolean "option" in sudoOption.
 * Returns true if found and allowed, false if negated, else UNSPEC.
 */
static int
sudo_ldap_check_bool(LDAP *ld, LDAPMessage *entry, char *option)
{
    struct berval **bv, **p;
    char *var;
    bool negated;
    int ret = UNSPEC;
    debug_decl(sudo_ldap_check_bool, SUDOERS_DEBUG_LDAP)

    if (entry == NULL)
	debug_return_int(ret);

    bv = ldap_get_values_len(ld, entry, "sudoOption");
    if (bv == NULL)
	debug_return_int(ret);

    /* walk through options */
    for (p = bv; *p != NULL; p++) {
	var = (*p)->bv_val;
	DPRINTF2("ldap sudoOption: '%s'", var);

	negated = sudo_ldap_is_negated(&var);
	if (strcmp(var, option) == 0)
	    ret = negated ? false : true;
    }

    ldap_value_free_len(bv);

    debug_return_int(ret);
}

/*
 * Read sudoOption and modify the defaults as we go.  This is used once
 * from the cn=defaults entry and also once when a final sudoRole is matched.
 */
static bool
sudo_ldap_parse_options(LDAP *ld, LDAPMessage *entry)
{
    struct berval **bv, **p;
    char *cn, *var, *val, *source = NULL;
    bool ret = false;
    int op;
    debug_decl(sudo_ldap_parse_options, SUDOERS_DEBUG_LDAP)

    bv = ldap_get_values_len(ld, entry, "sudoOption");
    if (bv == NULL)
	debug_return_bool(true);

    /* get the entry's dn for option error reporting */
    cn = sudo_ldap_get_first_rdn(ld, entry);
    if (cn != NULL) {
	if (asprintf(&source, "sudoRole %s", cn) == -1) {
	    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	    source = NULL;
	    goto done;
	}
    }

    /* walk through options, early ones first */
    for (p = bv; *p != NULL; p++) {
	struct early_default *early;
	char *copy;

	/* Avoid modifying bv as we need to use it again below. */
	if ((copy = strdup((*p)->bv_val)) == NULL) {
	    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	    goto done;
	}
	op = sudo_ldap_parse_option(copy, &var, &val);
	early = is_early_default(var);
	if (early != NULL) {
	    set_early_default(var, val, op,
		source ? source : "sudoRole UNKNOWN", 0, false, early);
	}
	free(copy);
    }
    run_early_defaults();

    /* walk through options again, skipping early ones */
    for (p = bv; *p != NULL; p++) {
	op = sudo_ldap_parse_option((*p)->bv_val, &var, &val);
	if (is_early_default(var) == NULL) {
	    set_default(var, val, op,
		source ? source : "sudoRole UNKNOWN", 0, false);
	}
    }
    ret = true;

done:
    free(source);
    if (cn)
	ldap_memfree(cn);
    ldap_value_free_len(bv);

    debug_return_bool(ret);
}

/*
 * Build an LDAP timefilter.
 *
 * Stores a filter in the buffer that makes sure only entries
 * are selected that have a sudoNotBefore in the past and a
 * sudoNotAfter in the future, i.e. a filter of the following
 * structure (spaced out a little more for better readability:
 *
 * (&
 *   (|
 *	(!(sudoNotAfter=*))
 *	(sudoNotAfter>__now__)
 *   )
 *   (|
 *	(!(sudoNotBefore=*))
 *	(sudoNotBefore<__now__)
 *   )
 * )
 *
 * If either the sudoNotAfter or sudoNotBefore attributes are missing,
 * no time restriction shall be imposed.
 */
static bool
sudo_ldap_timefilter(char *buffer, size_t buffersize)
{
    struct tm *tp;
    time_t now;
    char timebuffer[sizeof("20120727121554.0Z")];
    int len = -1;
    debug_decl(sudo_ldap_timefilter, SUDOERS_DEBUG_LDAP)

    /* Make sure we have a formatted timestamp for __now__. */
    time(&now);
    if ((tp = gmtime(&now)) == NULL) {
	sudo_warn(U_("unable to get GMT time"));
	goto done;
    }

    /* Format the timestamp according to the RFC. */
    if (strftime(timebuffer, sizeof(timebuffer), "%Y%m%d%H%M%S.0Z", tp) == 0) {
	sudo_warnx(U_("unable to format timestamp"));
	goto done;
    }

    /* Build filter. */
    len = snprintf(buffer, buffersize, "(&(|(!(sudoNotAfter=*))(sudoNotAfter>=%s))(|(!(sudoNotBefore=*))(sudoNotBefore<=%s)))",
	timebuffer, timebuffer);
    if (len <= 0 || (size_t)len >= buffersize) {
	sudo_warnx(U_("internal error, %s overflow"), __func__);
	len = -1;
    }

done:
    debug_return_bool(len != -1);
}

/*
 * Builds up a filter to search for default settings
 */
static char *
sudo_ldap_build_default_filter(void)
{
    char *filt;
    debug_decl(sudo_ldap_build_default_filter, SUDOERS_DEBUG_LDAP)

    if (!ldap_conf.search_filter)
	debug_return_str(strdup("cn=defaults"));

    if (asprintf(&filt, "(&%s(cn=defaults))", ldap_conf.search_filter) == -1)
	debug_return_str(NULL);

    debug_return_str(filt);
}

/*
 * Determine length of query value after escaping characters
 * as per RFC 4515.
 */
static size_t
sudo_ldap_value_len(const char *value)
{
    const char *s;
    size_t len = 0;

    for (s = value; *s != '\0'; s++) {
	switch (*s) {
	case '\\':
	case '(':
	case ')':
	case '*':
	    len += 2;
	    break;
	}
    }
    len += (size_t)(s - value);
    return len;
}

/*
 * Like strlcat() but escapes characters as per RFC 4515.
 */
static size_t
sudo_ldap_value_cat(char *dst, const char *src, size_t size)
{
    char *d = dst;
    const char *s = src;
    size_t n = size;
    size_t dlen;

    /* Find the end of dst and adjust bytes left but don't go past end */
    while (n-- != 0 && *d != '\0')
	d++;
    dlen = d - dst;
    n = size - dlen;

    if (n == 0)
	return dlen + strlen(s);
    while (*s != '\0') {
	switch (*s) {
	case '\\':
	    if (n < 3)
		goto done;
	    *d++ = '\\';
	    *d++ = '5';
	    *d++ = 'c';
	    n -= 3;
	    break;
	case '(':
	    if (n < 3)
		goto done;
	    *d++ = '\\';
	    *d++ = '2';
	    *d++ = '8';
	    n -= 3;
	    break;
	case ')':
	    if (n < 3)
		goto done;
	    *d++ = '\\';
	    *d++ = '2';
	    *d++ = '9';
	    n -= 3;
	    break;
	case '*':
	    if (n < 3)
		goto done;
	    *d++ = '\\';
	    *d++ = '2';
	    *d++ = 'a';
	    n -= 3;
	    break;
	default:
	    if (n < 1)
		goto done;
	    *d++ = *s;
	    n--;
	    break;
	}
	s++;
    }
done:
    *d = '\0';
    while (*s != '\0')
	s++;
    return dlen + (s - src);	/* count does not include NUL */
}

/*
 * Like strdup() but escapes characters as per RFC 4515.
 */
static char *
sudo_ldap_value_dup(const char *src)
{
    char *dst;
    size_t size;

    size = sudo_ldap_value_len(src) + 1;
    dst = malloc(size);
    if (dst == NULL)
	return NULL;

    *dst = '\0';
    if (sudo_ldap_value_cat(dst, src, size) >= size) {
	/* Should not be possible... */
	free(dst);
	dst = NULL;
    }
    return dst;
}

/*
 * Check the netgroups list beginning at "start" for nesting.
 * Parent nodes with a memberNisNetgroup that match one of the
 * netgroups are added to the list and checked for further nesting.
 * Return true on success or false if there was an internal overflow.
 */
static bool
sudo_netgroup_lookup_nested(LDAP *ld, char *base, struct timeval *timeout,
    struct ldap_netgroup_list *netgroups, struct ldap_netgroup *start)
{
    LDAPMessage *entry, *result;
    size_t filt_len;
    char *filt;
    int rc;
    debug_decl(sudo_netgroup_lookup_nested, SUDOERS_DEBUG_LDAP);

    DPRINTF1("Checking for nested netgroups from netgroup_base '%s'", base);
    do {
	struct ldap_netgroup *ng, *old_tail;

	result = NULL;
	old_tail = STAILQ_LAST(netgroups, ldap_netgroup, entries);
	filt_len = strlen(ldap_conf.netgroup_search_filter) + 7;
	for (ng = start; ng != NULL; ng = STAILQ_NEXT(ng, entries)) {
	    filt_len += sudo_ldap_value_len(ng->name) + 20;
	}
	if ((filt = malloc(filt_len)) == NULL)
	    goto oom;
	CHECK_STRLCPY(filt, "(&", filt_len);
	CHECK_STRLCAT(filt, ldap_conf.netgroup_search_filter, filt_len);
	CHECK_STRLCAT(filt, "(|", filt_len);
	for (ng = start; ng != NULL; ng = STAILQ_NEXT(ng, entries)) {
	    CHECK_STRLCAT(filt, "(memberNisNetgroup=", filt_len);
	    CHECK_LDAP_VCAT(filt, ng->name, filt_len);
	    CHECK_STRLCAT(filt, ")", filt_len);
	}
	CHECK_STRLCAT(filt, "))", filt_len);
	DPRINTF1("ldap netgroup search filter: '%s'", filt);
	rc = ldap_search_ext_s(ld, base, LDAP_SCOPE_SUBTREE, filt,
	    NULL, 0, NULL, NULL, timeout, 0, &result);
	free(filt);
	if (rc == LDAP_SUCCESS) {
	    LDAP_FOREACH(entry, ld, result) {
		struct berval **bv;

		bv = ldap_get_values_len(ld, entry, "cn");
		if (bv != NULL) {
		    /* Don't add a netgroup twice. */
		    STAILQ_FOREACH(ng, netgroups, entries) {
			/* Assumes only one cn per entry. */
			if (strcasecmp(ng->name, (*bv)->bv_val) == 0)
			    break;
		    }
		    if (ng == NULL) {
			ng = malloc(sizeof(*ng));
			if (ng == NULL ||
			    (ng->name = strdup((*bv)->bv_val)) == NULL) {
			    free(ng);
			    ldap_value_free_len(bv);
			    goto oom;
			}
#ifdef __clang_analyzer__
			/* clang analyzer false positive */
			if (__builtin_expect(netgroups->stqh_last == NULL, 0))
			    __builtin_trap();
#endif
			STAILQ_INSERT_TAIL(netgroups, ng, entries);
			DPRINTF1("Found new netgroup %s for %s", ng->name, base);
		    }
		    ldap_value_free_len(bv);
		}
	    }
	}
	ldap_msgfree(result);

	/* Check for nested netgroups in what we added. */
	start = old_tail ? STAILQ_NEXT(old_tail, entries) : STAILQ_FIRST(netgroups);
    } while (start != NULL);

    debug_return_bool(true);
oom:
    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    ldap_msgfree(result);
    debug_return_bool(false);
overflow:
    sudo_warnx(U_("internal error, %s overflow"), __func__);
    free(filt);
    debug_return_bool(false);
}

/*
 * Look up netgroups that the specified user is a member of.
 * Appends new entries to the netgroups list.
 * Return true on success or false if there was an internal overflow.
 */
static bool
sudo_netgroup_lookup(LDAP *ld, struct passwd *pw,
    struct ldap_netgroup_list *netgroups)
{
    struct ldap_config_str *base;
    struct ldap_netgroup *ng, *old_tail;
    struct timeval tv, *tvp = NULL;
    LDAPMessage *entry, *result = NULL;
    const char *domain;
    char *escaped_domain = NULL, *escaped_user = NULL;
    char *escaped_host = NULL, *escaped_shost = NULL, *filt = NULL;
    int filt_len, rc;
    bool ret = false;
    debug_decl(sudo_netgroup_lookup, SUDOERS_DEBUG_LDAP);

    if (ldap_conf.timeout > 0) {
	tv.tv_sec = ldap_conf.timeout;
	tv.tv_usec = 0;
	tvp = &tv;
    }

    /* Use NIS domain if set, else wildcard match. */
    domain = sudo_getdomainname();

    /* Escape the domain, host names, and user name per RFC 4515. */
    if (domain != NULL) {
	if ((escaped_domain = sudo_ldap_value_dup(domain)) == NULL)
	    goto oom;
    }
    if ((escaped_user = sudo_ldap_value_dup(pw->pw_name)) == NULL)
	    goto oom;
    if (def_netgroup_tuple) {
	escaped_host = sudo_ldap_value_dup(user_runhost);
	if (user_runhost == user_srunhost)
	    escaped_shost = escaped_host;
	else
	    escaped_shost = sudo_ldap_value_dup(user_srunhost);
	if (escaped_host == NULL || escaped_shost == NULL)
	    goto oom;
    }

    /* Build query, using NIS domain if it is set. */
    if (domain != NULL) {
	if (escaped_host != escaped_shost) {
	    filt_len = asprintf(&filt, "(&%s(|"
		"(nisNetgroupTriple=\\28,%s,%s\\29)"
		"(nisNetgroupTriple=\\28%s,%s,%s\\29)"
		"(nisNetgroupTriple=\\28%s,%s,%s\\29)"
		"(nisNetgroupTriple=\\28,%s,\\29)"
		"(nisNetgroupTriple=\\28%s,%s,\\29)"
		"(nisNetgroupTriple=\\28%s,%s,\\29)))",
		ldap_conf.netgroup_search_filter, escaped_user, escaped_domain,
		escaped_shost, escaped_user, escaped_domain,
		escaped_host, escaped_user, escaped_domain, escaped_user,
		escaped_shost, escaped_user, escaped_host, escaped_user);
	} else if (escaped_shost != NULL) {
	    filt_len = asprintf(&filt, "(&%s(|"
		"(nisNetgroupTriple=\\28,%s,%s\\29)"
		"(nisNetgroupTriple=\\28%s,%s,%s\\29)"
		"(nisNetgroupTriple=\\28,%s,\\29)"
		"(nisNetgroupTriple=\\28%s,%s,\\29)))",
		ldap_conf.netgroup_search_filter, escaped_user, escaped_domain,
		escaped_shost, escaped_user, escaped_domain,
		escaped_user, escaped_shost, escaped_user);
	} else {
	    filt_len = asprintf(&filt, "(&%s(|"
		"(nisNetgroupTriple=\\28*,%s,%s\\29)"
		"(nisNetgroupTriple=\\28*,%s,\\29)))",
		ldap_conf.netgroup_search_filter, escaped_user, escaped_domain,
		escaped_user);
	}
    } else {
	if (escaped_host != escaped_shost) {
	    filt_len = asprintf(&filt, "(&%s(|"
		"(nisNetgroupTriple=\\28,%s,*\\29)"
		"(nisNetgroupTriple=\\28%s,%s,*\\29)"
		"(nisNetgroupTriple=\\28%s,%s,*\\29)))",
		ldap_conf.netgroup_search_filter, escaped_user,
		escaped_shost, escaped_user, escaped_host, escaped_user);
	} else if (escaped_shost != NULL) {
	    filt_len = asprintf(&filt, "(&%s(|"
		"(nisNetgroupTriple=\\28,%s,*\\29)"
		"(nisNetgroupTriple=\\28%s,%s,*\\29)))",
		ldap_conf.netgroup_search_filter, escaped_user,
		escaped_shost, escaped_user);
	} else {
	    filt_len = asprintf(&filt,
		"(&%s(|(nisNetgroupTriple=\\28*,%s,*\\29)))",
		ldap_conf.netgroup_search_filter, escaped_user);
	}
    }
    if (filt_len == -1)
	goto oom;
    DPRINTF1("ldap netgroup search filter: '%s'", filt);

    STAILQ_FOREACH(base, &ldap_conf.netgroup_base, entries) {
	DPRINTF1("searching from netgroup_base '%s'", base->val);
	rc = ldap_search_ext_s(ld, base->val, LDAP_SCOPE_SUBTREE, filt,
	    NULL, 0, NULL, NULL, tvp, 0, &result);
	if (rc != LDAP_SUCCESS) {
	    DPRINTF1("ldap netgroup search failed: %s", ldap_err2string(rc));
	    ldap_msgfree(result);
	    continue;
	}

	old_tail = STAILQ_LAST(netgroups, ldap_netgroup, entries);
	LDAP_FOREACH(entry, ld, result) {
	    struct berval **bv;

	    bv = ldap_get_values_len(ld, entry, "cn");
	    if (bv != NULL) {
		/* Don't add a netgroup twice. */
		STAILQ_FOREACH(ng, netgroups, entries) {
		    /* Assumes only one cn per entry. */
		    if (strcasecmp(ng->name, (*bv)->bv_val) == 0)
			break;
		}
		if (ng == NULL) {
		    ng = malloc(sizeof(*ng));
		    if (ng == NULL ||
			(ng->name = strdup((*bv)->bv_val)) == NULL) {
			free(ng);
			ldap_value_free_len(bv);
			goto oom;
		    }
		    STAILQ_INSERT_TAIL(netgroups, ng, entries);
		    DPRINTF1("Found new netgroup %s for %s", ng->name,
			base->val);
		}
		ldap_value_free_len(bv);
	    }
	}
	ldap_msgfree(result);
	result = NULL;

	/* Check for nested netgroups in what we added. */
	ng = old_tail ? STAILQ_NEXT(old_tail, entries) : STAILQ_FIRST(netgroups);
	if (ng != NULL) {
	    if (!sudo_netgroup_lookup_nested(ld, base->val, tvp, netgroups, ng))
		goto done;
	}
    }
    ret = true;
    goto done;

oom:
    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
done:
    free(escaped_domain);
    free(escaped_user);
    free(escaped_host);
    if (escaped_host != escaped_shost)
	free(escaped_shost);
    free(filt);
    ldap_msgfree(result);
    debug_return_bool(ret);
}

/*
 * Builds up a filter to check against LDAP.
 */
static char *
sudo_ldap_build_pass1(LDAP *ld, struct passwd *pw)
{
    char *buf, timebuffer[TIMEFILTER_LENGTH + 1], gidbuf[MAX_UID_T_LEN + 1];
    struct ldap_netgroup_list netgroups;
    struct ldap_netgroup *ng = NULL;
    struct gid_list *gidlist;
    struct group_list *grlist;
    struct group *grp;
    size_t sz = 0;
    int i;
    debug_decl(sudo_ldap_build_pass1, SUDOERS_DEBUG_LDAP)

    STAILQ_INIT(&netgroups);

    /* If there is a filter, allocate space for the global AND. */
    if (ldap_conf.timed || ldap_conf.search_filter)
	sz += 3;

    /* Add LDAP search filter if present. */
    if (ldap_conf.search_filter)
	sz += strlen(ldap_conf.search_filter);

    /* Then add (|(sudoUser=USERNAME)(sudoUser=ALL)) + NUL */
    sz += 29 + sudo_ldap_value_len(pw->pw_name);

    /* Add space for primary and supplementary groups and gids */
    if ((grp = sudo_getgrgid(pw->pw_gid)) != NULL) {
	sz += 12 + sudo_ldap_value_len(grp->gr_name);
    }
    sz += 13 + MAX_UID_T_LEN;
    if ((grlist = sudo_get_grlist(pw)) != NULL) {
	for (i = 0; i < grlist->ngroups; i++) {
	    if (grp != NULL && strcasecmp(grlist->groups[i], grp->gr_name) == 0)
		continue;
	    sz += 12 + sudo_ldap_value_len(grlist->groups[i]);
	}
    }
    if ((gidlist = sudo_get_gidlist(pw, ENTRY_TYPE_ANY)) != NULL) {
	for (i = 0; i < gidlist->ngids; i++) {
	    if (pw->pw_gid == gidlist->gids[i])
		continue;
	    sz += 13 + MAX_UID_T_LEN;
	}
    }

    /* Add space for user netgroups if netgroup_base specified. */
    if (!STAILQ_EMPTY(&ldap_conf.netgroup_base)) {
	DPRINTF1("Looking up netgroups for %s", pw->pw_name);
	if (sudo_netgroup_lookup(ld, pw, &netgroups)) {
	    STAILQ_FOREACH(ng, &netgroups, entries) {
		sz += 14 + strlen(ng->name);
	    }
	} else {
	    /* sudo_netgroup_lookup() failed, clean up. */
	    while ((ng = STAILQ_FIRST(&netgroups)) != NULL) {
		STAILQ_REMOVE_HEAD(&netgroups, entries);
		free(ng->name);
		free(ng);
	    }
	}
    }

    /* If timed, add space for time limits. */
    if (ldap_conf.timed)
	sz += TIMEFILTER_LENGTH;
    if ((buf = malloc(sz)) == NULL) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	goto bad;
    }
    *buf = '\0';

    /*
     * If timed or using a search filter, start a global AND clause to
     * contain the search filter, search criteria, and time restriction.
     */
    if (ldap_conf.timed || ldap_conf.search_filter)
	CHECK_STRLCPY(buf, "(&", sz);

    if (ldap_conf.search_filter)
	CHECK_STRLCAT(buf, ldap_conf.search_filter, sz);

    /* Global OR + sudoUser=user_name filter */
    CHECK_STRLCAT(buf, "(|(sudoUser=", sz);
    CHECK_LDAP_VCAT(buf, pw->pw_name, sz);
    CHECK_STRLCAT(buf, ")", sz);

    /* Append primary group and gid */
    if (grp != NULL) {
	CHECK_STRLCAT(buf, "(sudoUser=%", sz);
	CHECK_LDAP_VCAT(buf, grp->gr_name, sz);
	CHECK_STRLCAT(buf, ")", sz);
    }
    (void) snprintf(gidbuf, sizeof(gidbuf), "%u", (unsigned int)pw->pw_gid);
    CHECK_STRLCAT(buf, "(sudoUser=%#", sz);
    CHECK_STRLCAT(buf, gidbuf, sz);
    CHECK_STRLCAT(buf, ")", sz);

    /* Append supplementary groups and gids */
    if (grlist != NULL) {
	for (i = 0; i < grlist->ngroups; i++) {
	    if (grp != NULL && strcasecmp(grlist->groups[i], grp->gr_name) == 0)
		continue;
	    CHECK_STRLCAT(buf, "(sudoUser=%", sz);
	    CHECK_LDAP_VCAT(buf, grlist->groups[i], sz);
	    CHECK_STRLCAT(buf, ")", sz);
	}
    }
    if (gidlist != NULL) {
	for (i = 0; i < gidlist->ngids; i++) {
	    if (pw->pw_gid == gidlist->gids[i])
		continue;
	    (void) snprintf(gidbuf, sizeof(gidbuf), "%u",
		(unsigned int)gidlist->gids[i]);
	    CHECK_STRLCAT(buf, "(sudoUser=%#", sz);
	    CHECK_STRLCAT(buf, gidbuf, sz);
	    CHECK_STRLCAT(buf, ")", sz);
	}
    }

    /* Done with groups. */
    if (gidlist != NULL)
	sudo_gidlist_delref(gidlist);
    if (grlist != NULL)
	sudo_grlist_delref(grlist);
    if (grp != NULL)
	sudo_gr_delref(grp);

    /* Add netgroups (if any), freeing the list as we go. */
    while ((ng = STAILQ_FIRST(&netgroups)) != NULL) {
	STAILQ_REMOVE_HEAD(&netgroups, entries);
	CHECK_STRLCAT(buf, "(sudoUser=+", sz);
	CHECK_LDAP_VCAT(buf, ng->name, sz);
	CHECK_STRLCAT(buf, ")", sz);
	free(ng->name);
	free(ng);
    }

    /* Add ALL to list and end the global OR. */
    CHECK_STRLCAT(buf, "(sudoUser=ALL)", sz);

    /* Add the time restriction, or simply end the global OR. */
    if (ldap_conf.timed) {
	CHECK_STRLCAT(buf, ")", sz); /* closes the global OR */
	if (!sudo_ldap_timefilter(timebuffer, sizeof(timebuffer)))
	    goto bad;
	CHECK_STRLCAT(buf, timebuffer, sz);
    } else if (ldap_conf.search_filter) {
	CHECK_STRLCAT(buf, ")", sz); /* closes the global OR */
    }
    CHECK_STRLCAT(buf, ")", sz); /* closes the global OR or the global AND */

    debug_return_str(buf);
overflow:
    sudo_warnx(U_("internal error, %s overflow"), __func__);
    if (ng != NULL) {
	/* Overflow while traversing netgroups. */
	free(ng->name);
	free(ng);
    }
bad:
    while ((ng = STAILQ_FIRST(&netgroups)) != NULL) {
	STAILQ_REMOVE_HEAD(&netgroups, entries);
	free(ng->name);
	free(ng);
    }
    free(buf);
    debug_return_str(NULL);
}

/*
 * Builds up a filter to check against non-Unix group
 * entries in LDAP, including netgroups.
 */
static char *
sudo_ldap_build_pass2(void)
{
    char *filt, timebuffer[TIMEFILTER_LENGTH + 1];
    bool query_netgroups = def_use_netgroups;
    int len;
    debug_decl(sudo_ldap_build_pass2, SUDOERS_DEBUG_LDAP)

    /* No need to query netgroups if using netgroup_base. */
    if (!STAILQ_EMPTY(&ldap_conf.netgroup_base))
	query_netgroups = false;

    /* Short circuit if no netgroups and no non-Unix groups. */
    if (!query_netgroups && !def_group_plugin) {
	errno = ENOENT;
	debug_return_str(NULL);
    }

    if (ldap_conf.timed) {
	if (!sudo_ldap_timefilter(timebuffer, sizeof(timebuffer)))
	    debug_return_str(NULL);
    }

    /*
     * Match all sudoUsers beginning with '+' or '%:'.
     * If a search filter or time restriction is specified,
     * those get ANDed in to the expression.
     */
    if (query_netgroups && def_group_plugin) {
	len = asprintf(&filt, "%s%s(|(sudoUser=+*)(sudoUser=%%:*))%s%s",
	    (ldap_conf.timed || ldap_conf.search_filter) ? "(&" : "",
	    ldap_conf.search_filter ? ldap_conf.search_filter : "",
	    ldap_conf.timed ? timebuffer : "",
	    (ldap_conf.timed || ldap_conf.search_filter) ? ")" : "");
    } else {
	len = asprintf(&filt, "(&%s(sudoUser=*)(sudoUser=%s*)%s)",
	    ldap_conf.search_filter ? ldap_conf.search_filter : "",
	    query_netgroups ? "+" : "%:",
	    ldap_conf.timed ? timebuffer : "");
    }
    if (len == -1)
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));

    debug_return_str(filt);
}

/*
 * Extract the dn from an entry and return the first rdn from it.
 */
static char *
sudo_ldap_get_first_rdn(LDAP *ld, LDAPMessage *entry)
{
#ifdef HAVE_LDAP_STR2DN
    char *dn, *rdn = NULL;
    LDAPDN tmpDN;
    debug_decl(sudo_ldap_get_first_rdn, SUDOERS_DEBUG_LDAP)

    if ((dn = ldap_get_dn(ld, entry)) == NULL)
	debug_return_str(NULL);
    if (ldap_str2dn(dn, &tmpDN, LDAP_DN_FORMAT_LDAP) == LDAP_SUCCESS) {
	ldap_rdn2str(tmpDN[0], &rdn, LDAP_DN_FORMAT_UFN);
	ldap_dnfree(tmpDN);
    }
    ldap_memfree(dn);
    debug_return_str(rdn);
#else
    char *dn, **edn;
    debug_decl(sudo_ldap_get_first_rdn, SUDOERS_DEBUG_LDAP)

    if ((dn = ldap_get_dn(ld, entry)) == NULL)
	return NULL;
    edn = ldap_explode_dn(dn, 1);
    ldap_memfree(dn);
    debug_return_str(edn ? edn[0] : NULL);
#endif
}

/*
 * Fetch and display the global Options.
 */
static int
sudo_ldap_display_defaults(struct sudo_nss *nss, struct passwd *pw,
    struct sudo_lbuf *lbuf)
{
    struct berval **bv, **p;
    struct timeval tv, *tvp = NULL;
    struct ldap_config_str *base;
    struct sudo_ldap_handle *handle = nss->handle;
    LDAP *ld;
    LDAPMessage *entry, *result;
    char *prefix, *filt;
    int rc, count = 0;
    debug_decl(sudo_ldap_display_defaults, SUDOERS_DEBUG_LDAP)

    if (handle == NULL || handle->ld == NULL)
	goto done;
    ld = handle->ld;

    filt = sudo_ldap_build_default_filter();
    if (filt == NULL) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	count = -1;
	goto done;
    }
    STAILQ_FOREACH(base, &ldap_conf.base, entries) {
	if (ldap_conf.timeout > 0) {
	    tv.tv_sec = ldap_conf.timeout;
	    tv.tv_usec = 0;
	    tvp = &tv;
	}
	result = NULL;
	rc = ldap_search_ext_s(ld, base->val, LDAP_SCOPE_SUBTREE,
	    filt, NULL, 0, NULL, NULL, tvp, 0, &result);
	if (rc == LDAP_SUCCESS && (entry = ldap_first_entry(ld, result))) {
	    bv = ldap_get_values_len(ld, entry, "sudoOption");
	    if (bv != NULL) {
		if (lbuf->len == 0 || isspace((unsigned char)lbuf->buf[lbuf->len - 1]))
		    prefix = "    ";
		else
		    prefix = ", ";
		for (p = bv; *p != NULL; p++) {
		    struct defaults d;

		    sudo_lbuf_append(lbuf, "%s", prefix);
		    d.op = sudo_ldap_parse_option((*p)->bv_val, &d.var, &d.val);
		    sudoers_format_default(lbuf, &d);
		    prefix = ", ";
		    count++;
		}
		ldap_value_free_len(bv);
	    }
	}
	ldap_msgfree(result);
    }
    free(filt);
done:
    if (sudo_lbuf_error(lbuf))
	debug_return_int(-1);
    debug_return_int(count);
}

/*
 * STUB
 */
static int
sudo_ldap_display_bound_defaults(struct sudo_nss *nss, struct passwd *pw,
    struct sudo_lbuf *lbuf)
{
    debug_decl(sudo_ldap_display_bound_defaults, SUDOERS_DEBUG_LDAP)
    debug_return_int(0);
}

static char *
berval_iter(void **vp)
{
    struct berval **bv = *vp;

    *vp = bv + 1;
    return *bv ? (*bv)->bv_val : NULL;
}

static struct userspec_list *
ldap_to_sudoers(LDAP *ld, struct ldap_result *lres)
{
    struct userspec_list *ldap_userspecs;
    struct userspec *us;
    struct member *m;
    unsigned int i;
    debug_decl(ldap_to_sudoers, SUDOERS_DEBUG_LDAP)

    if ((ldap_userspecs = calloc(1, sizeof(*ldap_userspecs))) == NULL)
	goto oom;
    TAILQ_INIT(ldap_userspecs);

    /* We only have a single userspec */
    if ((us = calloc(1, sizeof(*us))) == NULL)
	goto oom;
    TAILQ_INIT(&us->users);
    TAILQ_INIT(&us->privileges);
    STAILQ_INIT(&us->comments);
    TAILQ_INSERT_TAIL(ldap_userspecs, us, entries);

    /* The user has already matched, use ALL as wildcard. */
    if ((m = calloc(1, sizeof(*m))) == NULL)
	goto oom;
    m->type = ALL;
    TAILQ_INSERT_TAIL(&us->users, m, entries);

    /* Treat each sudoRole as a separate privilege. */
    for (i = 0; i < lres->nentries; i++) {
	LDAPMessage *entry = lres->entries[i].entry;
	struct berval **cmnds, **runasusers, **runasgroups;
	struct berval **opts, **notbefore, **notafter;
	struct privilege *priv;
	char *cn;

	/* Ignore sudoRole without sudoCommand. */
	cmnds = ldap_get_values_len(ld, entry, "sudoCommand");
	if (cmnds == NULL)
	    continue;

	/* Get the entry's dn for long format printing. */
	cn = sudo_ldap_get_first_rdn(ld, entry);

	/* Get sudoRunAsUser / sudoRunAsGroup */
	runasusers = ldap_get_values_len(ld, entry, "sudoRunAsUser");
	if (runasusers == NULL)
	    runasusers = ldap_get_values_len(ld, entry, "sudoRunAs");
	runasgroups = ldap_get_values_len(ld, entry, "sudoRunAsGroup");

	/* Get sudoNotBefore / sudoNotAfter */
	notbefore = ldap_get_values_len(ld, entry, "sudoNotBefore");
	notafter = ldap_get_values_len(ld, entry, "sudoNotAfter");

	/* Parse sudoOptions. */
	opts = ldap_get_values_len(ld, entry, "sudoOption");

	priv = sudo_ldap_role_to_priv(cn, NULL, runasusers, runasgroups,
	    cmnds, opts, notbefore ? notbefore[0]->bv_val : NULL,
	    notafter ? notafter[0]->bv_val : NULL, false, long_list,
	    berval_iter);

	/* Cleanup */
	if (cn != NULL)
	    ldap_memfree(cn);
	if (cmnds != NULL)
	    ldap_value_free_len(cmnds);
	if (runasusers != NULL)
	    ldap_value_free_len(runasusers);
	if (runasgroups != NULL)
	    ldap_value_free_len(runasgroups);
	if (opts != NULL)
	    ldap_value_free_len(opts);
	if (notbefore != NULL)
	    ldap_value_free_len(notbefore);
	if (notafter != NULL)
	    ldap_value_free_len(notafter);

	if (priv == NULL)
	    goto oom;
	TAILQ_INSERT_TAIL(&us->privileges, priv, entries);
    }

    debug_return_ptr(ldap_userspecs);

oom:
    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    if (ldap_userspecs != NULL) {
	while ((us = TAILQ_FIRST(ldap_userspecs)) != NULL) {
	    TAILQ_REMOVE(ldap_userspecs, us, entries);
	    free_userspec(us);
	}
	free(ldap_userspecs);
    }
    debug_return_ptr(NULL);
}

/*
 * Like sudo_ldap_lookup(), except we just print entries.
 */
static int
sudo_ldap_display_privs(struct sudo_nss *nss, struct passwd *pw,
    struct sudo_lbuf *lbuf)
{
    struct sudo_ldap_handle *handle = nss->handle;
    struct userspec_list *ldap_userspecs = NULL;
    struct ldap_result *lres;
    LDAP *ld;
    int ret = 0;
    debug_decl(sudo_ldap_display_privs, SUDOERS_DEBUG_LDAP)

    if (handle == NULL || handle->ld == NULL)
	goto done;
    ld = handle->ld;

    DPRINTF1("ldap search for command list");
    lres = sudo_ldap_result_get(nss, pw);
    if (lres == NULL)
	goto done;

    /* Convert to sudoers parse tree. */
    if ((ldap_userspecs = ldap_to_sudoers(ld, lres)) == NULL) {
	ret = -1;
	goto done;
    }

    /* Call common display code. */
    ret = sudo_display_userspecs(ldap_userspecs, pw, lbuf);

done:
    if (ldap_userspecs != NULL) {
	struct userspec *us;
	while ((us = TAILQ_FIRST(ldap_userspecs)) != NULL) {
	    TAILQ_REMOVE(ldap_userspecs, us, entries);
	    free_userspec(us);
	}
	free(ldap_userspecs);
    }
    if (sudo_lbuf_error(lbuf))
	debug_return_int(-1);
    debug_return_int(ret);
}

static int
sudo_ldap_display_cmnd(struct sudo_nss *nss, struct passwd *pw)
{
    struct sudo_ldap_handle *handle = nss->handle;
    LDAP *ld;
    struct ldap_result *lres;
    LDAPMessage *entry;
    bool found = false;
    unsigned int i;
    debug_decl(sudo_ldap_display_cmnd, SUDOERS_DEBUG_LDAP)

    if (handle == NULL || handle->ld == NULL)
	goto done;
    ld = handle->ld;

    /*
     * The sudo_ldap_result_get() function returns all nodes that match
     * the user and the host.
     */
    DPRINTF1("ldap search for command list");
    lres = sudo_ldap_result_get(nss, pw);
    if (lres == NULL)
	goto done;
    for (i = 0; i < lres->nentries; i++) {
	entry = lres->entries[i].entry;
	if (!sudo_ldap_check_runas(ld, entry))
	    continue;
	if (sudo_ldap_check_command(ld, entry, NULL) == true) {
	    found = true;
	    goto done;
	}
    }

done:
    if (found)
	sudo_printf(SUDO_CONV_INFO_MSG, "%s%s%s\n",
	    safe_cmnd ? safe_cmnd : user_cmnd,
	    user_args ? " " : "", user_args ? user_args : "");
   debug_return_int(!found);
}

#ifdef HAVE_LDAP_SASL_INTERACTIVE_BIND_S
static unsigned int (*sudo_gss_krb5_ccache_name)(unsigned int *minor_status, const char *name, const char **old_name);

static int
sudo_set_krb5_ccache_name(const char *name, const char **old_name)
{
    int ret = 0;
    unsigned int junk;
    static bool initialized;
    debug_decl(sudo_set_krb5_ccache_name, SUDOERS_DEBUG_LDAP)

    if (!initialized) {
	sudo_gss_krb5_ccache_name =
	    sudo_dso_findsym(SUDO_DSO_DEFAULT, "gss_krb5_ccache_name");
	initialized = true;
    }

    /*
     * Try to use gss_krb5_ccache_name() if possible.
     * We also need to set KRB5CCNAME since some LDAP libs may not use
     * gss_krb5_ccache_name().
     */
    if (sudo_gss_krb5_ccache_name != NULL) {
	ret = sudo_gss_krb5_ccache_name(&junk, name, old_name);
    } else {
	/* No gss_krb5_ccache_name(), fall back on KRB5CCNAME. */
	if (old_name != NULL)
	    *old_name = sudo_getenv("KRB5CCNAME");
    }
    if (name != NULL && *name != '\0') {
	if (sudo_setenv("KRB5CCNAME", name, true) == -1)
	    ret = -1;
    } else {
	if (sudo_unsetenv("KRB5CCNAME") == -1)
	    ret = -1;
    }

    debug_return_int(ret);
}

/*
 * Make a copy of the credential cache file specified by KRB5CCNAME
 * which must be readable by the user.  The resulting cache file
 * is root-owned and will be removed after authenticating via SASL.
 */
static char *
sudo_krb5_copy_cc_file(const char *old_ccname)
{
    int nfd, ofd = -1;
    ssize_t nread, nwritten = -1;
    static char new_ccname[sizeof(_PATH_TMP) + sizeof("sudocc_XXXXXXXX") - 1];
    char buf[10240], *ret = NULL;
    debug_decl(sudo_krb5_copy_cc_file, SUDOERS_DEBUG_LDAP)

    old_ccname = sudo_krb5_ccname_path(old_ccname);
    if (old_ccname != NULL) {
	/* Open credential cache as user to prevent stolen creds. */
	if (!set_perms(PERM_USER))
	    goto done;
	ofd = open(old_ccname, O_RDONLY|O_NONBLOCK);
	if (!restore_perms())
	    goto done;

	if (ofd != -1) {
	    (void) fcntl(ofd, F_SETFL, 0);
	    if (sudo_lock_file(ofd, SUDO_LOCK)) {
		snprintf(new_ccname, sizeof(new_ccname), "%s%s",
		    _PATH_TMP, "sudocc_XXXXXXXX");
		nfd = mkstemp(new_ccname);
		if (nfd != -1) {
		    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
			"copy ccache %s -> %s", old_ccname, new_ccname);
		    while ((nread = read(ofd, buf, sizeof(buf))) > 0) {
			ssize_t off = 0;
			do {
			    nwritten = write(nfd, buf + off, nread - off);
			    if (nwritten == -1) {
				sudo_warn("error writing to %s", new_ccname);
				goto write_error;
			    }
			    off += nwritten;
			} while (off < nread);
		    }
		    if (nread == -1)
			sudo_warn("unable to read %s", new_ccname);
write_error:
		    close(nfd);
		    if (nread != -1 && nwritten != -1) {
			ret = new_ccname;	/* success! */
		    } else {
			unlink(new_ccname);	/* failed */
		    }
		} else {
		    sudo_warn("unable to create temp file %s", new_ccname);
		}
	    }
	} else {
	    sudo_debug_printf(SUDO_DEBUG_WARN|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
		"unable to open %s", old_ccname);
	}
    }
done:
    if (ofd != -1)
	close(ofd);
    debug_return_str(ret);
}

static int
sudo_ldap_sasl_interact(LDAP *ld, unsigned int flags, void *_auth_id,
    void *_interact)
{
    char *auth_id = (char *)_auth_id;
    sasl_interact_t *interact = (sasl_interact_t *)_interact;
    int ret = LDAP_SUCCESS;
    debug_decl(sudo_ldap_sasl_interact, SUDOERS_DEBUG_LDAP)

    for (; interact->id != SASL_CB_LIST_END; interact++) {
	if (interact->id != SASL_CB_USER) {
	    sudo_warnx("sudo_ldap_sasl_interact: unexpected interact id %lu",
		interact->id);
	    ret = LDAP_PARAM_ERROR;
	    break;
	}

	if (auth_id != NULL)
	    interact->result = auth_id;
	else if (interact->defresult != NULL)
	    interact->result = interact->defresult;
	else
	    interact->result = "";

	interact->len = strlen(interact->result);
#if SASL_VERSION_MAJOR < 2
	interact->result = strdup(interact->result);
	if (interact->result == NULL) {
	    ret = LDAP_NO_MEMORY;
	    break;
	}
#endif /* SASL_VERSION_MAJOR < 2 */
	DPRINTF2("sudo_ldap_sasl_interact: SASL_CB_USER %s",
	    (const char *)interact->result);
    }
    debug_return_int(ret);
}
#endif /* HAVE_LDAP_SASL_INTERACTIVE_BIND_S */

/*
 * Create a new sudo_ldap_result structure.
 */
static struct ldap_result *
sudo_ldap_result_alloc(void)
{
    struct ldap_result *result;
    debug_decl(sudo_ldap_result_alloc, SUDOERS_DEBUG_LDAP)

    result = calloc(1, sizeof(*result));
    if (result != NULL)
	STAILQ_INIT(&result->searches);

    debug_return_ptr(result);
}

/*
 * Free the ldap result structure
 */
static void
sudo_ldap_result_free(struct ldap_result *lres)
{
    struct ldap_search_result *s;
    debug_decl(sudo_ldap_result_free, SUDOERS_DEBUG_LDAP)

    if (lres != NULL) {
	if (lres->nentries) {
	    free(lres->entries);
	    lres->entries = NULL;
	}
	while ((s = STAILQ_FIRST(&lres->searches)) != NULL) {
	    STAILQ_REMOVE_HEAD(&lres->searches, entries);
	    ldap_msgfree(s->searchresult);
	    free(s);
	}
	free(lres);
    }
    debug_return;
}

/*
 * Add a search result to the ldap_result structure.
 */
static struct ldap_search_result *
sudo_ldap_result_add_search(struct ldap_result *lres, LDAP *ldap,
    LDAPMessage *searchresult)
{
    struct ldap_search_result *news;
    debug_decl(sudo_ldap_result_add_search, SUDOERS_DEBUG_LDAP)

    /* Create new entry and add it to the end of the chain. */
    news = calloc(1, sizeof(*news));
    if (news != NULL) {
	news->ldap = ldap;
	news->searchresult = searchresult;
	STAILQ_INSERT_TAIL(&lres->searches, news, entries);
    }

    debug_return_ptr(news);
}

/*
 * Connect to the LDAP server specified by ld.
 * Returns LDAP_SUCCESS on success, else non-zero.
 */
static int
sudo_ldap_bind_s(LDAP *ld)
{
    int ret;
    debug_decl(sudo_ldap_bind_s, SUDOERS_DEBUG_LDAP)

#ifdef HAVE_LDAP_SASL_INTERACTIVE_BIND_S
    if (ldap_conf.rootuse_sasl == true ||
	(ldap_conf.rootuse_sasl != false && ldap_conf.use_sasl == true)) {
	const char *old_ccname = NULL;
	const char *new_ccname = ldap_conf.krb5_ccname;
	const char *tmp_ccname = NULL;
	void *auth_id = ldap_conf.rootsasl_auth_id ?
	    ldap_conf.rootsasl_auth_id : ldap_conf.sasl_auth_id;
	int rc;

	/* Make temp copy of the user's credential cache as needed. */
	if (ldap_conf.krb5_ccname == NULL && user_ccname != NULL) {
	    new_ccname = tmp_ccname = sudo_krb5_copy_cc_file(user_ccname);
	    if (tmp_ccname == NULL) {
		/* XXX - fatal error */
		sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
		    "unable to copy user ccache %s", user_ccname);
	    }
	}

	if (new_ccname != NULL) {
	    rc = sudo_set_krb5_ccache_name(new_ccname, &old_ccname);
	    if (rc == 0) {
		sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
		    "set ccache name %s -> %s",
		    old_ccname ? old_ccname : "(none)", new_ccname);
	    } else {
		sudo_debug_printf(SUDO_DEBUG_WARN|SUDO_DEBUG_LINENO,
		    "sudo_set_krb5_ccache_name() failed: %d", rc);
	    }
	}
	ret = ldap_sasl_interactive_bind_s(ld, ldap_conf.binddn,
	    ldap_conf.sasl_mech, NULL, NULL, LDAP_SASL_QUIET,
	    sudo_ldap_sasl_interact, auth_id);
	if (new_ccname != NULL) {
	    rc = sudo_set_krb5_ccache_name(old_ccname ? old_ccname : "", NULL);
	    if (rc == 0) {
		sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
		    "restore ccache name %s -> %s", new_ccname,
		    old_ccname ? old_ccname : "(none)");
	    } else {
		sudo_debug_printf(SUDO_DEBUG_WARN|SUDO_DEBUG_LINENO,
		    "sudo_set_krb5_ccache_name() failed: %d", rc);
	    }
	    /* Remove temporary copy of user's credential cache. */
	    if (tmp_ccname != NULL)
		unlink(tmp_ccname);
	}
	if (ret != LDAP_SUCCESS) {
	    sudo_warnx("ldap_sasl_interactive_bind_s(): %s",
		ldap_err2string(ret));
	    goto done;
	}
	DPRINTF1("ldap_sasl_interactive_bind_s() ok");
    } else
#endif /* HAVE_LDAP_SASL_INTERACTIVE_BIND_S */
#ifdef HAVE_LDAP_SASL_BIND_S
    {
	struct berval bv;

	bv.bv_val = ldap_conf.bindpw ? ldap_conf.bindpw : "";
	bv.bv_len = strlen(bv.bv_val);

	ret = ldap_sasl_bind_s(ld, ldap_conf.binddn, LDAP_SASL_SIMPLE, &bv,
	    NULL, NULL, NULL);
	if (ret != LDAP_SUCCESS) {
	    sudo_warnx("ldap_sasl_bind_s(): %s", ldap_err2string(ret));
	    goto done;
	}
	DPRINTF1("ldap_sasl_bind_s() ok");
    }
#else
    {
	ret = ldap_simple_bind_s(ld, ldap_conf.binddn, ldap_conf.bindpw);
	if (ret != LDAP_SUCCESS) {
	    sudo_warnx("ldap_simple_bind_s(): %s", ldap_err2string(ret));
	    goto done;
	}
	DPRINTF1("ldap_simple_bind_s() ok");
    }
#endif
done:
    debug_return_int(ret);
}

/*
 * Open a connection to the LDAP server.
 * Returns 0 on success and non-zero on failure.
 */
static int
sudo_ldap_open(struct sudo_nss *nss)
{
    LDAP *ld;
    int rc = -1;
    bool ldapnoinit = false;
    struct sudo_ldap_handle *handle;
    debug_decl(sudo_ldap_open, SUDOERS_DEBUG_LDAP)

    if (!sudo_ldap_read_config())
	goto done;

    /* Prevent reading of user ldaprc and system defaults. */
    if (sudo_getenv("LDAPNOINIT") == NULL) {
	if (sudo_setenv("LDAPNOINIT", "1", true) == 0)
	    ldapnoinit = true;
    }

    /* Set global LDAP options */
    if (sudo_ldap_set_options_global() != LDAP_SUCCESS)
	goto done;

    /* Connect to LDAP server */
#ifdef HAVE_LDAP_INITIALIZE
    if (!STAILQ_EMPTY(&ldap_conf.uri)) {
	char *buf = sudo_ldap_join_uri(&ldap_conf.uri);
	if (buf == NULL)
	    goto done;
	DPRINTF2("ldap_initialize(ld, %s)", buf);
	rc = ldap_initialize(&ld, buf);
	free(buf);
    } else
#endif
	rc = sudo_ldap_init(&ld, ldap_conf.host, ldap_conf.port);
    if (rc != LDAP_SUCCESS) {
	sudo_warnx(U_("unable to initialize LDAP: %s"), ldap_err2string(rc));
	goto done;
    }

    /* Set LDAP per-connection options */
    rc = sudo_ldap_set_options_conn(ld);
    if (rc != LDAP_SUCCESS)
	goto done;

    if (ldapnoinit)
	(void) sudo_unsetenv("LDAPNOINIT");

    if (ldap_conf.ssl_mode == SUDO_LDAP_STARTTLS) {
#if defined(HAVE_LDAP_START_TLS_S)
	rc = ldap_start_tls_s(ld, NULL, NULL);
	if (rc != LDAP_SUCCESS) {
	    sudo_warnx("ldap_start_tls_s(): %s", ldap_err2string(rc));
	    goto done;
	}
	DPRINTF1("ldap_start_tls_s() ok");
#elif defined(HAVE_LDAP_SSL_CLIENT_INIT) && defined(HAVE_LDAP_START_TLS_S_NP)
	int sslrc;
	rc = ldap_ssl_client_init(ldap_conf.tls_keyfile, ldap_conf.tls_keypw,
	    0, &sslrc);
	if (rc != LDAP_SUCCESS) {
	    sudo_warnx("ldap_ssl_client_init(): %s (SSL reason code %d)",
		ldap_err2string(rc), sslrc);
	    goto done;
	}
	rc = ldap_start_tls_s_np(ld, NULL);
	if (rc != LDAP_SUCCESS) {
	    sudo_warnx("ldap_start_tls_s_np(): %s", ldap_err2string(rc));
	    goto done;
	}
	DPRINTF1("ldap_start_tls_s_np() ok");
#else
	sudo_warnx(U_("start_tls specified but LDAP libs do not support ldap_start_tls_s() or ldap_start_tls_s_np()"));
#endif /* !HAVE_LDAP_START_TLS_S && !HAVE_LDAP_START_TLS_S_NP */
    }

    /* Actually connect */
    rc = sudo_ldap_bind_s(ld);
    if (rc != LDAP_SUCCESS)
	goto done;

    /* Create a handle container. */
    handle = calloc(1, sizeof(struct sudo_ldap_handle));
    if (handle == NULL) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	rc = -1;
	goto done;
    }
    handle->ld = ld;
    /* handle->result = NULL; */
    /* handle->username = NULL; */
    /* handle->gidlist = NULL; */
    nss->handle = handle;

done:
    debug_return_int(rc == LDAP_SUCCESS ? 0 : -1);
}

static int
sudo_ldap_setdefs(struct sudo_nss *nss)
{
    struct ldap_config_str *base;
    struct sudo_ldap_handle *handle = nss->handle;
    struct timeval tv, *tvp = NULL;
    LDAP *ld;
    LDAPMessage *entry, *result = NULL;
    char *filt;
    int ret;
    debug_decl(sudo_ldap_setdefs, SUDOERS_DEBUG_LDAP)

    if (handle == NULL || handle->ld == NULL)
	debug_return_int(-1);
    ld = handle->ld;

    filt = sudo_ldap_build_default_filter();
    if (filt == NULL) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	debug_return_int(-1);
    }
    DPRINTF1("Looking for cn=defaults: %s", filt);

    STAILQ_FOREACH(base, &ldap_conf.base, entries) {
	if (ldap_conf.timeout > 0) {
	    tv.tv_sec = ldap_conf.timeout;
	    tv.tv_usec = 0;
	    tvp = &tv;
	}
	ldap_msgfree(result);
	result = NULL;
	ret = ldap_search_ext_s(ld, base->val, LDAP_SCOPE_SUBTREE,
	    filt, NULL, 0, NULL, NULL, tvp, 0, &result);
	if (ret == LDAP_SUCCESS && (entry = ldap_first_entry(ld, result))) {
	    DPRINTF1("found:%s", ldap_get_dn(ld, entry));
	    if (!sudo_ldap_parse_options(ld, entry)) {
		ret = -1;
		goto done;
	    }
	} else {
	    DPRINTF1("no default options found in %s", base->val);
	}
    }
    ret = 0;

done:
    ldap_msgfree(result);
    free(filt);

    debug_return_int(ret);
}

/*
 * like sudoers_lookup() - only LDAP style
 */
static int
sudo_ldap_lookup(struct sudo_nss *nss, int ret, int pwflag)
{
    struct sudo_ldap_handle *handle = nss->handle;
    LDAP *ld;
    LDAPMessage *entry;
    int rc, setenv_implied;
    unsigned int i;
    struct ldap_result *lres = NULL;
    debug_decl(sudo_ldap_lookup, SUDOERS_DEBUG_LDAP)

    if (handle == NULL || handle->ld == NULL)
	debug_return_int(ret);
    ld = handle->ld;

    /* Fetch list of sudoRole entries that match user and host. */
    lres = sudo_ldap_result_get(nss, sudo_user.pw);
    if (lres == NULL)
	debug_return_int(ret);

    /*
     * The following queries only determine whether or not a password
     * is required, so the order of the entries doesn't matter.
     */
    if (pwflag) {
	int doauth = UNSPEC;
	int matched = UNSPEC;
	enum def_tuple pwcheck =
	    (pwflag == -1) ? never : sudo_defs_table[pwflag].sd_un.tuple;

	DPRINTF1("perform search for pwflag %d", pwflag);
	for (i = 0; i < lres->nentries; i++) {
	    entry = lres->entries[i].entry;
	    if ((pwcheck == any && doauth != false) ||
		(pwcheck == all && doauth != true)) {
		doauth = !!sudo_ldap_check_bool(ld, entry, "authenticate");
	    }
	    if (matched == true)
		continue;
	    /* Only check the command when listing another user. */
	    if (user_uid == 0 || list_pw == NULL ||
		user_uid == list_pw->pw_uid ||
		sudo_ldap_check_command(ld, entry, NULL) == true) {
		matched = true;
	    }
	}
	if (matched == true || user_uid == 0) {
	    SET(ret, VALIDATE_SUCCESS);
	    CLR(ret, VALIDATE_FAILURE);
	    switch (pwcheck) {
		case always:
		    SET(ret, FLAG_CHECK_USER);
		    break;
		case all:
		case any:
		    if (doauth == false)
			SET(ret, FLAG_NOPASSWD);
		    else
			CLR(ret, FLAG_NOPASSWD);
		    break;
		default:
		    break;
	    }
	}
	goto done;
    }

    DPRINTF1("searching LDAP for sudoers entries");

    setenv_implied = false;
    for (i = 0; i < lres->nentries; i++) {
	entry = lres->entries[i].entry;
	if (!sudo_ldap_check_runas(ld, entry))
	    continue;
	rc = sudo_ldap_check_command(ld, entry, &setenv_implied);
	if (rc != UNSPEC) {
	    /* We have a match. */
	    DPRINTF1("Command %sallowed", rc == true ? "" : "NOT ");
	    if (rc == true) {
		DPRINTF1("LDAP entry: %p", entry);
		/* Apply entry-specific options. */
		if (setenv_implied)
		    def_setenv = true;
		if (sudo_ldap_parse_options(ld, entry)) {
#ifdef HAVE_SELINUX
		    /* Set role and type if not specified on command line. */
		    if (user_role == NULL)
			user_role = def_role;
		    if (user_type == NULL)
			user_type = def_type;
#endif /* HAVE_SELINUX */
		    SET(ret, VALIDATE_SUCCESS);
		    CLR(ret, VALIDATE_FAILURE);
		} else {
		    SET(ret, VALIDATE_ERROR);
		}
	    } else {
		SET(ret, VALIDATE_FAILURE);
		CLR(ret, VALIDATE_SUCCESS);
	    }
	    break;
	}
    }

done:
    DPRINTF1("done with LDAP searches");
    DPRINTF1("user_matches=%s", lres->user_matches ? "true" : "false");
    DPRINTF1("host_matches=%s", lres->host_matches ? "true" : "false");

    if (!ISSET(ret, VALIDATE_SUCCESS)) {
	/* No matching entries. */
	if (pwflag && list_pw == NULL)
	    SET(ret, FLAG_NO_CHECK);
    }
    if (pwflag || lres->user_matches)
	CLR(ret, FLAG_NO_USER);
    if (pwflag || lres->host_matches)
	CLR(ret, FLAG_NO_HOST);
    DPRINTF1("sudo_ldap_lookup(%d)=0x%02x", pwflag, ret);

    debug_return_int(ret);
}

/*
 * Comparison function for ldap_entry_wrapper structures, descending order.
 */
static int
ldap_entry_compare(const void *a, const void *b)
{
    const struct ldap_entry_wrapper *aw = a;
    const struct ldap_entry_wrapper *bw = b;
    debug_decl(ldap_entry_compare, SUDOERS_DEBUG_LDAP)

    debug_return_int(bw->order < aw->order ? -1 :
	(bw->order > aw->order ? 1 : 0));
}

/*
 * Return the last entry in the list of searches, usually the
 * one currently being used to add entries.
 */
static struct ldap_search_result *
sudo_ldap_result_last_search(struct ldap_result *lres)
{
    debug_decl(sudo_ldap_result_last_search, SUDOERS_DEBUG_LDAP)

    debug_return_ptr(STAILQ_LAST(&lres->searches, ldap_search_result, entries));
}

/*
 * Add an entry to the result structure.
 */
static struct ldap_entry_wrapper *
sudo_ldap_result_add_entry(struct ldap_result *lres, LDAPMessage *entry)
{
    struct ldap_search_result *last;
    struct berval **bv;
    double order = 0.0;
    char *ep;
    debug_decl(sudo_ldap_result_add_entry, SUDOERS_DEBUG_LDAP)

    /* Determine whether the entry has the sudoOrder attribute. */
    last = sudo_ldap_result_last_search(lres);
    if (last != NULL) {
	bv = ldap_get_values_len(last->ldap, entry, "sudoOrder");
	if (bv != NULL) {
	    if (ldap_count_values_len(bv) > 0) {
		/* Get the value of this attribute, 0 if not present. */
		DPRINTF2("order attribute raw: %s", (*bv)->bv_val);
		order = strtod((*bv)->bv_val, &ep);
		if (ep == (*bv)->bv_val || *ep != '\0') {
		    sudo_warnx(U_("invalid sudoOrder attribute: %s"),
			(*bv)->bv_val);
		    order = 0.0;
		}
		DPRINTF2("order attribute: %f", order);
	    }
	    ldap_value_free_len(bv);
	}
    }

    /*
     * Enlarge the array of entry wrappers as needed, preallocating blocks
     * of 100 entries to save on allocation time.
     */
    if (++lres->nentries > lres->allocated_entries) {
	int allocated_entries = lres->allocated_entries + ALLOCATION_INCREMENT;
	struct ldap_entry_wrapper *entries = reallocarray(lres->entries,
	    allocated_entries, sizeof(lres->entries[0]));
	if (entries == NULL)
	    debug_return_ptr(NULL);
	lres->allocated_entries = allocated_entries;
	lres->entries = entries;
    }

    /* Fill in the new entry and return it. */
    lres->entries[lres->nentries - 1].entry = entry;
    lres->entries[lres->nentries - 1].order = order;

    debug_return_ptr(&lres->entries[lres->nentries - 1]);
}

/*
 * Free the ldap result structure in the sudo_nss handle.
 */
static void
sudo_ldap_result_free_nss(struct sudo_nss *nss)
{
    struct sudo_ldap_handle *handle = nss->handle;
    debug_decl(sudo_ldap_result_free_nss, SUDOERS_DEBUG_LDAP)

    if (handle->result != NULL) {
	DPRINTF1("removing reusable search result");
	sudo_ldap_result_free(handle->result);
	handle->username = NULL;
	handle->gidlist = NULL;
	handle->result = NULL;
    }
    debug_return;
}

/*
 * Perform the LDAP query for the user or return a cached query if
 * there is one for this user.
 */
static struct ldap_result *
sudo_ldap_result_get(struct sudo_nss *nss, struct passwd *pw)
{
    struct sudo_ldap_handle *handle = nss->handle;
    struct ldap_config_str *base;
    struct ldap_result *lres;
    struct timeval tv, *tvp = NULL;
    LDAPMessage *entry, *result;
    LDAP *ld = handle->ld;
    int pass, rc;
    char *filt;
    debug_decl(sudo_ldap_result_get, SUDOERS_DEBUG_LDAP)

    /*
     * If we already have a cached result, return it so we don't have to
     * have to contact the LDAP server again.
     */
    if (handle->result) {
	if (handle->gidlist == user_gid_list &&
	    strcmp(pw->pw_name, handle->username) == 0) {
	    DPRINTF1("reusing previous result (user %s) with %d entries",
		handle->username, handle->result->nentries);
	    debug_return_ptr(handle->result);
	}
	/* User mismatch, cached result cannot be used. */
	DPRINTF1("removing result (user %s), new search (user %s)",
	    handle->username, pw->pw_name);
	sudo_ldap_result_free_nss(nss);
    }

    /*
     * Okay - time to search for anything that matches this user
     * Lets limit it to only two queries of the LDAP server
     *
     * The first pass will look by the username, groups, and
     * the keyword ALL.  We will then inspect the results that
     * came back from the query.  We don't need to inspect the
     * sudoUser in this pass since the LDAP server already scanned
     * it for us.
     *
     * The second pass will return all the entries that contain non-
     * Unix groups, including netgroups.  Then we take the non-Unix
     * groups returned and try to match them against the username.
     *
     * Since we have to sort the possible entries before we make a
     * decision, we perform the queries and store all of the results in
     * an ldap_result object.  The results are then sorted by sudoOrder.
     */
    lres = sudo_ldap_result_alloc();
    if (lres == NULL) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	debug_return_ptr(NULL);
    }
    for (pass = 0; pass < 2; pass++) {
	filt = pass ? sudo_ldap_build_pass2() : sudo_ldap_build_pass1(ld, pw);
	if (filt != NULL) {
	    DPRINTF1("ldap search '%s'", filt);
	    STAILQ_FOREACH(base, &ldap_conf.base, entries) {
		DPRINTF1("searching from base '%s'",
		    base->val);
		if (ldap_conf.timeout > 0) {
		    tv.tv_sec = ldap_conf.timeout;
		    tv.tv_usec = 0;
		    tvp = &tv;
		}
		result = NULL;
		rc = ldap_search_ext_s(ld, base->val, LDAP_SCOPE_SUBTREE, filt,
		    NULL, 0, NULL, NULL, tvp, 0, &result);
		if (rc != LDAP_SUCCESS) {
		    DPRINTF1("ldap search pass %d failed: %s", pass + 1,
			ldap_err2string(rc));
		    continue;
		}

		/* Add the search result to list of search results. */
		DPRINTF1("adding search result");
		if (sudo_ldap_result_add_search(lres, ld, result) == NULL) {
		    sudo_warnx(U_("%s: %s"), __func__,
			U_("unable to allocate memory"));
		    free(filt);
		    sudo_ldap_result_free(lres);
		    debug_return_ptr(NULL);
		}
		LDAP_FOREACH(entry, ld, result) {
		    /* Check user or non-unix group. */
		    if (pass && !sudo_ldap_check_non_unix_group(ld, entry, pw))
			continue;
		    lres->user_matches = true;
		    /* Check host. */
		    if (!sudo_ldap_check_host(ld, entry, pw))
			continue;
		    lres->host_matches = true;
		    if (sudo_ldap_result_add_entry(lres, entry) == NULL) {
			sudo_warnx(U_("%s: %s"), __func__,
			    U_("unable to allocate memory"));
			free(filt);
			sudo_ldap_result_free(lres);
			debug_return_ptr(NULL);
		    }
		}
		DPRINTF1("result now has %d entries", lres->nentries);
	    }
	    free(filt);
	} else if (errno != ENOENT) {
	    /* Out of memory? */
	    sudo_ldap_result_free(lres);
	    debug_return_ptr(NULL);
	}
    }

    /* Sort the entries by the sudoOrder attribute. */
    if (lres->nentries != 0) {
	DPRINTF1("sorting remaining %d entries", lres->nentries);
	qsort(lres->entries, lres->nentries, sizeof(lres->entries[0]),
	    ldap_entry_compare);
    }

    /* Store everything in the sudo_nss handle. */
    /* XXX - store pw and take a reference to it. */
    /* XXX - take refs for gidlist and grlist */
    handle->result = lres;
    handle->username = pw->pw_name;
    handle->gidlist = user_gid_list;

    debug_return_ptr(lres);
}

/*
 * Shut down the LDAP connection.
 */
static int
sudo_ldap_close(struct sudo_nss *nss)
{
    struct sudo_ldap_handle *handle = nss->handle;
    debug_decl(sudo_ldap_close, SUDOERS_DEBUG_LDAP)

    if (handle != NULL) {
	/* Free the result before unbinding; it may use the LDAP connection. */
	sudo_ldap_result_free_nss(nss);

	/* Unbind and close the LDAP connection. */
	if (handle->ld != NULL) {
	    ldap_unbind_ext_s(handle->ld, NULL, NULL);
	    handle->ld = NULL;
	}

	/* Free the handle container. */
	free(nss->handle);
	nss->handle = NULL;
    }
    debug_return_int(0);
}

/*
 * STUB
 */
static int
sudo_ldap_parse(struct sudo_nss *nss)
{
    return 0;
}

#if 0
/*
 * Create an ldap_result from an LDAP search result.
 *
 * This function is currently not used anywhere, it is left here as
 * an example of how to use the cached searches.
 */
static struct ldap_result *
sudo_ldap_result_from_search(LDAP *ldap, LDAPMessage *searchresult)
{
    struct ldap_search_result *last;
    struct ldap_result *result;
    LDAPMessage	*entry;

    /*
     * An ldap_result is built from several search results, which are
     * organized in a list. The head of the list is maintained in the
     * ldap_result structure, together with the wrappers that point
     * to individual entries, this has to be initialized first.
     */
    result = sudo_ldap_result_alloc();
    if (result == NULL) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	debug_return_ptr(NULL);
    }

    /*
     * Build a new list node for the search result, this creates the
     * list node.
     */
    last = sudo_ldap_result_add_search(result, ldap, searchresult);

    /*
     * Now add each entry in the search result to the array of of entries
     * in the ldap_result object.
     */
    LDAP_FOREACH(entry, last->ldap, last->searchresult) {
	if (sudo_ldap_result_add_entry(result, entry) == NULL) {
	    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	    sudo_ldap_result_free(result);
	    result = NULL;
	    break;
	}
    }
    DPRINTF1("sudo_ldap_result_from_search: %d entries found",
	result ? result->nentries : -1);
    return result;
}
#endif
