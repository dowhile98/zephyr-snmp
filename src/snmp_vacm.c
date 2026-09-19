/*
 * Copyright (c) 2026 DAECGE
 * SPDX-License-Identifier: Apache-2.0
 *
 * SNMPv3 View-based Access Control Model (RFC 3415).
 * Supports security-name → group mapping and per-group read/write views.
 */

#include <snmp/snmp_vacm.h>
#include <snmp/snmp_ber.h>
#include <snmp/snmp_mib.h>
#include <string.h>
#include <errno.h>

#if defined(CONFIG_SNMP_AGENT) && defined(CONFIG_SNMP_VERSION_3)

/* ---- Access right enum ---- */
typedef enum {
	VACM_ACCESS_NONE  = 0,
	VACM_ACCESS_READ  = 1,
	VACM_ACCESS_WRITE = 2,
	VACM_ACCESS_NOTIFY = 3,
} vacm_access_t;

/* ---- Static group table ---- */
#define VACM_MAX_GROUPS 8

struct vacm_group {
	char   name[32];
	bool   read_access;   /* GET / GETNEXT / GETBULK */
	bool   write_access;  /* SET */
	bool   notify_access; /* traps */
};

static struct vacm_group g_groups[VACM_MAX_GROUPS] = {
	{ .name = "admin",    .read_access = true,  .write_access = true,  .notify_access = true },
	{ .name = "readonly", .read_access = true,  .write_access = false, .notify_access = true },
};
static size_t g_group_cnt = 2;

/* ---- User → Group mapping ---- */
#define VACM_MAX_USER_MAP 16

struct vacm_user_map {
	char   user_name[32];
	char   group_name[32];
};

static struct vacm_user_map g_user_map[VACM_MAX_USER_MAP] = {
	{ .user_name = CONFIG_SNMP_V3_USER_NAME, .group_name = "admin" },
	{ .user_name = "monitor",                 .group_name = "readonly" },
};
static size_t g_user_map_cnt = 2;

/* ---- Internal helpers ---- */

static struct vacm_group *vacm_find_group(const char *name)
{
	for (size_t i = 0; i < g_group_cnt; i++) {
		if (strcmp(g_groups[i].name, name) == 0)
			return &g_groups[i];
	}
	return NULL;
}

static struct vacm_group *vacm_resolve_user(const char *user_name)
{
	if (!user_name)
		return NULL;

	/* Find user mapping */
	for (size_t i = 0; i < g_user_map_cnt; i++) {
		if (strcmp(g_user_map[i].user_name, user_name) == 0)
			return vacm_find_group(g_user_map[i].group_name);
	}

	/* Unknown user — default to no access */
	return NULL;
}

/* ---- Public API ---- */

int snmp_vacm_init(void)
{
	strncpy(g_user_map[0].user_name, CONFIG_SNMP_V3_USER_NAME, sizeof(g_user_map[0].user_name) - 1);
	g_user_map[0].user_name[sizeof(g_user_map[0].user_name) - 1] = '\0';
	return 0;
}

int snmp_vacm_add_user(const char *user_name, const char *group_name)
{
	if (!user_name || !group_name)
		return -EINVAL;
	if (g_user_map_cnt >= VACM_MAX_USER_MAP)
		return -ENOMEM;

	strncpy(g_user_map[g_user_map_cnt].user_name, user_name, sizeof(g_user_map[g_user_map_cnt].user_name) - 1);
	g_user_map[g_user_map_cnt].user_name[sizeof(g_user_map[g_user_map_cnt].user_name) - 1] = '\0';
	strncpy(g_user_map[g_user_map_cnt].group_name, group_name, sizeof(g_user_map[g_user_map_cnt].group_name) - 1);
	g_user_map[g_user_map_cnt].group_name[sizeof(g_user_map[g_user_map_cnt].group_name) - 1] = '\0';
	g_user_map_cnt++;
	return 0;
}

int snmp_vacm_check_access(const struct snmp_v3_msg *msg, bool is_write)
{
	if (!msg)
		return -EINVAL;

	char user_name[sizeof(msg->usm.user_name)];
	size_t name_len = msg->usm.user_name_len < sizeof(msg->usm.user_name)
			  ? msg->usm.user_name_len : sizeof(msg->usm.user_name) - 1;
	memcpy(user_name, msg->usm.user_name, name_len);
	user_name[name_len] = '\0';

	struct vacm_group *group = vacm_resolve_user(user_name);
	if (!group)
		return -EACCES;

	if (is_write && !group->write_access)
		return -EACCES;

	if (!is_write && !group->read_access)
		return -EACCES;

	return 0;
}

#endif /* CONFIG_SNMP_AGENT && CONFIG_SNMP_VERSION_3 */
