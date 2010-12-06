#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include "ubusd_id.h"

static int random_fd = -1;

static int ubus_cmp_id(const void *k1, const void *k2, void *ptr)
{
	const uint32_t *id1 = k1, *id2 = k2;

	if (*id1 < *id2)
		return -1;
	else
		return *id1 > *id2;
}

void ubus_init_id_tree(struct avl_tree *tree)
{
	if (random_fd < 0) {
		random_fd = open("/dev/urandom", O_RDONLY);
		if (random_fd < 0) {
			perror("open");
			exit(1);
		}
	}

	avl_init(tree, ubus_cmp_id, false, NULL);
}

bool ubus_alloc_id(struct avl_tree *tree, struct ubus_id *id)
{
	id->avl.key = &id->id;
	do {
		if (read(random_fd, &id->id, sizeof(id->id)) != sizeof(id->id))
			return false;

		if (!id->id)
			continue;
	} while (avl_insert(tree, &id->avl) != 0);

	return true;
}

