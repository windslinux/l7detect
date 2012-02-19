#include "stdio.h"
#include "string.h"
#include "mpse.h"
#include "str_search.h"

int match_back(void* id, void * tree, int index, void *data, void *neg_list)
{
	printf("in callback id=%d, index=%d, data=%s, neg_list=%p\n", (int)id, index, (char *)data, neg_list);
	if ((int)id == 0) {
		char *str = (char *)data;
#if 0
		if (index != strlen(str)-2) {
			return -1;
		} else {
			printf("found id1 in index %d\n", index);
		}
#endif
	}
    return -1;
}
int main()
{
	int pattern_id = 0;
	char pattern[] = {0x00, 0x03};
	char *pattern2 = "zhou";

	char content[] = {0x01, 0x02, 0x00, 0x03, 0x05};
	int mpse_id = 0;
	int result;

	result = search_api->search_init(1, MPSE_AC_BNFA);
	printf("init result %d\n", result);
	search_api->search_add(mpse_id, pattern, sizeof(pattern), (int)(unsigned long)(pattern_id++));
	search_api->search_add(mpse_id, pattern2, strlen(pattern2), (int)(unsigned long)(pattern_id++));
	printf("add result %d\n", result);
	search_api->search_prep(mpse_id);
	printf("compile result %d\n", result);
	result = search_api->search_find(mpse_id, content, sizeof(content), 0, match_back);
	printf("find result %d\n", result);
	return 0;
}
