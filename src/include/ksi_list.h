#ifndef KSI_LIST_H_
#define KSI_LIST_H_

#ifdef __cplusplus
extern "C" {
#endif

	void KSI_List_free(KSI_List *list);
	int KSI_List_new(void (*obj_free)(void *), KSI_List **list);
	int KSI_List_append(KSI_List *list, void *obj);
	int KSI_List_remove(KSI_List *list, int pos);
	int KSI_List_iter(KSI_List *list);
	int KSI_List_next(KSI_List *list, void **o);
	int KSI_List_indexOf(KSI_List *list, void *o);
	int KSI_List_insertAt(KSI_List *list, int pos, void *o);
	int KSI_List_elementAt(KSI_List *list, int pos, void **o);
	int KSI_List_length(KSI_List *list);
	int KSI_List_get(KSI_List *list, int pos, void **o);


#ifdef __cplusplus
}
#endif

#endif /* KSI_LIST_H_ */
