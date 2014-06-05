#ifndef KSI_LIST_H_
#define KSI_LIST_H_

#ifdef __cplusplus
extern "C" {
#endif

	void KSI_List_free(KSI_List *list);
	int KSI_List_new(void (*obj_free)(void *), KSI_List **list);
	int KSI_List_append(KSI_List *list, void *obj);
	int KSI_List_remove(KSI_List *list, unsigned int pos);
	int KSI_List_iter(KSI_List *list);
	int KSI_List_next(KSI_List *list, void **o);
	int KSI_List_indexOf(const KSI_List *list, const void *o);
	int KSI_List_insertAt(KSI_List *list, unsigned int pos, void *o);
	int KSI_List_replaceAt(KSI_List *list, unsigned int pos, void *o);
	int KSI_List_elementAt(const KSI_List *list, unsigned int pos, void **o);
	int KSI_List_length(const KSI_List *list);


#ifdef __cplusplus
}
#endif

#endif /* KSI_LIST_H_ */
