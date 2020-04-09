
typedef void PyObject;
typedef void PyDictObject;
typedef void PyListObject;
typedef void Py_None;

struct record_t
{
    char *name;
    int type; /* 1 for int, 0 for list. */
};

struct record_list_node
{
    struct record_t *record;
    struct record_list_node *next;
    int val; /* unused: Perhaps record_list_guard_t was same type as record_list_node. */
};

struct record_list_guard_t
{
    struct record_list_node *tail;
    struct record_list_node *head;
    int list_size;
}

struct type_handler_t
{
    struct record_list_guard_t *list;
    int ref_cnt;
};

struct type_handler_t *type_handlers[256];

int recordComparator(struct record_t *left, struct record_t *right)
{
    int res;

    res = strcmp(left->name, right->name);
    if (res == 0)
    {
        res = left->type < right->type;
    }
    return res;
}

struct record_t *newRecord(char *name, int type)
{
    struct record_t *new_record;

    new_record = malloc(sizeof(struct record_t));
    new_record->name = name;
    new_record->type = type;

    return new_record;
}

void createTypeHandler(struct record_t *record)
{
    for (int i = 0; i < 256; i++)
    {
        if (type_handlers[i])
            continue;

        type_handlers[i] = malloc(sizeof(struct type_handler_t));
        type_handlers[i]->record = record;
        type_handlers[i]->ref_cnt = 1;
        return;
    }

    PyErr_SetString(PyExc_TypeError, "COLLECTION FULL");
}

struct type_handler_t *getTypeHandler(record_list_guard_t *list)
{
    for (int i = 0; i < 256; i++)
    {
        if (type_handlers[i] == 0)
            continue;

        if (listIsEquivalent(type_handlers[i], list, recordComparator))
        {
            type_handlers[i]->ref_cnt += 1;
            return;
        }
    }

    createTypeHandler(list);
}

struct record_list_node *createNode(struct record_t *record)
{
    struct record_list_node *node;

    /* Looks like heap bug, but in fact malloc(8) should allocate 0x20 bytes. */
    node = malloc(8);
    node->record = record;
    node->next = NULL;
    return node;
}

struct record_list_guard_t *listCreate()
{
    struct record_list_guard_t *guard;

    /* Looks like heap bug, but in fact malloc(8) should allocate 0x20 bytes. */
    guard = malloc(8);
    memset(guard, 0x0, 24);
    return guard;
}

void listAppend(struct record_list_guard_t *guard, struct record_t *record)
{
    struct record_list_node *node;

    node = createNode(record);
    if (guard->list_size != 0)
    {
        /* List was not empty. */
        guard->tail->next = node;
        guard->tail = node;
        guard->list_size += 1;
        return;
    }

    /* List was empty. */
    guard->head = node;
    guard->tail = node;
    guard->list_size = 1;
}

int listIsEquivalent(struct record_list_guard_t *left, struct struct record_list_guard_t *right)
{
    if (left->list_size != right->list_size)
        return 0;

    /* TODO. */
}

int __init__(PyObject *self, PyObject *args)
{
    PyDictObject dict;
    PyListObject keys;
    PyObject *element, *key, *value;
    size_t keys_num, pos;
    struct record_list_guard_t *list;
    struct record_t *record;
    char *key_utf8;
    struct type_handler_t *type_handler;
    int val;

    if (PyArg_ParseTuple(args, "O!", PyDictType, &dict) == 0)
    {
        PyErr_SetString(PyExc_TypeError, "parameter must be a directory");
        return -1;
    }

    /* Test if all keys are strings. */
    keys = PyDict_Keys(dict);
    keys_num = PyList_Size(keys);
    for (int i = 0; i < keys_num; i++)
    {
        element = PyList_GetItem(keys, i);
        if ((element->_ob_prev[0xab] & 0x10) == 0)
        {
            PyErr_SetString(PyExc_TypeError, "parameter must be a string");
            return -1;
        }
    }

    list = listCreate();
    while (PyDict_Next(dict, &pos, &key, &value))
    {
        key_utf8 = PyUnicode_AsUTF8(key);
        if (value is not{integer, dict, list})
        {
            PyErr_SetString(PyExc_TypeError, "properties can only be either list, dictionary or an integer");
            return -1;
        }
        record = newRecord();
        listAppend(list, record);
    }

    /* Set values. */
    self->type_handler = getTypeHandler(list);
    while (PyDict_Next(dict, &pos, &key, &value))
    {
        Py_INCREF(value);
        PyUnicode_AsUTF8(key);
        if (value type is {list, dict} ) {
            self->values[pos] = value;
        } else {
            /* Extract int from PyObject type. */
            self->values[pos] = PyLong_AsLong(val);
        }
       
    }
}



PyObject *get(struct collection_t *self, PyObject *args) {
    char *key;
    int idx, act_idx, res;
    struct record_list_node *node;

    PyArg_ParseTuple(args, "s", &key);


    idx = listIndexOf(self->list, key, recordNameComparator);
    if (idx == -1) {
        return Py_None;
    }

    node = self->list->tail;
    act_idx = 0;
    while (node && act_idx < idx) {
        node = node->next;
        act_idx += 1;
    }

    res = self->values[idx];
    if (node->record->type == 1) {
        /* If type is int, then pack it into PyObject. */
        return PyLong_FromLong(res);
    }

    return Py_None;
}




PyObject* PyInit_Collection() {  
    PyObject *module;

    PyType_Ready(&type);
    module = PyModule_Create2(&def,0x3f5);
    if (module != 0) {
        _type = _type + 1;
        PyModule_AddObject(module,0x102740,&type);
        mprotect((void *)0x439000,1,7);
        [...]
        mprotect((void *)0x439000,1,5);
        init_sandbox(); /* setting seccomp rules */
    }
    return module;
}