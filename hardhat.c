#include <inttypes.h>
#include <stdbool.h>
#include <hardhat/reader.h>
#include <hardhat/maker.h>

#include "Python.h"

typedef struct {
	PyObject_HEAD
	uint64_t magic;
	hardhat_t *hh;
} HardhatObject;

typedef struct {
	PyObject_HEAD
	uint64_t magic;
	hardhat_cursor_t *c;
	bool recursive;
} HardhatCursorObject;

typedef struct {
	PyObject_HEAD
	uint64_t magic;
	hardhat_maker_t *hhm;
} HardhatMakerObject;

static PyTypeObject HardhatObject_type;
static PyTypeObject HardhatCursorObject_type;
static PyTypeObject HardhatMakerObject_type;

#define HARDHAT_MAGIC (UINT64_C(0x36CCB37946C40BBF))
#define HARDHAT_MAKER_MAGIC (UINT64_C(0x5236CC4EFF9CAE19))
#define HARDHAT_CURSOR_MAGIC (UINT64_C(0xE0B0487F7D045047))

static inline bool HardhatObject_is_valid(void *v) {
	return v && Py_TYPE(v) == &HardhatObject_type && ((HardhatObject *)v)->magic == HARDHAT_MAGIC;
}

static inline bool HardhatCursorObject_is_valid(void *v) {
	return v && Py_TYPE(v) == &HardhatCursorObject_type && ((HardhatCursorObject *)v)->magic == HARDHAT_CURSOR_MAGIC;
}

static inline bool HardhatMakerObject_is_valid(void *v) {
	return v && Py_TYPE(v) == &HardhatMakerObject_type && ((HardhatMakerObject *)v)->magic == HARDHAT_MAKER_MAGIC;
}

static HardhatObject *HardhatObject_new(PyTypeObject *subtype, PyObject *args, PyObject *kwds) {
	HardhatObject *self = (HardhatObject *)subtype->tp_alloc(subtype, 0);
	if(self) {
		self->magic = HARDHAT_MAGIC;
		self->hh = NULL;
	}
	return self;
}

static void HardhatObject_dealloc(HardhatObject *self) {
	if(HardhatObject_is_valid(self)) {
		self->magic = 0;
		/* hardhat_close(self->hardhat); */
	}
	PyObject_Del(self);
}

/* Hardhat methods */

static PyObject *HardhatObject_find(HardhatObject *self, PyObject *args) {
	if(!PyArg_ParseTuple(args, ":derp"))
		return NULL;
    Py_RETURN_NONE;
}

static PyMethodDef HardhatObject_methods[] = {
	{"find", (PyCFunction)HardhatObject_find, METH_VARARGS, "return a recursive cursor"},
	{NULL}
};

static PyTypeObject HardhatObject_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"hardhat.Hardhat",                  /*tp_name*/
	sizeof(HardhatObject),              /*tp_basicsize*/
	0,                                  /*tp_itemsize*/
	/* methods */
	(destructor)HardhatObject_dealloc,  /*tp_dealloc*/
	0,                                  /*tp_print*/
	0,                                  /*tp_getattr*/
	0,                                  /*tp_setattr*/
	0,                                  /*tp_reserved*/
	0,                                  /*tp_repr*/
	0,                                  /*tp_as_number*/
	0,                                  /*tp_as_sequence*/
	0,                                  /*tp_as_mapping*/
	0,                                  /*tp_hash*/
	0,                                  /*tp_call*/
	0,                                  /*tp_str*/
	0,                                  /*tp_getattro*/
	0,                                  /*tp_setattro*/
	0,                                  /*tp_as_buffer*/
	Py_TPFLAGS_DEFAULT,                 /*tp_flags*/
	0,                                  /*tp_doc*/
	0,                                  /*tp_traverse*/
	0,                                  /*tp_clear*/
	0,                                  /*tp_richcompare*/
	0,                                  /*tp_weaklistoffset*/
	0,                                  /*tp_iter*/
	0,                                  /*tp_iternext*/
	HardhatObject_methods,              /*tp_methods*/
	0,                                  /*tp_members*/
	0,                                  /*tp_getset*/
	0,                                  /*tp_base*/
	0,                                  /*tp_dict*/
	0,                                  /*tp_descr_get*/
	0,                                  /*tp_descr_set*/
	0,                                  /*tp_dictoffset*/
	0,                                  /*tp_init*/
	0,                                  /*tp_alloc*/
	(newfunc)HardhatObject_new,         /*tp_new*/
	0,                                  /*tp_free*/
	0,                                  /*tp_is_gc*/
};

static PyObject *Hardhat_normalize(HardhatObject *self, PyObject *args) {
	if(!PyArg_ParseTuple(args, ":derp"))
		return NULL;
    Py_RETURN_NONE;
}

static PyMethodDef Hardhat_functions[] = {
	{"normalize", (PyCFunction)Hardhat_normalize, METH_VARARGS, "return a normalized bytes object"},
	{NULL}
};

PyDoc_STRVAR(Hardhat_doc, "Python wrapper for the hardhat library");

static struct PyModuleDef Hardhat_module = {
	PyModuleDef_HEAD_INIT,
	"hardhat",
	Hardhat_doc,
	-1,
	Hardhat_functions,
	NULL,
	NULL,
	NULL,
	NULL
};

PyMODINIT_FUNC PyInit_hardhat(void) {
	if(PyType_Ready(&HardhatObject_type) == -1)
		return NULL;
	return PyModule_Create(&Hardhat_module);
}
