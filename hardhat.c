#include <inttypes.h>
#include <stdbool.h>
#include <hardhat/reader.h>
#include <hardhat/maker.h>

#include "Python.h"

typedef struct {
	PyObject_HEAD
	uint64_t magic;
	hardhat_t *hh;
} Hardhat;

typedef struct {
	PyObject_HEAD
	uint64_t magic;
	hardhat_cursor_t *c;
	bool recursive;
} HardhatCursor;

typedef struct {
	PyObject_HEAD
	uint64_t magic;
	hardhat_maker_t *hhm;
} HardhatMaker;

static PyTypeObject Hardhat_type;
static PyTypeObject HardhatCursor_type;
static PyTypeObject HardhatMaker_type;

#define HARDHAT_MAGIC (UINT64_C(0x36CCB37946C40BBF))
#define HARDHAT_MAKER_MAGIC (UINT64_C(0x5236CC4EFF9CAE19))
#define HARDHAT_CURSOR_MAGIC (UINT64_C(0xE0B0487F7D045047))

static inline bool Hardhat_is_valid(void *v) {
	return v && Py_TYPE(v) == &Hardhat_type && ((Hardhat *)v)->magic == HARDHAT_MAGIC;
}

static inline bool HardhatCursor_is_valid(void *v) {
	return v && Py_TYPE(v) == &HardhatCursor_type && ((HardhatCursor *)v)->magic == HARDHAT_CURSOR_MAGIC;
}

static inline bool HardhatMaker_is_valid(void *v) {
	return v && Py_TYPE(v) == &HardhatMaker_type && ((HardhatMaker *)v)->magic == HARDHAT_MAKER_MAGIC;
}

static Hardhat *Hardhat_new(PyTypeObject *subtype, PyObject *args, PyObject *kwds) {
	Hardhat *self = NULL;
	PyObject *filename, *decoded_filename;
	hardhat_t *hh;

	if(!PyArg_ParseTuple(args, "O:new", &filename))
		return NULL;

	if(!PyUnicode_FSConverter(filename, &decoded_filename))
		return NULL;

	Py_BEGIN_ALLOW_THREADS

	hh = hardhat_open(PyBytes_AsString(decoded_filename));

	Py_END_ALLOW_THREADS

	Py_XDECREF(decoded_filename);

	if(hh) {
		self = (Hardhat *)subtype->tp_alloc(subtype, 0);
		if(self) {
			self->magic = HARDHAT_MAGIC;
			self->hh = hh;
		}
	} else {
		PyErr_SetFromErrnoWithFilenameObject(PyExc_OSError, filename);
	}

	return self;
}

static void Hardhat_dealloc(Hardhat *self) {
	if(Hardhat_is_valid(self)) {
		self->magic = 0;
		hardhat_close(self->hh);
	}
	PyObject_Del(self);
}

// Hardhat object methods

static PyObject *Hardhat_find(Hardhat *self, PyObject *args) {
	if(!PyArg_ParseTuple(args, ":find"))
		return NULL;
    Py_RETURN_NONE;
}

static PyMethodDef Hardhat_methods[] = {
	{"find", (PyCFunction)Hardhat_find, METH_VARARGS, "return a recursive cursor"},
	{NULL}
};

static PyTypeObject Hardhat_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"hardhat.Hardhat",                  // tp_name
	sizeof(Hardhat),                    // tp_basicsize
	0,                                  // tp_itemsize
	(destructor)Hardhat_dealloc,        // tp_dealloc
	0,                                  // tp_print
	0,                                  // tp_getattr
	0,                                  // tp_setattr
	0,                                  // tp_reserved
	0,                                  // tp_repr
	0,                                  // tp_as_number
	0,                                  // tp_as_sequence
	0,                                  // tp_as_mapping
	0,                                  // tp_hash
	0,                                  // tp_call
	0,                                  // tp_str
	0,                                  // tp_getattro
	0,                                  // tp_setattro
	0,                                  // tp_as_buffer
	Py_TPFLAGS_DEFAULT,                 // tp_flags
	0,                                  // tp_doc
	0,                                  // tp_traverse
	0,                                  // tp_clear
	0,                                  // tp_richcompare
	0,                                  // tp_weaklistoffset
	0,                                  // tp_iter
	0,                                  // tp_iternext
	Hardhat_methods,                    // tp_methods
	0,                                  // tp_members
	0,                                  // tp_getset
	0,                                  // tp_base
	0,                                  // tp_dict
	0,                                  // tp_descr_get
	0,                                  // tp_descr_set
	0,                                  // tp_dictoffset
	0,                                  // tp_init
	0,                                  // tp_alloc
	(newfunc)Hardhat_new,               // tp_new
	0,                                  // tp_free
	0,                                  // tp_is_gc
};

// Hardhat module functions

static PyObject *hardhat_module_normalize(PyObject *self, PyObject *args) {
	if(!PyArg_ParseTuple(args, ":derp"))
		return NULL;
    Py_RETURN_NONE;
}

static PyMethodDef hardhat_module_functions[] = {
	{"normalize", hardhat_module_normalize, METH_VARARGS, "return a normalized bytes object"},
	{NULL}
};

PyDoc_STRVAR(hardhat_module_doc, "Python wrapper for the hardhat library");

static struct PyModuleDef hardhat_module = {
	PyModuleDef_HEAD_INIT,
	"hardhat",
	hardhat_module_doc,
	-1,
	hardhat_module_functions,
	NULL,
	NULL,
	NULL,
	NULL
};

PyMODINIT_FUNC PyInit_hardhat(void) {
	if(PyType_Ready(&Hardhat_type) == -1)
		return NULL;
	PyObject *module = PyModule_Create(&hardhat_module);
	if(module)
		PyModule_AddObject(module, "Hardhat", (PyObject *)&Hardhat_type);
	return module;
}
