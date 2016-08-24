#include <inttypes.h>
#include <stdbool.h>
#include <stdarg.h>
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
	Hardhat *hardhat;
	hardhat_cursor_t *c;
	bool recursive;
} HardhatCursor;

typedef struct {
	PyObject_HEAD
	uint64_t magic;
	Hardhat *hardhat;
	const char *buf;
	size_t len;
} HardhatValue;

typedef struct {
	PyObject_HEAD
	uint64_t magic;
	hardhat_maker_t *hhm;
} HardhatMaker;

static PyTypeObject Hardhat_type;
static PyTypeObject HardhatCursor_type;
static PyTypeObject HardhatMaker_type;

#define HARDHAT_MAGIC (UINT64_C(0x36CCB37946C40BBF))
#define HARDHAT_CURSOR_MAGIC (UINT64_C(0xE0B0487F7D045047))
#define HARDHAT_VALUE_MAGIC (UINT64_C(0xAAE89394CECC3DD8))
#define HARDHAT_MAKER_MAGIC (UINT64_C(0x5236CC4EFF9CAE19))

#define HARDHAT_FILE_FORMAT_ERROR "FileFormatError"

static struct PyModuleDef hardhat_module;

static inline bool Hardhat_is_valid(void *v) {
	return v && Py_TYPE(v) == &Hardhat_type && ((Hardhat *)v)->magic == HARDHAT_MAGIC;
}

static inline bool HardhatCursor_is_valid(void *v) {
	return v && Py_TYPE(v) == &HardhatCursor_type && ((HardhatCursor *)v)->magic == HARDHAT_CURSOR_MAGIC;
}

static inline bool HardhatValue_is_valid(void *v) {
	return v && Py_TYPE(v) == &HardhatValue_type && ((HardhatValue *)v)->magic == HARDHAT_VALUE_MAGIC;
}

static inline bool HardhatMaker_is_valid(void *v) {
	return v && Py_TYPE(v) == &HardhatMaker_type && ((HardhatMaker *)v)->magic == HARDHAT_MAKER_MAGIC;
}

__attribute__((unused))
static PyObject *hardhat_module_symbol(const char *name) {
	PyObject *module, *moduledict, *symbol = NULL, *type, *value, *traceback;
	PyErr_Fetch(&type, &value, &traceback);
	module = PyState_FindModule(&hardhat_module);
	if(module) {
		moduledict = PyModule_GetDict(module);
		if(moduledict)
			symbol = PyDict_GetItemString(moduledict, name);
	}
	PyErr_Restore(type, value, traceback);
	return symbol;
}

static PyObject *hardhat_module_create_exception(PyObject *module, const char *name) {
	PyObject *exception;
	char fullname[100];
	if(strlen(hardhat_module.m_name) + 1 + strlen(name) < sizeof fullname) {
		sprintf(fullname, "%s.%s", hardhat_module.m_name, name);
		exception = PyErr_NewException(fullname, NULL, NULL);
		PyModule_AddObject(module, name, exception);
		return exception;
	}
	return NULL;
}

// to avoid using global variables
static PyObject *hardhat_module_exception(const char *name) {
	PyObject *module, *moduledict, *exception = NULL, *type, *value, *traceback;
	PyErr_Fetch(&type, &value, &traceback);
	module = PyState_FindModule(&hardhat_module);
	if(module) {
		moduledict = PyModule_GetDict(module);
		if(moduledict)
			exception = PyDict_GetItemString(moduledict, name);
		if(!exception)
			exception = hardhat_module_create_exception(module, name);
	}
	PyErr_Restore(type, value, traceback);
	if(exception)
		return exception;
	return PyExc_Exception;
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

	Py_DecRef(decoded_filename);

	if(hh) {
		self = (Hardhat *)subtype->tp_alloc(subtype, 0);
		if(self) {
			self->magic = HARDHAT_MAGIC;
			self->hh = hh;
		}
	} else {
		if(errno == EPROTO) {
			PyErr_Format(hardhat_module_exception(HARDHAT_FILE_FORMAT_ERROR),
				"not a hardhat file: '%S'", filename);
		} else {
			PyErr_SetFromErrnoWithFilenameObject(PyExc_OSError, filename);
		}
	}

	return self;
}

static void Hardhat_finalize(Hardhat *self) {
	if(Hardhat_is_valid(self)) {
		self->magic = 0;
		Py_BEGIN_ALLOW_THREADS
		hardhat_close(self->hh);
		Py_END_ALLOW_THREADS
	}
}

static void Hardhat_dealloc(Hardhat *self) {
	Hardhat_finalize(self);
	PyObject_Del(self);
}

// Hardhat object methods

static PyObject *Hardhat_find(Hardhat *self, PyObject *args) {
	if(!PyArg_ParseTuple(args, ":find"))
		return NULL;
	Py_RETURN_NONE;
}

static PyObject *Hardhat_get(Hardhat *self, PyObject *args) {
	char *key;
	Pyssize_t len;
	PyObject *keyobject;
	Py_buffer keybuffer;
	char stackbuf[64];
	char *heapbuf = NULL;
	hardhat_cursor_t *c;
	HardhatValue *value;
	PyObject *bytes = NULL;

	if(PyArg_ParseTuple(args, "s#:__getitem__", &key, &len)) {
		if(len > UINT16_MAX)
			return PyErr_SetNone(PyExc_KeyError);
	} else {
		PyErr_Clear();
		if(!PyArg_ParseTuple(args, "s*:__getitem__", &keybuffer))
			return NULL;
		len = keybuffer.len;
		if(len > UINT16_MAX)
			return PyErr_SetNone(PyExc_KeyError);
		if(len < sizeof buf) {
			key = stackbuf;
		} else {
			heapbuf = malloc(len);
			if(!heapbuf)
				return PyErr_NoMemory();
			key = heapbuf;
		}
		memcpy(key, keybuffer.buf, len);
	}

	Py_BEGIN_ALLOW_THREADS
	c = hardhat_cursor(self->hh, key, len);
	Py_END_ALLOW_THREADS

	free(heapbuf);

	if(c) {
		if(c->data) {
			value = PyObject_New(HardhatValue, &HardhatValue_type);
			if(value) {
				Py_IncRef(self);
				value->hardhat = self;
				value->buf = c->datalen;
				value->len = c->len;
				bytes = PyBytes_FromObject(value);
				Py_DecRef(value);
			}
		} else {
			if(PyArg_ParseTuple(args, "O:__getitem__", &keyobject)) {
				PyErr_SetFormat(PyExc_KeyError, "'%S'", keyobject);
			} else {
				PyErr_Clear();
				PyErr_SetNone(PyExc_KeyError);
			}
		}
		hardhat_cursor_free(c);
	} else {
		PyErr_SetFromErrno(PyExc_OSError);
	}

	return bytes;
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
#ifndef Py_TPFLAGS_DEFAULT
	(destructor)Hardhat_dealloc,        // tp_dealloc
#endif
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
	Py_TPFLAGS_DEFAULT                  // tp_flags
#ifdef Py_TPFLAGS_HAVE_FINALIZE
		| Py_TPFLAGS_HAVE_FINALIZE
#endif
	,
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
	0,                                  // tp_bases
	0,                                  // tp_mro
	0,                                  // tp_cache
	0,                                  // tp_subclasses
	0,                                  // tp_weaklist
	0,                                  // tp_del
	0,                                  // tp_version_tag
#ifdef Py_TPFLAGS_HAVE_FINALIZE
	Hardhat_finalize,                   // tp_finalize;
#endif
};

// Hardhat object methods

static void Hardhat_dealloc(HardhatValue *self) {
	if(HardhatValue_is_valid(self)) {
		self->magic = 0;
		Py_DecRef(self->hardhat);
	}
}

static PyMethodDef HardhatValue_methods[] = {
	{NULL}
};

static PyTypeObject HardhatValue_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"hardhat.HardhatValue",             // tp_name
	sizeof(HardhatValue),               // tp_basicsize
	0,                                  // tp_itemsize
	(destructor)HardhatValue_dealloc,   // tp_dealloc
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
	HardhatValue_methods,               // tp_methods
	0,                                  // tp_members
	0,                                  // tp_getset
	0,                                  // tp_base
	0,                                  // tp_dict
	0,                                  // tp_descr_get
	0,                                  // tp_descr_set
	0,                                  // tp_dictoffset
	0,                                  // tp_init
	0,                                  // tp_alloc
	0,                                  // tp_new
	0,                                  // tp_free
	0,                                  // tp_is_gc
	0,                                  // tp_bases
	0,                                  // tp_mro
	0,                                  // tp_cache
	0,                                  // tp_subclasses
	0,                                  // tp_weaklist
	0,                                  // tp_del
	0,                                  // tp_version_tag
#ifdef Py_TPFLAGS_HAVE_FINALIZE
	0,                                  // tp_finalize;
#endif
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
	// ensure this exists:
	hardhat_module_create_exception(module, HARDHAT_FILE_FORMAT_ERROR);
	return module;
}
