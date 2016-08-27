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
	hardhat_cursor_t *hhc;
	bool recursive;
	bool keys;
	bool values;
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
#define HARDHAT_CURSOR_MAGIC (UINT64_C(0xE0B0487F7D045047))
#define HARDHAT_VALUE_MAGIC (UINT64_C(0xAAE89394CECC3DD8))
#define HARDHAT_MAKER_MAGIC (UINT64_C(0x5236CC4EFF9CAE19))

#define HARDHAT_INTERNAL_ERROR "InternalError"
#define HARDHAT_FILE_FORMAT_ERROR "FileFormatError"

static struct PyModuleDef hardhat_module;

static inline bool Hardhat_check(void *v) {
	return v && Py_TYPE(v) == &Hardhat_type && ((Hardhat *)v)->magic == HARDHAT_MAGIC;
}

static inline bool HardhatCursor_check(void *v) {
	return v && Py_TYPE(v) == &HardhatCursor_type && ((HardhatCursor *)v)->magic == HARDHAT_CURSOR_MAGIC;
}

static inline bool HardhatMaker_check(void *v) {
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
	PyObject *filename_object, *decoded_filename;
	const char *filename;
	hardhat_t *hh;

	if(!PyArg_ParseTuple(args, "O:new", &filename_object))
		return NULL;

	if(PyUnicode_Check(filename_object)) {
		if(!PyUnicode_FSConverter(filename_object, &decoded_filename))
			return NULL;
	} else if(PyBytes_Check(filename_object)) {
		decoded_filename = filename_object;
		Py_IncRef(decoded_filename);
	} else {
		decoded_filename = PyBytes_FromObject(filename_object);
		if(!decoded_filename)
			return NULL;
	}

	filename = PyBytes_AsString(decoded_filename);
	if(!filename) {
		Py_DecRef(decoded_filename);
		return NULL;
	}

	Py_BEGIN_ALLOW_THREADS

	hh = hardhat_open(filename);

	Py_END_ALLOW_THREADS

	Py_DecRef(decoded_filename);

	if(hh) {
		self = PyObject_New(Hardhat, subtype);
		if(self) {
			self->magic = HARDHAT_MAGIC;
			self->hh = hh;
		}
	} else {
		if(errno == EPROTO) {
			PyErr_Format(hardhat_module_exception(HARDHAT_FILE_FORMAT_ERROR),
				"not a hardhat file: '%S'", filename_object);
		} else {
			PyErr_SetFromErrnoWithFilenameObject(PyExc_OSError, filename_object);
		}
	}

	return self;
}

static void Hardhat_dealloc(Hardhat *self) {
	if(Hardhat_check(self)) {
		self->magic = 0;
		Py_BEGIN_ALLOW_THREADS
		hardhat_close(self->hh);
		Py_END_ALLOW_THREADS
	}

	PyObject_Del(self);
}

// Hardhat object methods

static bool Hardhat_object_to_buffer(PyObject *obj, Py_buffer *buffer) {
	char *str;
	Py_ssize_t len;

	if(PyUnicode_Check(obj)) {
		str = PyUnicode_AsUTF8AndSize(obj, &len);
		if(!str)
			return false;
		PyBuffer_FillInfo(buffer, obj, str, len, 1, 0);
	} else {
		if(PyObject_GetBuffer(obj, buffer, PyBUF_SIMPLE) == -1)
			return false;

		if(!PyBuffer_IsContiguous(buffer, 'C')) {
			PyBuffer_Release(buffer);
			PyErr_SetString(PyExc_BufferError, "buffer not contiguous");
			return false;
		}
	}
	return true;
}

static PyObject *Hardhat_cursor(Hardhat *self, PyObject *keyobject, bool recursive, bool keys, bool values) {
	Py_buffer keybuffer;
	hardhat_cursor_t *c;
	HardhatCursor *cursor = NULL;

	if(!Hardhat_object_to_buffer(keyobject, &keybuffer))
		return NULL;

	if(keybuffer.len > UINT16_MAX) {
		PyBuffer_Release(&keybuffer);
		return PyErr_SetString(PyExc_KeyError, "supplied key too long"), NULL;
	}

	Py_BEGIN_ALLOW_THREADS
	c = hardhat_cursor(self->hh, keybuffer.buf, keybuffer.len);
	Py_END_ALLOW_THREADS

	PyBuffer_Release(&keybuffer);

	if(c) {
		cursor = PyObject_New(HardhatCursor, &HardhatCursor_type);
		if(cursor) {
			Py_IncRef(&self->ob_base);
			cursor->hardhat = self;
			cursor->hhc = c;
			cursor->recursive = recursive;
			cursor->keys = keys;
			cursor->values = values;
			cursor->magic = HARDHAT_CURSOR_MAGIC;
			return &cursor->ob_base;
		}
		hardhat_cursor_free(c);
	} else {
		PyErr_SetFromErrno(PyExc_OSError);
	}

	return NULL;
}

static PyObject *Hardhat_ls(Hardhat *self, PyObject *keyobject) {
	return (PyObject *)Hardhat_cursor(self, keyobject, false, true, true);
}

static PyObject *Hardhat_find(Hardhat *self, PyObject *keyobject) {
	return (PyObject *)Hardhat_cursor(self, keyobject, true, true, true);
}

static PyObject *Hardhat_getitem(Hardhat *self, PyObject *keyobject) {
	PyObject *view = NULL;
	HardhatCursor *cursor = (HardhatCursor *)Hardhat_cursor(self, keyobject, false, false, true);
	if(!cursor)
		return NULL;
	if(cursor->hhc->data)
		view = PyMemoryView_FromObject(&cursor->ob_base);
	else
		PyErr_Format(PyExc_KeyError, "'%S'", keyobject);
	Py_DecRef(&cursor->ob_base);
	return view;
}

static PyMappingMethods Hardhat_as_mapping = {
	0,                                  // mp_length
	(binaryfunc)Hardhat_getitem,        // mp_subscript
	0,                                  // mp_subscript
};

static PyMethodDef Hardhat_methods[] = {
	{"ls", (PyCFunction)Hardhat_ls, METH_O, "return a non-recursive cursor"},
	{"find", (PyCFunction)Hardhat_find, METH_O, "return a recursive cursor"},
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
	&Hardhat_as_mapping,                // tp_as_mapping
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
	0,                                  // tp_bases
	0,                                  // tp_mro
	0,                                  // tp_cache
	0,                                  // tp_subclasses
	0,                                  // tp_weaklist
	0,                                  // tp_del
	0,                                  // tp_version_tag
};

// Hardhat object methods

static int HardhatCursor_getbuffer(HardhatCursor *self, Py_buffer *buffer, int flags) {
	hardhat_cursor_t *hhc;
	if(HardhatCursor_check(self)) {
		hhc = self->hhc;
		if(hhc->data)
			return PyBuffer_FillInfo(buffer, &self->hardhat->ob_base, (char *)hhc->data, hhc->datalen, 1, flags);
		else
			PyErr_SetString(PyExc_BufferError, "HardhatCursor object doesn't currently point at an entry");
	} else {
		PyErr_SetString(PyExc_BufferError, "not a valid HardhatCursor object");
	}
	buffer->obj = NULL;
	return -1;
}

static PyObject *HardhatCursor_iternext(HardhatCursor *self) {
	hardhat_cursor_t *hhc;
	PyObject *keyobject, *valueobject, *tupleobject;
	if(HardhatCursor_check(self)) {
		hhc = self->hhc;
		if(hardhat_fetch(hhc, self->recursive)) {
			if(self->keys) {
				keyobject = PyBytes_FromStringAndSize(hhc->key, hhc->keylen);
				if(!keyobject)
					return NULL;
				if(self->values) {
					valueobject = PyMemoryView_FromObject(&self->ob_base);
					if(valueobject) {
						tupleobject = PyTuple_Pack(2, keyobject, valueobject);
						Py_DecRef(valueobject);
					} else {
						tupleobject = NULL;
					}
					Py_DecRef(keyobject);
					return tupleobject;
				} else {
					return keyobject;
				}
			} else {
				if(self->values)
					return PyMemoryView_FromObject(&self->ob_base);
				else
					return PyErr_SetString(hardhat_module_exception(HARDHAT_FILE_FORMAT_ERROR),
						"internal error in HardhatCursor_iternext()"), NULL;
			}
		} else {
			return NULL;
		}
	} else {
		PyErr_SetString(PyExc_TypeError, "not a valid HardhatCursor object");
		return NULL;
	}
}

static void HardhatCursor_dealloc(HardhatCursor *self) {
	if(HardhatCursor_check(self)) {
		self->magic = 0;
		Py_DecRef(&self->hardhat->ob_base);
	}
}

static PyMethodDef HardhatCursor_methods[] = {
	{NULL}
};

static PyBufferProcs HardhatCursor_as_buffer = {
	(getbufferproc)HardhatCursor_getbuffer,    // bf_getbuffer
	0,                                         // bf_releasebuffer
};

static PyTypeObject HardhatCursor_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"hardhat.HardhatCursor",                   // tp_name
	sizeof(HardhatCursor),                     // tp_basicsize
	0,                                         // tp_itemsize
	(destructor)HardhatCursor_dealloc,         // tp_dealloc
	0,                                         // tp_print
	0,                                         // tp_getattr
	0,                                         // tp_setattr
	0,                                         // tp_reserved
	0,                                         // tp_repr
	0,                                         // tp_as_number
	0,                                         // tp_as_sequence
	0,                                         // tp_as_mapping
	0,                                         // tp_hash
	0,                                         // tp_call
	0,                                         // tp_str
	0,                                         // tp_getattro
	0,                                         // tp_setattro
	&HardhatCursor_as_buffer,                  // tp_as_buffer
	Py_TPFLAGS_DEFAULT,                        // tp_flags
	0,                                         // tp_doc
	0,                                         // tp_traverse
	0,                                         // tp_clear
	0,                                         // tp_richcompare
	0,                                         // tp_weaklistoffset
	PyObject_SelfIter,                         // tp_iter
	(iternextfunc)HardhatCursor_iternext,      // tp_iternext
	HardhatCursor_methods,                     // tp_methods
	0,                                         // tp_members
	0,                                         // tp_getset
	0,                                         // tp_base
	0,                                         // tp_dict
	0,                                         // tp_descr_get
	0,                                         // tp_descr_set
	0,                                         // tp_dictoffset
	0,                                         // tp_init
	0,                                         // tp_alloc
	0,                                         // tp_new
	0,                                         // tp_free
	0,                                         // tp_is_gc
	0,                                         // tp_bases
	0,                                         // tp_mro
	0,                                         // tp_cache
	0,                                         // tp_subclasses
	0,                                         // tp_weaklist
	0,                                         // tp_del
	0,                                         // tp_version_tag
#ifdef Py_TPFLAGS_HAVE_FINALIZE
	0,                                         // tp_finalize;
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
		PyModule_AddObject(module, "Hardhat", &Hardhat_type.ob_base.ob_base);
	// ensure this exists:
	hardhat_module_create_exception(module, HARDHAT_INTERNAL_ERROR);
	hardhat_module_create_exception(module, HARDHAT_FILE_FORMAT_ERROR);
	return module;
}
