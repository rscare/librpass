#include <Python.h>
#include <gpgme.h>
#include <stdio.h>
#include <string.h>

#include "rGPG.h"

static PyObject *rGPGError;

static PyObject * encrypt_to_file(PyObject *self, PyObject *args) {
    gpgme_data_t plain_text = NULL;
    gpgme_data_t cipher_text = NULL;

    const char *contents = NULL;
    const char *filename = NULL;
    FILE *fp = NULL;

    PyObject * result = NULL;

    if (!PyArg_ParseTuple(args, "ss", &contents, &filename)) {
        PyErr_SetString(PyExc_TypeError, "Argument errors.");
        return NULL;
    }
    if (!(fp = fopen(filename, "wb"))) {
        PyErr_SetString(PyExc_IOError, "Unable to open file.");
        return NULL;
    }

    if (!create_gpg_data(&plain_text, NULL, contents, strlen(contents), 0)) {
        fclose(fp);
        PyErr_SetString(rGPGError, "Failed to allocate plain text buffer.");
        return NULL;
    }
    if (!create_gpg_data(&cipher_text, fp, NULL, 0, 0)) {
        fclose(fp);
        destroy_gpg_data(plain_text);
        PyErr_SetString(rGPGError, "Failed to allocate cipher text buffer.");
        return NULL;
    }
    if (!initialize_engine(0, NULL)) {
        destroy_gpg_data(cipher_text);
        fclose(fp);
        destroy_gpg_data(plain_text);
        PyErr_SetString(rGPGError, "Failed to initialize engine.");
        return NULL;
    }
    if (!encrypt_object(plain_text, cipher_text)) {
        destroy_gpg_data(cipher_text);
        fclose(fp);
        destroy_gpg_data(plain_text);
        destroy_engine();
        PyErr_SetString(rGPGError, "Failed to decrypt data.");
        return NULL;
    }

    destroy_gpg_data(cipher_text);
    fclose(fp);
    destroy_gpg_data(plain_text);
    destroy_engine();

    return Py_BuildValue("");
}

static PyObject * decrypt_from_file(PyObject *self, PyObject *args) {
    gpgme_data_t plain_text = NULL;
    gpgme_data_t cipher_text = NULL;

    const char *filename = NULL;
    FILE *fp = NULL;

    size_t len = 0;

    PyObject * result = NULL;

    if (!PyArg_ParseTuple(args, "s", &filename)) {
        PyErr_SetString(PyExc_TypeError, "Argument errors.");
        return NULL;
    }
    if (!(fp = fopen(filename, "rb"))) {
        PyErr_SetString(PyExc_IOError, "Unable to open file.");
        return NULL;
    }
    if (!create_gpg_data(&plain_text, NULL, NULL, 0, 0)) {
        fclose(fp);
        PyErr_SetString(rGPGError, "Unable to allocate plain text buffer.");
        return NULL;
    }
    if (!create_gpg_data(&cipher_text, fp, NULL, 0, 0)) {
        fclose(fp);
        destroy_gpg_data(plain_text);
        PyErr_SetString(rGPGError, "Unable to allocate cipher text buffer.");
        return NULL;
    }
    if (!initialize_engine(0, NULL)) {
        destroy_gpg_data(cipher_text);
        fclose(fp);
        destroy_gpg_data(plain_text);
        PyErr_SetString(rGPGError, "Unable to initialize engine.");
        return NULL;
    }
    if (!decrypt_object(cipher_text, plain_text)) {
        destroy_gpg_data(cipher_text);
        fclose(fp);
        destroy_gpg_data(plain_text);
        destroy_engine();
        PyErr_SetString(rGPGError, "Unable to decrypt cipher text.");
        return NULL;
    }

    destroy_gpg_data(cipher_text);
    fclose(fp);
    destroy_engine();

    result = Py_BuildValue("s", gpg_object_to_string(plain_text));
    destroy_gpg_data(plain_text);

    return result;
}

static PyMethodDef GPGMethods[] = {
    { "decrypt_file", decrypt_from_file, METH_VARARGS,
    "Decrypt info from a file into memory." },
    { "encrypt_file", encrypt_to_file, METH_VARARGS,
    "Encrypt info to a file from memory." },
    { NULL, NULL, 0, NULL }
};

static struct PyModuleDef rGPGmodule = {
    PyModuleDef_HEAD_INIT,
    "rGPG",
    NULL,
    -1,
    GPGMethods
};

PyMODINIT_FUNC PyInit_rGPG() {
    PyObject *m = PyModule_Create(&rGPGmodule);
    if (m == NULL)
        return NULL;

    rGPGError = PyErr_NewException("rGPG.rGPGError", NULL, NULL);
    Py_INCREF(rGPGError);
    PyModule_AddObject(m, "rGPGError", rGPGError);

    return m;
}
