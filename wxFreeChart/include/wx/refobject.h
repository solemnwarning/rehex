#ifndef REFOBJECT_H_
#define REFOBJECT_H_

/**
 * Object with reference counter.
 * TODO: This class was not part of this project. Use other way to count references.
 */
class WXDLLIMPEXP_FREECHART RefObject
{
public:
    RefObject()
    {
        refCount = 0;
    }

    virtual ~RefObject()
    {
        if (refCount > 0) {
            wxLogError(wxT("RefObject::~RefObject: object still have references. refCount=%i"), refCount);
        }
    }

    void AddRef()
    {
        refCount++;
    }

    void Unref()
    {
        refCount--;
        if (refCount < 0) {
            wxLogError(wxT("RefObject::Unref: refCount < 0"));
        }
    }

    int RefCount()
    {
        return refCount;
    }

private:
    int refCount;
};

#define SAFE_UNREF(ptr) do {                            \
    if (ptr != NULL) {                                    \
        ptr->Unref();                                    \
        if (ptr->RefCount() <= 0) {                        \
            delete ptr;                                    \
        }                                                \
    }                                                    \
    ptr = NULL;                                            \
} while (0)

#define SAFE_REPLACE_UNREF(dst, src) do {                \
    SAFE_UNREF(dst);                                    \
    if (src != NULL)                                    \
        ((RefObject *)src)->AddRef();                    \
    dst = src;                                            \
} while (0)

#define SAFE_UNREF_ELEMENTS(arrPtr, arrSize) do {    \
    if (arrPtr != NULL) {                                \
        for (int n = 0; n < arrSize; n++) {                \
            SAFE_UNREF(arrPtr[n]);                        \
        }                                                \
        wxDELETEA(arrPtr);                                \
    }                                                    \
} while (0)

#endif /*REFOBJECT_H_*/
