/*
 * Written by Moskvichev A.V.
 * PUBLIC DOMAIN
 */

#ifndef PATTERNS_OBSERVABLE_H
#define PATTERNS_OBSERVABLE_H

#include <vector>

/**
 * This template defines Observable object pattern.
 */
template<class O> class Observable
{
public:
    typedef O Observer;
    typename std::vector<O*>::iterator OIt;

    Observable()
    {
    }

    void AddObserver(O *_observer)
    {
        for (typename std::vector<O*>::iterator it = observers.begin();
             it < observers.end(); it++) {
            if (*it == _observer)
                return ;
        }
        observers.push_back(_observer);
    }

    void RemoveObserver(O *_observer)
    {
        for (typename std::vector<O*>::iterator it = observers.begin();
             it < observers.end(); it++) {
            if (*it == _observer) {
                observers.erase(it);
                return ;
            }
        }
    }

protected:
    std::vector<O*> observers;
};

#define DECLARE_FIRE(proc) void Fire##proc();

#define DEFINE_FIRE(cls, proc) void cls :: Fire##proc()            \
{                                                                    \
    for (std::vector<Observer*>::iterator it = observers.begin();    \
         it < observers.end(); it++)                                \
        (*it)->proc();                                                \
}

#define DECLARE_FIRE_WITH_VALUE(proc, type, value) void Fire##proc(type value);

#define DEFINE_FIRE_WITH_VALUE(cls, proc, type, value) void cls :: Fire##proc(type value)    \
{                                                                                            \
    for (std::vector<Observer*>::iterator it = observers.begin();                            \
         it < observers.end(); it++)                                                        \
        (*it)->proc(value);                                                                    \
}

#define FIRE_WITH_VALUE(proc, type, value) void Fire##proc(type value)    \
{                                                                                            \
    for (std::vector<Observer*>::iterator it = observers.begin();                            \
         it < observers.end(); it++)                                                        \
        (*it)->proc(value);                                                                    \
}

#define FIRE_WITH_VALUE2(proc, type1, value1, type2, value2) void Fire##proc(type1 value1, type2 value2)    \
{                                                                                            \
    for (std::vector<Observer*>::iterator it = observers.begin();                            \
         it < observers.end(); it++)                                                        \
        (*it)->proc(value1, value2);                                                                    \
}


#define DECLARE_FIRE_WITH_THIS(proc) void Fire##proc();

#define DEFINE_FIRE_WITH_THIS(cls, proc) void cls :: Fire##proc()    \
{                                                                    \
    for (std::vector<Observer*>::iterator it = observers.begin();    \
         it < observers.end(); it++)                                \
        (*it)->proc(this);                                            \
}

#define FIRE_WITH_THIS(proc) void Fire##proc()                        \
{                                                                    \
    for (std::vector<Observer*>::iterator it = observers.begin();    \
         it < observers.end(); it++)                                \
        (*it)->proc(this);                                            \
}

#define FIRE_VOID(proc) void Fire##proc()                        \
{                                                                    \
    for (std::vector<Observer*>::iterator it = observers.begin();    \
         it < observers.end(); it++)                                \
        (*it)->proc();                                            \
}

#define SAFE_REPLACE_OBSERVER(O, oldO, newO) do {                    \
    if (oldO != NULL) {                                                \
        oldO->RemoveObserver(O);                                    \
    }                                                                \
                                                                    \
    if (newO != NULL) {                                                \
        newO->AddObserver(O);                                        \
    }                                                                \
} while (0)

#define SAFE_REMOVE_OBSERVER(O, oldO) do {                            \
    if (oldO != NULL) {                                                \
        oldO->RemoveObserver(O);                                    \
    }                                                                \
} while (0)

#endif /* PATTERNS_OBSERVABLE_H */
