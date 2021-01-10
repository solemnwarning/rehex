--
-- Adapted from http://lua-users.org/wiki/ObjectOrientationTutorial
--
-- The "class" function is called with one or more tables that specify the base
-- classes.
--
-- If the user provides an "_init" method, this will be used as the class
-- constructor.
--
-- Each class also provides Python-style properties, which are implemented as
-- tables that provide a "get" and "set" method.
--

local Class = {}

function Class.class(...)
    -- "cls" is the new class
    local cls, bases = {}, {...}

    -- Copy base class contents into the new class
    for _, base in ipairs(bases) do
        for k, v in pairs(base) do
            cls[k] = v
        end
    end

    -- Class also provides Python-style properties. These are implemented as
    -- tables with a "get" and "set" method
    cls.property = {}

    function cls:__index(key)
        local property = cls.property[key]

        if property then
            return property.get(self)
        else
            return cls[key]
        end

        return member
    end

    function cls:__newindex(key, value)
        local property = cls.property[key]

        if property then
            return property.set(self, value)
        else
            return rawset(self, key, value)
        end
    end

    -- Start filling an "is_a" table that contains this class and all of its
    -- bases so you can do an "instance of" check using
    -- my_instance.is_a[MyClass]
    cls.is_a = { [cls] = true }
    for i, base in ipairs(bases) do
        for c in pairs(base.is_a) do
            cls.is_a[c] = true
        end
        cls.is_a[base] = true
    end

    -- The class's __call metamethod
    setmetatable(cls, {
        __call = function(c, ...)
            local instance = setmetatable({}, c)
            -- Run the "init" method if it's there
            local init = instance._init
            if init then init(instance, ...) end

            return instance
        end
    })

    -- Return the new class table, that's ready to fill with methods
    return cls
end

return Class
